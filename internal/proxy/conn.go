package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/audit"
	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/fanout"
	"github.com/netquor/mongodb-tenant-proxy/internal/limits"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

const maxCursorsPerConn = 10000

// conn is one client connection. It owns a dedicated upstream connection so
// that cursors, sessions and transactions keep working unchanged.
type conn struct {
	s   *Server
	nc  net.Conn
	br  *bufio.Reader
	id  int64
	log *slog.Logger
	connOps

	reqComp wire.Compressor // compressor of the request being handled (replies mirror it)

	tenant     *rewrite.Tenant
	tenantHeld bool
	lim        *limits.Tenant // quota state of the bound tenant
	// cursorsCharged is how many of c.cursors are counted in lim.
	cursorsCharged int
	sasl           *auth.SASL

	// up is the upstream connection carrying the command in progress. In
	// pooled mode it is borrowed per command (see uplink.go); in dedicated
	// mode it is one of this client's own per-member connections (ded).
	up      *upstream.Conn
	ded     map[string]*upstream.Conn // dedicated mode: member -> connection
	txnConn *upstream.Conn            // pooled mode: connection pinned by an open transaction
	txnBody bsoncore.Document         // abortTransaction for the open transaction
	tails   map[int64]*upstream.Conn  // pooled mode: change-stream / tailable cursor -> pinned connection
	rt      route                     // route of the command in progress
	// cursorAt maps a server cursor to the member that owns it: getMore and
	// killCursors must go back to that member.
	cursorAt map[int64]string
	cursors  map[int64]string // cursor id -> namespace it was opened on
	viewPhys map[int64]string // view cursor id -> physical view collection
	// idCursors are cursors whose documents hold namespaced _id values.
	idCursors map[int64]bool
	streams   map[int64]*fanout.Sub // virtual change stream cursors served by the fan-out
	outID     int32
	upAddr    string // local address of the upstream connection in use ($currentOp attribution)
}

func newConn(s *Server, nc net.Conn) *conn {
	id := s.nextID.Add(1)
	c := &conn{
		s: s, nc: nc, id: id,
		br:       bufio.NewReaderSize(nc, 64*1024),
		cursors:  map[int64]string{},
		cursorAt: map[int64]string{},
		ded:      map[string]*upstream.Conn{},
		tails:    map[int64]*upstream.Conn{},
		streams:  map[int64]*fanout.Sub{},
		viewPhys: map[int64]string{},
		log:      s.log.With("conn", id, "remote", nc.RemoteAddr().String()),
	}
	c.initOps()
	return c
}

func (c *conn) serve(ctx context.Context) {
	s := c.s
	s.M.ConnsTotal.Add(1)
	s.M.ConnsActive.Add(1)
	defer s.M.ConnsActive.Add(-1)
	defer c.cleanup()
	s.audit.Log(c.event(audit.Connect))

	if s.auth.Has("static") {
		if err := c.bindTenant(s.auth.StaticTenant()); err != nil {
			c.log.Warn("rejecting connection", "err", err)
			c.authFail("", err.Error())
			return
		}
		c.authOK()
	}
	for {
		if idle := s.rt().idle; idle > 0 {
			c.nc.SetReadDeadline(time.Now().Add(idle))
		}
		h, body, err := wire.ReadFrame(c.br, s.rt().maxMessage)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				c.log.Debug("read failed", "err", err)
			}
			return
		}
		c.countIn(int64(h.Length))
		if why, bad := c.revoked(); bad {
			c.kill(why)
			return
		}
		c.reqComp = wire.CompNone
		if h.OpCode == wire.OpCompressed {
			h, body, err = c.decompress(h, body)
			if err != nil {
				c.log.Debug("bad OP_COMPRESSED", "err", err)
				return
			}
		}
		switch h.OpCode {
		case wire.OpMsg:
			err = c.safely(func() error { return c.handleMsg(h, body) })
		case wire.OpQuery:
			err = c.safely(func() error { return c.handleLegacy(h, body) })
		default:
			c.log.Warn("unsupported opcode", "opcode", h.OpCode)
			return
		}
		c.endCommand()
		if err != nil {
			c.log.Debug("closing connection", "err", err)
			return
		}
		c.endMsg()
	}
}

// safely runs one request handler. A bug triggered by hostile input must
// close that client's connection, not crash the proxy and with it every
// other tenant's connections.
func (c *conn) safely(fn func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			c.log.Error("panic while handling request", "panic", p, "stack", string(debug.Stack()))
			err = fmt.Errorf("internal error: %v", p)
		}
	}()
	return fn()
}

// decompress unwraps an OP_COMPRESSED request and remembers the compressor so
// the reply can mirror it, as mongod does.
func (c *conn) decompress(h wire.Header, body []byte) (wire.Header, []byte, error) {
	id, ok := wire.CompressorID(body)
	if !ok || !c.s.clientComp[id] {
		return h, nil, fmt.Errorf("compressor %d not enabled", id)
	}
	op, _, data, err := wire.Decompress(body, c.s.cfg.MaxMessageBytes)
	if err != nil {
		return h, nil, err
	}
	c.reqComp = id
	h.OpCode, h.Length = op, int32(len(data)+16)
	return h, data, nil
}

// send writes a reply frame to the client, compressing it with the
// compressor of the request being answered (never for legacy OP_REPLY).
func (c *conn) send(requestID, responseTo, opcode int32, body []byte) error {
	if c.reqComp != wire.CompNone && opcode == wire.OpMsg {
		cb, err := wire.Compress(c.reqComp, opcode, body)
		if err != nil {
			return err
		}
		return wire.WriteFrame(c.nc, requestID, responseTo, wire.OpCompressed, cb)
	}
	return wire.WriteFrame(c.nc, requestID, responseTo, opcode, body)
}

func (c *conn) cleanup() {
	e := c.event(audit.Disconnect)
	if why := c.killed.Load(); why != nil {
		e.Reason = *why
		if *why != "killed by admin" {
			e.Type = audit.ConnKilled
		}
	}
	c.s.audit.Log(e)
	for _, sub := range c.streams {
		sub.Close()
	}
	c.abortOpenTxn()
	c.detach()
	c.killOpenCursors()
	c.up = nil
	if c.pooled() {
		held := map[*upstream.Conn]bool{}
		if c.txnConn != nil {
			held[c.txnConn] = true
		}
		for _, u := range c.tails {
			held[u] = true
		}
		for u := range held {
			c.s.dial.Release(u)
		}
	}
	for _, u := range c.ded {
		u.Close()
	}
	c.nc.Close()
	if c.lim != nil {
		c.cursors = nil
		c.syncCursors()
	}
	if c.tenantHeld {
		c.s.releaseTenant(c.tenant.ID)
	}
}

// killOpenCursors releases server-side cursors the client abandoned, on the
// member that owns each of them.
func (c *conn) killOpenCursors() {
	type key struct{ addr, ns string }
	by := map[key][]int64{}
	for id, ns := range c.cursors {
		if _, virtual := c.streams[id]; virtual {
			continue
		}
		k := key{c.cursorAt[id], ns}
		by[k] = append(by[k], id)
	}
	for k, ids := range by {
		if k.addr == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		u := c.tails[ids[0]]
		if u == nil {
			var err error
			if u, err = c.acquire(ctx, k.addr); err != nil {
				cancel()
				continue
			}
		}
		u.SetDeadline(time.Now().Add(2 * time.Second))
		db, coll := splitNS(k.ns)
		vals := make([]bsoncore.Value, len(ids))
		for i, id := range ids {
			vals[i] = bsoncore.Value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, id)}
		}
		cmd := bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "killCursors", coll),
			bsoncore.AppendArrayElement(nil, "cursors", bsoncore.BuildArray(nil, vals...)),
		)
		_, err := c.s.dial.RunCommand(u, db, cmd)
		cancel()
		if err != nil {
			c.failConn(u, err)
		} else if c.tails[ids[0]] == nil && c.pooled() {
			c.s.dial.Release(u)
		}
	}
}

func (c *conn) bindTenant(id string) error {
	t, err := rewrite.NewTenant(c.s.cfg.Tenant.IDType, id)
	if err != nil {
		return err
	}
	if c.s.reg.Disabled(id) {
		return errors.New("tenant disabled")
	}
	if !c.s.acquireTenant(id) {
		return errors.New("tenant connection limit reached")
	}
	if c.tenantHeld {
		c.s.releaseTenant(c.tenant.ID)
	}
	c.tenant, c.tenantHeld = t, true
	c.lim = c.s.lim.For(id)
	c.onBind(id)
	c.log = c.log.With("tenant", id)
	return nil
}

// ---- replies -------------------------------------------------------------

func (c *conn) nextRequestID() int32 { c.outID++; return c.outID }

func (c *conn) reply(h wire.Header, d bsoncore.Document) error {
	m := wire.Msg{Body: d}
	b := m.Encode()
	c.countOut(int64(len(b) + 16))
	if c.lim != nil {
		c.lim.CountReply(len(b) + 16)
	}
	return c.send(c.nextRequestID(), h.RequestID, wire.OpMsg, b)
}

func errorDoc(code int32, codeName, msg string) bsoncore.Document {
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "ok", 0),
		bsoncore.AppendStringElement(nil, "errmsg", msg),
		bsoncore.AppendInt32Element(nil, "code", code),
		bsoncore.AppendStringElement(nil, "codeName", codeName),
	)
}

func okDoc() bsoncore.Document {
	return bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "ok", 1))
}

func toErrorDoc(err error) bsoncore.Document {
	var re *rewrite.Error
	if errors.As(err, &re) {
		return errorDoc(re.Code, re.CodeName, re.Msg)
	}
	return errorDoc(8, "UnknownError", err.Error())
}

func splitNS(ns string) (db, coll string) {
	for i := 0; i < len(ns); i++ {
		if ns[i] == '.' {
			return ns[:i], ns[i+1:]
		}
	}
	return ns, ""
}
