package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/fanout"
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

	tenant     *rewrite.Tenant
	tenantHeld bool
	sasl       *auth.SASL

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
	cursors  map[int64]string      // cursor id -> namespace it was opened on
	viewPhys map[int64]string      // view cursor id -> physical view collection
	streams  map[int64]*fanout.Sub // virtual change stream cursors served by the fan-out
	outID    int32
}

func newConn(s *Server, nc net.Conn) *conn {
	id := s.nextID.Add(1)
	return &conn{
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
}

func (c *conn) serve(ctx context.Context) {
	s := c.s
	s.M.ConnsTotal.Add(1)
	s.M.ConnsActive.Add(1)
	defer s.M.ConnsActive.Add(-1)
	defer c.cleanup()

	if s.auth.Mode() == "static" {
		if err := c.bindTenant(s.auth.StaticTenant()); err != nil {
			c.log.Warn("rejecting connection", "err", err)
			return
		}
	}
	idle := s.cfg.IdleDuration()
	for {
		if idle > 0 {
			c.nc.SetReadDeadline(time.Now().Add(idle))
		}
		h, body, err := wire.ReadFrame(c.br, s.cfg.MaxMessageBytes)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
				c.log.Debug("read failed", "err", err)
			}
			return
		}
		s.M.BytesIn.Add(int64(h.Length))
		switch h.OpCode {
		case wire.OpMsg:
			err = c.handleMsg(h, body)
		case wire.OpQuery:
			err = c.handleLegacy(h, body)
		default:
			c.log.Warn("unsupported opcode", "opcode", h.OpCode)
			return
		}
		c.endCommand()
		if err != nil {
			c.log.Debug("closing connection", "err", err)
			return
		}
	}
}

func (c *conn) cleanup() {
	for _, sub := range c.streams {
		sub.Close()
	}
	c.abortOpenTxn()
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
	if !c.s.acquireTenant(id) {
		return errors.New("tenant connection limit reached")
	}
	if c.tenantHeld {
		c.s.releaseTenant(c.tenant.ID)
	}
	c.tenant, c.tenantHeld = t, true
	c.log = c.log.With("tenant", id)
	return nil
}

// ---- replies -------------------------------------------------------------

func (c *conn) nextRequestID() int32 { c.outID++; return c.outID }

func (c *conn) reply(h wire.Header, d bsoncore.Document) error {
	m := wire.Msg{Body: d}
	b := m.Encode()
	c.s.M.BytesOut.Add(int64(len(b) + 16))
	return wire.WriteFrame(c.nc, c.nextRequestID(), h.RequestID, wire.OpMsg, b)
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
