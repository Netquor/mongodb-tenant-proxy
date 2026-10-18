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

	tenant     *rewrite.Tenant
	tenantHeld bool
	lim        *limits.Tenant // quota state of the bound tenant
	// cursorsCharged is how many of c.cursors are counted in lim.
	cursorsCharged int
	sasl           *auth.SASL

	up       *upstream.Conn
	cursors  map[int64]string // cursor id -> namespace it was opened on
	viewPhys map[int64]string // view cursor id -> physical view collection
	// idCursors are cursors whose documents hold namespaced _id values.
	idCursors map[int64]bool
	streams   map[int64]*fanout.Sub // virtual change stream cursors served by the fan-out
	outID     int32
	upAddr    string // local address of the upstream connection ($currentOp attribution)
}

func newConn(s *Server, nc net.Conn) *conn {
	id := s.nextID.Add(1)
	return &conn{
		s: s, nc: nc, id: id,
		br:       bufio.NewReaderSize(nc, 64*1024),
		cursors:  map[int64]string{},
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
			err = c.safely(func() error { return c.handleMsg(h, body) })
		case wire.OpQuery:
			err = c.safely(func() error { return c.handleLegacy(h, body) })
		default:
			c.log.Warn("unsupported opcode", "opcode", h.OpCode)
			return
		}
		if err != nil {
			c.log.Debug("closing connection", "err", err)
			return
		}
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

func (c *conn) cleanup() {
	for _, sub := range c.streams {
		sub.Close()
	}
	if c.up != nil {
		c.killOpenCursors()
		if c.upAddr != "" {
			c.s.unregisterUp(c.tenant.ID, c.upAddr)
		}
		c.up.Close()
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

// killOpenCursors releases server-side cursors the client abandoned.
func (c *conn) killOpenCursors() {
	byNS := map[string][]int64{}
	for id, ns := range c.cursors {
		if _, virtual := c.streams[id]; virtual {
			continue
		}
		byNS[ns] = append(byNS[ns], id)
	}
	c.up.SetDeadline(time.Now().Add(2 * time.Second))
	for ns, ids := range byNS {
		db, coll := splitNS(ns)
		vals := make([]bsoncore.Value, len(ids))
		for i, id := range ids {
			vals[i] = bsoncore.Value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, id)}
		}
		cmd := bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "killCursors", coll),
			bsoncore.AppendArrayElement(nil, "cursors", bsoncore.BuildArray(nil, vals...)),
		)
		if _, err := c.s.dial.RunCommand(c.up, db, cmd); err != nil {
			return
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
	c.lim = c.s.lim.For(id)
	c.log = c.log.With("tenant", id)
	return nil
}

// ---- replies -------------------------------------------------------------

func (c *conn) nextRequestID() int32 { c.outID++; return c.outID }

func (c *conn) reply(h wire.Header, d bsoncore.Document) error {
	m := wire.Msg{Body: d}
	b := m.Encode()
	c.s.M.BytesOut.Add(int64(len(b) + 16))
	if c.lim != nil {
		c.lim.CountReply(len(b) + 16)
	}
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
