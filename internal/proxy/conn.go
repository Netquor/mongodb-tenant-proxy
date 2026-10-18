package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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

	reqComp wire.Compressor // compressor of the request being handled (replies mirror it)

	tenant     *rewrite.Tenant
	tenantHeld bool
	sasl       *auth.SASL

	up       *upstream.Conn
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

	if s.auth.Has("static") {
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
			err = c.handleMsg(h, body)
		case wire.OpQuery:
			err = c.handleLegacy(h, body)
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
	for _, sub := range c.streams {
		sub.Close()
	}
	if c.up != nil {
		c.killOpenCursors()
		c.up.Close()
	}
	c.nc.Close()
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
	c.log = c.log.With("tenant", id)
	return nil
}

// ---- replies -------------------------------------------------------------

func (c *conn) nextRequestID() int32 { c.outID++; return c.outID }

func (c *conn) reply(h wire.Header, d bsoncore.Document) error {
	m := wire.Msg{Body: d}
	b := m.Encode()
	c.s.M.BytesOut.Add(int64(len(b) + 16))
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
