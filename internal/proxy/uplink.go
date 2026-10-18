package proxy

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// route says where one client command runs and what it needs from the
// upstream connection that carries it.
type route struct {
	sel upstream.Selector
	// read commands may run on a secondary and may be repeated if the
	// connection breaks before any reply byte arrives.
	read bool
	// inTxn: part of a multi-document transaction (needs the pinned connection).
	inTxn, startTxn, endTxn bool
	// retryableWrite: carries a txnNumber outside a transaction, so drivers may
	// retry it if told so with RetryableWriteError.
	retryableWrite bool
	// tail: opens a cursor that must keep its connection (change streams,
	// tailable cursors).
	tail bool
	// pinned, when set, is the connection that must carry the command.
	pinned *upstream.Conn
}

// readCommands may be served by a secondary when the client asks for it.
var readCommands = map[string]bool{
	"find": true, "aggregate": true, "count": true, "distinct": true,
	"listCollections": true, "listIndexes": true, "dbStats": true, "collStats": true,
}

// planRoute derives the route of a client command from its original body.
func (c *conn) planRoute(name string, body bsoncore.Document) (route, error) {
	rt := route{sel: upstream.Selector{Mode: upstream.Primary}}
	if ac, ok := body.Lookup("autocommit").BooleanOK(); ok && !ac {
		rt.inTxn = true
		rt.startTxn, _ = body.Lookup("startTransaction").BooleanOK()
	} else if body.Lookup("txnNumber").Type != 0 {
		rt.retryableWrite = true
	}
	rt.endTxn = name == "commitTransaction" || name == "abortTransaction"
	switch name {
	case "aggregate":
		if first := pipelineStage(body, false); first == "$changeStream" {
			rt.tail = true
		} else if last := pipelineStage(body, true); last != "$out" && last != "$merge" {
			rt.read = true
		}
	case "find":
		if t, _ := body.Lookup("tailable").BooleanOK(); t {
			rt.tail = true
		} else {
			rt.read = true
		}
	default:
		rt.read = readCommands[name]
	}
	if rt.read && !rt.inTxn && !c.s.dial.Direct() {
		if rp, ok := body.Lookup("$readPreference").DocumentOK(); ok {
			sel, err := upstream.ParseReadPref(rp)
			if err != nil {
				return rt, err
			}
			rt.sel = sel
		}
	}
	return rt, nil
}

// pipelineStage returns the name of the first (or last) aggregation stage.
func pipelineStage(body bsoncore.Document, last bool) string {
	arr, ok := body.Lookup("pipeline").ArrayOK()
	if !ok {
		return ""
	}
	vals, _ := arr.Values()
	if len(vals) == 0 {
		return ""
	}
	v := vals[0]
	if last {
		v = vals[len(vals)-1]
	}
	d, ok := v.DocumentOK()
	if !ok {
		return ""
	}
	e, err := d.IndexErr(0)
	if err != nil {
		return ""
	}
	return e.Key()
}

var errNoTxn = errors.New("transaction state was lost")

func (c *conn) pooled() bool { return c.s.dial.Pooled() }

// useUp makes c.up the connection that will carry a command on route rt.
func (c *conn) useUp(rt route) error {
	if rt.inTxn && c.pooled() {
		if !rt.startTxn {
			if c.txnConn == nil {
				return errNoTxn
			}
			c.setUp(c.txnConn)
			return nil
		}
		c.dropTxn()
	}
	if rt.pinned != nil {
		c.setUp(rt.pinned)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.s.cfg.Upstream.SelectionTimeout()+c.s.cfg.Upstream.PoolWait())
	defer cancel()
	addr := rt.sel.Addr
	if addr == "" {
		var err error
		if addr, err = c.s.dial.Select(ctx, rt.sel); err != nil {
			return err
		}
	}
	if c.up == nil || c.up.Addr != addr {
		c.releaseUp()
		u, err := c.acquire(ctx, addr)
		if err != nil {
			return err
		}
		c.up = u
	}
	if rt.startTxn && c.pooled() {
		c.txnConn = c.up
	}
	return nil
}

func (c *conn) setUp(u *upstream.Conn) {
	if c.up != u {
		c.releaseUp()
		c.up = u
	}
}

// acquire returns a connection to addr: the shared pool in pooled mode, this
// client's own connection to that member in dedicated mode.
func (c *conn) acquire(ctx context.Context, addr string) (*upstream.Conn, error) {
	if c.pooled() {
		return c.s.dial.Checkout(ctx, addr)
	}
	if u := c.ded[addr]; u != nil {
		return u, nil
	}
	u, err := c.s.dial.DialMember(ctx, addr)
	if err != nil {
		return nil, err
	}
	c.ded[addr] = u
	return u, nil
}

func (c *conn) isPinned(u *upstream.Conn) bool {
	if u == c.txnConn {
		return true
	}
	for _, t := range c.tails {
		if t == u {
			return true
		}
	}
	return false
}

// releaseUp gives the current connection back unless something pins it.
func (c *conn) releaseUp() {
	u := c.up
	c.up = nil
	if u != nil && c.pooled() && !c.isPinned(u) {
		c.s.dial.Release(u)
	}
}

// endCommand runs after every client command: pooled connections go back to
// the pool unless a transaction or cursor needs them.
func (c *conn) endCommand() { c.releaseUp() }

// upFailed handles a transport failure on c.up: the connection is dropped,
// the topology learns about it and any pins on it are void.
func (c *conn) upFailed(err error) {
	u := c.up
	c.up = nil
	c.failConn(u, err)
}

// failConn is upFailed for any connection this client holds.
func (c *conn) failConn(u *upstream.Conn, err error) {
	if u == nil {
		return
	}
	if c.up == u {
		c.up = nil
	}
	if u == c.txnConn {
		c.txnConn = nil
	}
	for id, t := range c.tails {
		if t == u {
			delete(c.tails, id)
		}
	}
	for addr, d := range c.ded {
		if d == u {
			delete(c.ded, addr)
		}
	}
	c.s.dial.Discard(u)
	if upstream.IsNetwork(err) {
		c.s.dial.NetworkError(u.Addr, err)
	}
}

// dropTxn forgets the transaction connection.
func (c *conn) dropTxn() {
	u := c.txnConn
	c.txnConn = nil
	if u != nil && u != c.up && !c.isPinned(u) {
		c.s.dial.Release(u)
	}
}

// endTxnConn is called once commitTransaction / abortTransaction has been
// answered; the connection is free again.
func (c *conn) endTxnConn() {
	c.txnConn = nil
	c.releaseUp()
}

func (c *conn) pinTail(id int64) {
	if c.pooled() && c.up != nil {
		c.tails[id] = c.up
	}
}

func (c *conn) unpinTail(id int64) {
	u := c.tails[id]
	if u == nil {
		return
	}
	delete(c.tails, id)
	if u != c.up && !c.isPinned(u) && c.pooled() {
		c.s.dial.Release(u)
	}
}

// runUp runs a housekeeping command on the current connection. Housekeeping is
// idempotent, so a transport failure is retried once on a fresh connection.
func (c *conn) runUp(rt route, db string, cmd bsoncore.Document) (bsoncore.Document, error) {
	resp, err := c.s.dial.RunCommand(c.up, db, cmd)
	if err != nil && upstream.IsNetwork(err) && !rt.inTxn && rt.pinned == nil {
		c.upFailed(err)
		if c.useUp(rt) != nil {
			return nil, err
		}
		resp, err = c.s.dial.RunCommand(c.up, db, cmd)
	}
	if err != nil && upstream.IsNetwork(err) {
		c.upFailed(err)
	}
	return resp, err
}

// retryUp is runUp for helpers that take the connection (EnsureImages...).
func (c *conn) retryUp(rt route, fn func(*upstream.Conn) error) error {
	err := fn(c.up)
	if err != nil && upstream.IsNetwork(err) && !rt.inTxn && rt.pinned == nil {
		c.upFailed(err)
		if c.useUp(rt) != nil {
			return err
		}
		err = fn(c.up)
	}
	if err != nil && upstream.IsNetwork(err) {
		c.upFailed(err)
	}
	return err
}

// upstreamError builds the reply for a command that could not reach, or lost,
// its upstream member. Labels tell drivers whether to retry.
func (c *conn) upstreamError(rt route, err error) bsoncore.Document {
	code, name := int32(upstream.CodeHostUnreachable), "HostUnreachable"
	var sel *upstream.ErrSelection
	switch {
	case errors.As(err, &sel) && sel.Sel.Mode != upstream.Primary:
		code, name = 133, "FailedToSatisfyReadPreference"
	case errors.Is(err, errNoTxn):
		code, name = 251, "NoSuchTransaction"
	}
	d := errorDoc(code, name, "tenant proxy: upstream unavailable: "+err.Error())
	switch {
	case errors.Is(err, errNoTxn) || rt.inTxn:
		d = upstream.AddLabels(d, upstream.LabelTransient)
	case rt.retryableWrite:
		d = upstream.AddLabels(d, upstream.LabelRetryableWrite)
	}
	return d
}

// abortOpenTxn tells the member to abort a transaction the client abandoned.
func (c *conn) abortOpenTxn() {
	if c.txnConn == nil || c.txnBody == nil {
		return
	}
	c.up = c.txnConn
	c.up.SetDeadline(time.Now().Add(2 * time.Second))
	c.s.dial.RunCommand(c.up, "admin", c.txnBody)
}

// txnAbortBody builds abortTransaction for the transaction in body.
func txnAbortBody(body bsoncore.Document) bsoncore.Document {
	lsid := body.Lookup("lsid")
	n := body.Lookup("txnNumber")
	if lsid.Type == 0 || n.Type == 0 {
		return nil
	}
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "abortTransaction", 1),
		bsoncore.AppendValueElement(nil, "lsid", lsid),
		bsoncore.AppendValueElement(nil, "txnNumber", n),
		bsoncore.AppendBooleanElement(nil, "autocommit", false),
	)
}

var _ = wire.OpMsg

// killAt kills cursors on a specific member, best effort.
func (c *conn) killAt(addr, ns string, ids []int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	u := c.tails[ids[0]]
	if u == nil {
		var err error
		if u, err = c.acquire(ctx, addr); err != nil {
			return
		}
	}
	u.SetDeadline(time.Now().Add(2 * time.Second))
	db, coll := splitNS(ns)
	vals := make([]bsoncore.Value, len(ids))
	for i, id := range ids {
		vals[i] = bsoncore.Value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, id)}
	}
	_, err := c.s.dial.RunCommand(u, db, bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "killCursors", coll),
		bsoncore.AppendArrayElement(nil, "cursors", bsoncore.BuildArray(nil, vals...))))
	if err != nil {
		c.failConn(u, err)
	} else if c.tails[ids[0]] == nil && c.pooled() {
		c.s.dial.Release(u)
	}
}
