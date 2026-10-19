package proxy

import (
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/limits"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// quotaErrCode is the error code used for every quota rejection. 8000 is in
// the range drivers treat as a plain, non-retryable server error.
const quotaErrCode = 8000

func quotaErrorDoc(msg string) bsoncore.Document {
	return errorDoc(quotaErrCode, "TenantQuotaExceeded", msg)
}

// admit applies session ownership and quotas to a command before it runs.
// On success release must be called once the command has finished; on
// failure errDoc is the reply to send.
func (c *conn) admit(name string, m *wire.Msg, size int) (release func(), errDoc bsoncore.Document) {
	noop := func() {}
	if c.tenant == nil {
		return noop, nil
	}
	switch name {
	case "hello", "isMaster", "ismaster", "saslStart", "saslContinue", "ping":
		return noop, nil
	}
	id := c.tenant.ID

	if msg := c.s.sess.check(id, name, m.Body); msg != "" {
		c.s.M.SessionRejected(id)
		c.s.M.Command(name, "denied")
		c.log.Warn("session rejected", "command", name)
		return nil, errorDoc(13, "Unauthorized", msg)
	}

	// Each tracked cursor is state kept for the connection's life; past the
	// cap a cursor would be opened upstream untracked (and so never killed
	// when the client goes away). Refuse before it exists.
	switch name {
	case "find", "aggregate", "listIndexes", "listCollections":
		if len(c.cursors) >= maxCursorsPerConn {
			c.s.M.Command(name, "denied")
			return nil, quotaErrorDoc(fmt.Sprintf("tenant proxy: more than %d open cursors on this connection; close some first", maxCursorsPerConn))
		}
	}

	lt := c.lim
	rel, qerr := lt.Admit(size, name != "getMore")
	if qerr != nil {
		return nil, c.quotaReject(name, qerr)
	}
	fail := func(e *limits.Error) (func(), bsoncore.Document) {
		rel()
		return nil, c.quotaReject(name, e)
	}
	switch name {
	case "find", "aggregate", "listIndexes", "listCollections":
		if e := lt.CheckCursor(); e != nil {
			return fail(e)
		}
	case "createIndexes":
		db, _ := m.Body.Lookup("$db").StringValueOK()
		if e := lt.CheckIndexes(rewrite.IndexNames(db, m.Body)); e != nil {
			return fail(e)
		}
	case "dropIndexes":
		db, _ := m.Body.Lookup("$db").StringValueOK()
		if ix := rewrite.DroppedIndex(db, m.Body); ix != "" {
			lt.ForgetIndex(ix)
		}
	}
	if (lt.L.DisableJS || lt.L.JSPerSec > 0) && rewrite.UsesJS(name, m.Body) {
		if e := lt.CheckJS(); e != nil {
			return fail(e)
		}
	}
	c.s.M.Gauge("inflight_operations", id).Add(1)
	return func() {
		c.s.M.Gauge("inflight_operations", id).Add(-1)
		rel()
	}, nil
}

func (c *conn) quotaReject(name string, e *limits.Error) bsoncore.Document {
	c.s.M.Quota(c.tenant.ID, e.Reason)
	c.s.M.Command(name, "denied")
	c.log.Warn("quota exceeded", "command", name, "reason", e.Reason)
	return quotaErrorDoc(e.Msg)
}

// syncCursors reflects this connection's open cursors in the tenant's total.
func (c *conn) syncCursors() {
	if c.lim == nil {
		return
	}
	if d := len(c.cursors) - c.cursorsCharged; d != 0 {
		c.lim.AddCursors(d)
		c.s.M.Gauge("open_cursors", c.tenant.ID).Add(int64(d))
		c.cursorsCharged = len(c.cursors)
	}
}

// applyMaxTime enforces the tenant's maxTimeMS cap and default.
func (c *conn) applyMaxTime(res *rewrite.Result) error {
	if c.lim == nil || res.Body == nil {
		return nil
	}
	l := c.lim.L
	if l.MaxTimeMSCap <= 0 && l.DefaultMaxTimeMS <= 0 {
		return nil
	}
	b, err := rewrite.ApplyMaxTime(res.Command, res.Body, l.MaxTimeMSCap, l.DefaultMaxTimeMS, res.ChangeStream)
	if err != nil {
		return err
	}
	res.Body = b
	return nil
}

// oversize is called when an upstream reply exceeds the tenant's result
// limit: the cursor it opened is killed and an error is returned instead.
func (c *conn) oversize(h wire.Header, rb []byte, res *rewrite.Result, getMoreID int64) error {
	if e := c.lim.CheckResult(len(rb)); e != nil {
		c.s.M.Quota(c.tenant.ID, e.Reason)
		if rm, err := wire.ParseMsg(rb); err == nil {
			if cur, ok := rm.Body.Lookup("cursor").DocumentOK(); ok {
				id, _ := cur.Lookup("id").AsInt64OK()
				if id != 0 {
					ns, _ := cur.Lookup("ns").StringValueOK()
					if getMoreID != 0 {
						delete(c.cursors, getMoreID)
						delete(c.viewPhys, getMoreID)
					}
					c.killUpstream(ns, id)
				}
			}
		}
		c.s.M.Command(res.Command, "error")
		return c.reply(h, quotaErrorDoc(e.Msg))
	}
	return nil
}

func (c *conn) killUpstream(ns string, id int64) {
	db, coll := splitNS(ns)
	if coll == "" {
		return
	}
	c.up.SetDeadline(time.Now().Add(2 * time.Second))
	cmd := bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "killCursors", coll),
		bsoncore.AppendArrayElement(nil, "cursors", bsoncore.BuildArray(nil,
			bsoncore.Value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, id)})),
	)
	c.s.dial.RunCommand(c.up, db, cmd)
}
