package proxy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

func (c *conn) handleMsg(h wire.Header, body []byte) error {
	m, err := wire.ParseMsg(body)
	if err != nil {
		return err
	}
	name := rewrite.CommandName(m.Body)
	db, _ := m.Body.Lookup("$db").StringValueOK()
	c.beginCmd(name, db)
	if err := rewrite.ValidateBody(m.Body); err != nil {
		return c.reply(h, toErrorDoc(err))
	}

	switch name {
	case "hello", "isMaster", "ismaster":
		return c.reply(h, c.hello(m.Body))
	case "saslStart", "saslContinue":
		return c.reply(h, c.handleSASL(name, m.Body))
	case "getMore":
		return c.handleGetMore(h, m, db)
	case "killCursors":
		return c.handleKillCursors(h, m, db)
	}

	if c.tenant == nil && name != "ping" {
		c.cmdDeny(name, "authentication required")
		return c.reply(h, errorDoc(13, "Unauthorized", "tenant proxy: authentication required"))
	}

	if handled, err := c.maybeView(h, m, name, db); handled || err != nil {
		return err
	}

	res, err := c.s.rt().rw.Rewrite(c.tenant, db, m.Body, m.Seqs)
	if err == nil && name == "listCollections" {
		c.hookListCollections(res, m.Body, db)
	}
	if err != nil {
		c.cmdDeny(name, err.Error())
		c.log.Warn("command denied", "db", db, "command", name, "reason", err.Error())
		if m.Flags&wire.FlagMoreToCome != 0 {
			return nil
		}
		return c.reply(h, toErrorDoc(err))
	}
	if res.Reply != nil {
		c.cmdDone(name, "ok")
		return c.reply(h, res.Reply)
	}
	if res.Stream != nil && c.s.fan != nil {
		if handled, err := c.openStream(h, m, res); handled || err != nil {
			return err
		}
	}
	return c.forward(h, m.Flags, res, 0)
}

func (c *conn) ensureUp() error {
	if c.up != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.s.cfg.DialDuration())
	defer cancel()
	up, err := c.s.dial.Dial(ctx)
	if err != nil {
		return err
	}
	c.up = up
	return nil
}

// forward sends a rewritten command upstream and relays the reply.
func (c *conn) forward(h wire.Header, flags uint32, res *rewrite.Result, getMoreID int64) error {
	if err := c.ensureUp(); err != nil {
		c.log.Error("upstream dial failed", "err", err)
		c.cmdDone(res.Command, "error")
		return c.reply(h, errorDoc(6, "HostUnreachable", "tenant proxy: upstream unavailable"))
	}
	if !c.s.cfg.ChangeStreams.DisableAutoImages && c.s.dbWatched(res.DB) {
		// A database-level stream is open: collections created from now on
		// need pre/post images before their first write.
		if coll := writeTarget(res); coll != "" {
			if err := c.s.dial.EnsureImages(c.up, res.DB, coll); err != nil {
				c.log.Warn("enabling change stream images failed", "coll", coll, "err", err)
			}
		}
	}
	if res.ChangeStream && res.DBLevel {
		c.s.dbStreams.Store(res.DB, struct{}{})
	}
	if res.ChangeStream && !c.s.cfg.ChangeStreams.DisableAutoImages {
		var err error
		if res.DBLevel {
			err = c.s.dial.EnsureImagesDB(c.up, res.DB)
		} else {
			err = c.s.dial.EnsureImages(c.up, res.DB, res.Collection)
		}
		if err != nil {
			c.log.Error("enabling change stream images failed", "err", err)
			return c.reply(h, errorDoc(8, "UnknownError", "tenant proxy: could not enable change stream images: "+err.Error()))
		}
	}
	if bad := c.runSteps(res.Before); bad != nil {
		c.cmdDone(res.Command, "error")
		return c.reply(h, bad)
	}
	out := wire.Msg{
		Flags: flags &^ (wire.FlagExhaustAllowed | wire.FlagChecksumPresent),
		Body:  res.Body,
		Seqs:  res.Seqs,
	}
	if err := wire.WriteFrame(c.up, h.RequestID, 0, wire.OpMsg, out.Encode()); err != nil {
		return fmt.Errorf("upstream write: %w", err)
	}
	if flags&wire.FlagMoreToCome != 0 {
		c.cmdDone(res.Command, "ok")
		return nil // unacknowledged write: no reply
	}
	rh, rb, err := wire.ReadFrame(c.up.R, c.s.rt().maxMessage)
	if err != nil {
		return fmt.Errorf("upstream read: %w", err)
	}
	if rh.OpCode != wire.OpMsg {
		return errors.New("unexpected upstream opcode")
	}
	needParse := res.Post != nil || res.Alias != "" || len(res.After) > 0 || tracksCursor(res.Command)
	if needParse {
		rm, err := wire.ParseMsg(rb)
		if err != nil {
			return err
		}
		if len(res.After) > 0 {
			if ok, _ := rm.Body.Lookup("ok").AsInt64OK(); ok == 1 {
				if bad := c.runSteps(res.After); bad != nil {
					c.cmdDone(res.Command, "error")
					return c.reply(h, bad)
				}
			}
		}
		if res.Post != nil {
			rm.Body = res.Post(rm.Body)
			rb = rm.Encode()
		}
		if res.Alias != "" {
			rm.Body = patchCursorNS(rm.Body, res.DB+"."+res.Alias)
			rb = rm.Encode()
			c.noteViewCursor(rm.Body, res.Phys, getMoreID)
		}
		c.trackCursor(res.Command, getMoreID, rm.Body)
	}
	c.cmdDone(res.Command, "ok")
	c.countOut(int64(len(rb) + 16))
	return wire.WriteFrame(c.nc, rh.RequestID, h.RequestID, wire.OpMsg, rb)
}

func tracksCursor(cmd string) bool {
	switch cmd {
	case "find", "aggregate", "listIndexes", "listCollections", "getMore":
		return true
	}
	return false
}

// trackCursor records cursors opened on this connection so that getMore and
// killCursors can only ever address cursors this tenant created.
func (c *conn) trackCursor(cmd string, getMoreID int64, resp bsoncore.Document) {
	if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
		if cmd == "getMore" {
			delete(c.cursors, getMoreID)
		}
		return
	}
	cur, ok := resp.Lookup("cursor").DocumentOK()
	if !ok {
		return
	}
	id, _ := cur.Lookup("id").AsInt64OK()
	switch {
	case id == 0 && cmd == "getMore":
		delete(c.cursors, getMoreID)
		delete(c.viewPhys, getMoreID)
	case id != 0 && cmd != "getMore":
		if len(c.cursors) < maxCursorsPerConn {
			ns, _ := cur.Lookup("ns").StringValueOK()
			c.cursors[id] = ns
		}
	}
}

func (c *conn) handleGetMore(h wire.Header, m *wire.Msg, db string) error {
	id, ok := m.Body.Lookup("getMore").AsInt64OK()
	coll, _ := m.Body.Lookup("collection").StringValueOK()
	ns, owned := c.cursors[id]
	if sub, virtual := c.streams[id]; virtual && c.tenant != nil && ok && owned && ns == db+"."+coll {
		return c.streamGetMore(h, m, id, sub, ns)
	}
	if c.tenant == nil || !ok || len(m.Seqs) > 0 || !owned || ns != db+"."+coll {
		c.cmdDeny("getMore", "cursor not owned by connection")
		return c.reply(h, errorDoc(43, "CursorNotFound", fmt.Sprintf("cursor id %d not found", id)))
	}
	res := &rewrite.Result{Command: "getMore", DB: db, Body: m.Body}
	if phys, isView := c.viewPhys[id]; isView {
		res.Body, res.Alias, res.Phys = withString(m.Body, "collection", phys), coll, phys
	}
	return c.forward(h, m.Flags, res, id)
}

func (c *conn) handleKillCursors(h wire.Header, m *wire.Msg, db string) error {
	coll, _ := m.Body.Lookup("killCursors").StringValueOK()
	arr, ok := m.Body.Lookup("cursors").ArrayOK()
	if c.tenant == nil || !ok || len(m.Seqs) > 0 {
		return c.reply(h, errorDoc(13, "Unauthorized", "tenant proxy: authentication required"))
	}
	vals, _ := arr.Values()
	var owned, missing []bsoncore.Value
	var ownedIDs []int64
	var virtualKilled []bsoncore.Value
	for _, v := range vals {
		id, ok := v.AsInt64OK()
		if sub, virtual := c.streams[id]; virtual && ok && c.cursors[id] == db+"."+coll {
			sub.Close()
			delete(c.streams, id)
			delete(c.cursors, id)
			virtualKilled = append(virtualKilled, v)
			continue
		}
		if ns, has := c.cursors[id]; ok && has && ns == db+"."+coll {
			owned = append(owned, v)
			ownedIDs = append(ownedIDs, id)
		} else {
			missing = append(missing, v)
		}
	}
	if len(owned) == 0 {
		return c.reply(h, bsoncore.BuildDocument(nil,
			bsoncore.AppendArrayElement(nil, "cursorsKilled", bsoncore.BuildArray(nil, virtualKilled...)),
			bsoncore.AppendArrayElement(nil, "cursorsNotFound", bsoncore.BuildArray(nil, missing...)),
			bsoncore.AppendArrayElement(nil, "cursorsAlive", bsoncore.BuildArray(nil)),
			bsoncore.AppendArrayElement(nil, "cursorsUnknown", bsoncore.BuildArray(nil)),
			bsoncore.AppendInt32Element(nil, "ok", 1),
		))
	}
	elems, err := m.Body.Elements()
	if err != nil {
		return err
	}
	nb := make([]byte, 4)
	for _, e := range elems {
		if e.Key() == "cursors" {
			nb = bsoncore.AppendArrayElement(nb, "cursors", bsoncore.BuildArray(nil, owned...))
		} else {
			nb = append(nb, e...)
		}
	}
	nb = append(nb, 0)
	n := len(nb)
	nb[0], nb[1], nb[2], nb[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	for _, id := range ownedIDs {
		delete(c.cursors, id)
	}
	for _, id := range ownedIDs {
		if phys, isView := c.viewPhys[id]; isView {
			nb = withString(nb, "killCursors", phys)
			delete(c.viewPhys, id)
		}
	}
	return c.forward(h, m.Flags, &rewrite.Result{Command: "killCursors", DB: db, Body: nb}, 0)
}

// ---- handshake -----------------------------------------------------------

func (c *conn) helloDoc(legacy bool) bsoncore.Document {
	l := c.s.limits
	b := make([]byte, 4, 256)
	b = bsoncore.AppendBooleanElement(b, "helloOk", true)
	b = bsoncore.AppendBooleanElement(b, "ismaster", true)
	b = bsoncore.AppendBooleanElement(b, "isWritablePrimary", true)
	// Present as a mongos so drivers never try to discover (and bypass the
	// proxy via) the real replica-set members.
	b = bsoncore.AppendStringElement(b, "msg", "isdbgrid")
	b = bsoncore.AppendInt32Element(b, "maxBsonObjectSize", l.maxBSON)
	b = bsoncore.AppendInt32Element(b, "maxMessageSizeBytes", l.maxMessage)
	b = bsoncore.AppendInt32Element(b, "maxWriteBatchSize", l.maxBatch)
	b = bsoncore.AppendDateTimeElement(b, "localTime", time.Now().UnixMilli())
	b = bsoncore.AppendInt32Element(b, "logicalSessionTimeoutMinutes", l.sessionTimeout)
	b = bsoncore.AppendInt32Element(b, "connectionId", int32(c.id))
	b = bsoncore.AppendInt32Element(b, "minWireVersion", l.minWire)
	b = bsoncore.AppendInt32Element(b, "maxWireVersion", l.maxWire)
	b = bsoncore.AppendBooleanElement(b, "readOnly", false)
	b = bsoncore.AppendInt32Element(b, "ok", 1)
	b = append(b, 0)
	n := len(b)
	b[0], b[1], b[2], b[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return b
}

func (c *conn) hello(req bsoncore.Document) bsoncore.Document {
	if c.s.auth.Mode() == "appname" && c.tenant == nil {
		if name, ok := req.Lookup("client", "application", "name").StringValueOK(); ok {
			id, err := c.s.auth.ResolveAppName(name)
			if err == nil {
				err = c.bindTenant(id)
				if err == nil {
					c.authOK()
				}
			}
			if err != nil {
				c.authFail("", "appName authentication failed")
				c.log.Warn("appName authentication failed", "err", err)
				return errorDoc(18, "AuthenticationFailed", "Authentication failed.")
			}
		}
	}
	d := c.helloDoc(false)
	if c.s.auth.Mode() == "scram" {
		if _, ok := req.Lookup("saslSupportedMechs").StringValueOK(); ok {
			mech := bsoncore.BuildArray(nil, bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "SCRAM-SHA-256")})
			d = insertBeforeOK(d, bsoncore.AppendArrayElement(nil, "saslSupportedMechs", mech))
		}
	}
	return d
}

// insertBeforeOK appends an element to a document built by helloDoc.
func insertBeforeOK(d bsoncore.Document, elem []byte) bsoncore.Document {
	out := make([]byte, 0, len(d)+len(elem))
	out = append(out, d[:len(d)-1]...)
	out = append(out, elem...)
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// handleLegacy answers the OP_QUERY handshake that drivers send before they
// know the server speaks OP_MSG.
func (c *conn) handleLegacy(h wire.Header, body []byte) error {
	q, err := wire.ParseQuery(body)
	if err != nil {
		return err
	}
	name := rewrite.CommandName(q.Doc)
	var resp bsoncore.Document
	switch name {
	case "hello", "isMaster", "ismaster":
		resp = c.hello(q.Doc)
	default:
		resp = errorDoc(59, "CommandNotFound", "tenant proxy: only the handshake may use OP_QUERY")
	}
	return wire.WriteFrame(c.nc, c.nextRequestID(), h.RequestID, wire.OpReply, wire.EncodeReply(resp))
}

// ---- SCRAM ---------------------------------------------------------------

func (c *conn) handleSASL(name string, cmd bsoncore.Document) bsoncore.Document {
	fail := func() bsoncore.Document {
		c.sasl = nil
		c.authFail(c.saslUser, "invalid credentials or tenant unavailable")
		return errorDoc(18, "AuthenticationFailed", "Authentication failed.")
	}
	if c.s.auth.Mode() != "scram" {
		return errorDoc(59, "CommandNotFound", "tenant proxy: authentication is not enabled; the tenant is determined by the proxy")
	}
	_, payload, _ := cmd.Lookup("payload").BinaryOK()
	var (
		out  []byte
		done bool
		err  error
	)
	if name == "saslStart" {
		if mech, _ := cmd.Lookup("mechanism").StringValueOK(); mech != "SCRAM-SHA-256" {
			return errorDoc(334, "MechanismUnavailable", "tenant proxy: only SCRAM-SHA-256 is supported")
		}
		skip, _ := cmd.Lookup("options", "skipEmptyExchange").BooleanOK()
		c.saslUser = saslUser(payload)
		c.sasl, out, err = c.s.auth.StartSASL(payload, skip)
		if err != nil {
			return fail()
		}
	} else {
		if c.sasl == nil {
			return fail()
		}
		out, done, err = c.sasl.Continue(payload)
		if err != nil {
			return fail()
		}
		if c.sasl.Authenticated() && c.tenant == nil {
			if err := c.bindTenant(c.sasl.Tenant()); err != nil {
				c.log.Warn("tenant bind failed", "err", err)
				return fail()
			}
			c.setUser(c.sasl.Username())
			c.authOK()
		}
		if done {
			c.sasl = nil
		}
	}
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "conversationId", 1),
		bsoncore.AppendBooleanElement(nil, "done", done),
		bsoncore.AppendBinaryElement(nil, "payload", 0, out),
		bsoncore.AppendInt32Element(nil, "ok", 1),
	)
}

// runSteps executes housekeeping commands on the upstream connection. It
// returns an error document for the client if one fails.
func (c *conn) runSteps(cmds []rewrite.Command) bsoncore.Document {
steps:
	for _, cmd := range cmds {
		if cmd.CacheKey != "" {
			if _, done := c.s.steps.Load(cmd.CacheKey); done {
				continue
			}
		}
		resp, err := c.s.dial.RunCommand(c.up, cmd.DB, cmd.Body)
		if err != nil {
			return errorDoc(6, "HostUnreachable", "tenant proxy: "+err.Error())
		}
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			code, _ := resp.Lookup("code").AsInt64OK()
			for _, ig := range cmd.IgnoreCodes {
				if int64(ig) == code {
					if cmd.CacheKey != "" {
						c.s.steps.Store(cmd.CacheKey, struct{}{})
					}
					continue steps
				}
			}
			return resp
		}
		if cmd.CacheKey != "" {
			c.s.steps.Store(cmd.CacheKey, struct{}{})
		}
	}
	return nil
}

// writeTarget returns the collection a write-type command targets ("" otherwise).
func writeTarget(res *rewrite.Result) string {
	switch res.Command {
	case "insert", "update", "delete", "findAndModify", "createIndexes", "create":
		if e, err := res.Body.IndexErr(0); err == nil {
			c, _ := e.Value().StringValueOK()
			return c
		}
	}
	return ""
}
