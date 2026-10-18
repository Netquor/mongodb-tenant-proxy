package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
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
	rt, rtErr := c.planRoute(name, m.Body)
	if rtErr != nil {
		return c.reply(h, errorDoc(2, "BadValue", "invalid $readPreference: "+rtErr.Error()))
	}
	c.rt = rt
	if rt.startTxn {
		c.txnBody = txnAbortBody(m.Body)
	}

	if rel, bad := c.admit(name, m, len(body)); bad != nil {
		if m.Flags&wire.FlagMoreToCome != 0 {
			return nil
		}
		return c.reply(h, bad)
	} else {
		defer rel()
	}
	defer c.syncCursors()

	switch name {
	case "hello", "isMaster", "ismaster":
		return c.reply(h, c.hello(m.Body))
	case "saslStart", "saslContinue":
		return c.reply(h, c.handleSASL(name, m.Body))
	case "authenticate":
		return c.reply(h, c.handleAuthenticate(m.Body))
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
	if bad := changeStreamUnsupported(res, c.s.limits.maxWire); bad != nil {
		c.s.M.Command(name, "error")
		return c.reply(h, bad)
	}
	if res.Run != nil {
		return c.runResult(h, m, res)
	}
	if len(res.Namespaces) > 0 {
		if err := c.checkBulkViews(res); err != nil {
			c.s.M.Command(name, "denied")
			return c.reply(h, c.runErrorDoc(err))
		}
	}
	if res.Stream != nil && c.s.fan != nil {
		if handled, err := c.openStream(h, m, res); handled || err != nil {
			return err
		}
	}
	return c.forward(h, m.Flags, res, 0)
}

// ensureUp makes sure the command in progress has an upstream connection.
func (c *conn) ensureUp() error {
	if c.up != nil {
		return nil
	}
	return c.useUp(c.rt)
}

// forward sends a rewritten command upstream and relays the reply.
func (c *conn) forward(h wire.Header, flags uint32, res *rewrite.Result, getMoreID int64) error {
	if err := c.applyMaxTime(res); err != nil {
		return c.reply(h, toErrorDoc(err))
	}
	if err := c.useUp(c.rt); err != nil {
		c.log.Error("upstream unavailable", "err", err)
		c.cmdDone(res.Command, "error")
		return c.reply(h, c.upstreamError(c.rt, err))
	}
	if !c.s.cfg.ChangeStreams.DisableAutoImages && c.s.dbWatched(res.DB) {
		// A database-level stream is open: collections created from now on
		// need pre/post images before their first write.
		if coll := writeTarget(res); coll != "" {
			err := c.retryUp(c.rt, func(u *upstream.Conn) error { return c.s.dial.EnsureImages(u, res.DB, coll) })
			if err != nil {
				c.log.Warn("enabling change stream images failed", "coll", coll, "err", err)
			}
		}
	}
	if res.ChangeStream && res.DBLevel {
		c.s.dbStreams.Store(res.DB, struct{}{})
	}
	if res.ChangeStream && !c.s.cfg.ChangeStreams.DisableAutoImages {
		err := c.retryUp(c.rt, func(u *upstream.Conn) error {
			if res.DBLevel {
				return c.s.dial.EnsureImagesDB(u, res.DB)
			}
			return c.s.dial.EnsureImages(u, res.DB, res.Collection)
		})
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
	return c.exchange(h, flags, res, getMoreID, out.Encode())
}

func tracksCursor(cmd string) bool {
	switch cmd {
	case "find", "aggregate", "listIndexes", "listCollections", "getMore", "bulkWrite":
		return true
	}
	return false
}

// trackCursor records cursors opened on this connection so that getMore and
// killCursors can only ever address cursors this tenant created.
func (c *conn) trackCursor(cmd string, getMoreID int64, resp bsoncore.Document) {
	if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
		c.noteCursor(cmd, getMoreID, false, 0, "")
		return
	}
	cur, ok := resp.Lookup("cursor").DocumentOK()
	if !ok {
		return
	}
	id, _ := cur.Lookup("id").AsInt64OK()
	ns, _ := cur.Lookup("ns").StringValueOK()
	c.noteCursor(cmd, getMoreID, true, id, ns)
}

// noteCursor is trackCursor on already-extracted fields (the streaming relay
// never materialises the reply document).
func (c *conn) noteCursor(cmd string, getMoreID int64, ok bool, id int64, ns string) {
	if !ok {
		if cmd == "getMore" {
			c.forgetCursor(getMoreID)
		}
		return
	}
	switch {
	case id == 0 && cmd == "getMore":
		c.forgetCursor(getMoreID)
	case id != 0 && cmd != "getMore":
		if len(c.cursors) < maxCursorsPerConn {
			c.cursors[id] = ns
			if c.up != nil {
				c.cursorAt[id] = c.up.Addr
			}
			if c.rt.tail {
				c.pinTail(id)
			}
		}
	}
}

func (c *conn) forgetCursor(id int64) {
	delete(c.cursors, id)
	delete(c.idCursors, id)
	delete(c.viewPhys, id)
	delete(c.cursorAt, id)
	c.unpinTail(id)
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
	// A cursor lives on one member, and change-stream / tailable cursors on
	// one connection: the getMore must go back there. It is never repeated.
	c.rt.read = false
	c.rt.sel = upstream.Selector{Addr: c.cursorAt[id]}
	c.rt.pinned = c.tails[id]
	c.rt.tail = c.tails[id] != nil
	if c.idCursors[id] {
		res.IDCursor, res.Post = true, c.s.rt().rw.IDPost(c.tenant)
	}
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
		if phys, isView := c.viewPhys[id]; isView {
			nb = withString(nb, "killCursors", phys)
		}
	}
	// Cursors can live on different members; the first group is killed by
	// the command itself, any others best-effort.
	first := c.cursorAt[ownedIDs[0]]
	c.rt.read = false
	c.rt.sel = upstream.Selector{Addr: first}
	c.rt.pinned = c.tails[ownedIDs[0]]
	rest := map[string][]int64{}
	for _, id := range ownedIDs {
		if a := c.cursorAt[id]; a != first {
			rest[a] = append(rest[a], id)
		}
	}
	err = c.forward(h, m.Flags, &rewrite.Result{Command: "killCursors", DB: db, Body: nb}, 0)
	for a, ids := range rest {
		c.killAt(a, db+"."+coll, ids)
	}
	for _, id := range ownedIDs {
		c.forgetCursor(id)
	}
	return err
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
	if c.s.auth.Has("appname") && c.tenant == nil {
		if name, ok := wire.LookupPath(req, "client", "application", "name").StringValueOK(); ok {
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
	if names := c.negotiateCompression(req); len(names) > 0 {
		vals := make([]bsoncore.Value, len(names))
		for i, n := range names {
			vals[i] = bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, n)}
		}
		d = insertBeforeOK(d, bsoncore.AppendArrayElement(nil, "compression", bsoncore.BuildArray(nil, vals...)))
	}
	if user, ok := req.Lookup("saslSupportedMechs").StringValueOK(); ok {
		if mechs := c.s.auth.SupportedMechs(user); len(mechs) > 0 {
			vals := make([]bsoncore.Value, len(mechs))
			for i, m := range mechs {
				vals[i] = bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, m)}
			}
			d = insertBeforeOK(d, bsoncore.AppendArrayElement(nil, "saslSupportedMechs", bsoncore.BuildArray(nil, vals...)))
		}
	}
	return d
}

// negotiateCompression returns the client's requested compressors that the
// proxy has enabled, in the client's order.
func (c *conn) negotiateCompression(req bsoncore.Document) []string {
	if len(c.s.clientComp) == 0 {
		return nil
	}
	arr, ok := req.Lookup("compression").ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := arr.Values()
	var out []string
	for _, v := range vals {
		n, _ := v.StringValueOK()
		if id, ok := wire.CompressorByName(n); ok && c.s.clientComp[id] {
			out = append(out, id.String())
		}
	}
	return out
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

// ---- client authentication ----------------------------------------------

func saslReply(done bool, payload []byte) bsoncore.Document {
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "conversationId", 1),
		bsoncore.AppendBooleanElement(nil, "done", done),
		bsoncore.AppendBinaryElement(nil, "payload", 0, payload),
		bsoncore.AppendInt32Element(nil, "ok", 1),
	)
}

func authFailed() bsoncore.Document {
	return errorDoc(18, "AuthenticationFailed", "Authentication failed.")
}

// authenticated binds the connection to the tenant a mechanism resolved. A
// connection that is already bound can only re-authenticate as the same tenant.
func (c *conn) authenticated(tenant string) error {
	if c.tenant != nil {
		if c.tenant.ID == tenant {
			return nil
		}
		return errors.New("connection is already authenticated as another tenant")
	}
	if err := c.bindTenant(tenant); err != nil {
		return err
	}
	c.authOK()
	return nil
}

func (c *conn) handleSASL(name string, cmd bsoncore.Document) bsoncore.Document {
	fail := func() bsoncore.Document {
		c.sasl = nil
		c.authFail(c.saslUser, "invalid credentials or tenant unavailable")
		return authFailed()
	}
	if len(c.s.auth.Mechanisms()) == 0 {
		return errorDoc(59, "CommandNotFound", "tenant proxy: authentication is not enabled; the tenant is determined by the proxy")
	}
	_, payload, _ := cmd.Lookup("payload").BinaryOK()
	if name == "saslStart" {
		mech, _ := cmd.Lookup("mechanism").StringValueOK()
		switch mech {
		case auth.MechOIDC:
			return c.handleOIDC(payload)
		case auth.MechSCRAM256, auth.MechSCRAM1:
			skip, _ := wire.LookupPath(cmd, "options", "skipEmptyExchange").BooleanOK()
			c.saslUser = saslUser(payload)
			var out []byte
			var err error
			c.sasl, out, err = c.s.auth.StartSASL(mech, payload, skip)
			if errors.Is(err, auth.ErrMechanismUnavailable) {
				return errorDoc(334, "MechanismUnavailable", "tenant proxy: "+mech+" is not enabled")
			}
			if err != nil {
				return fail()
			}
			return saslReply(false, out)
		}
		return errorDoc(334, "MechanismUnavailable", "tenant proxy: unsupported mechanism "+mech)
	}
	if c.sasl == nil {
		return fail()
	}
	out, done, err := c.sasl.Continue(payload)
	if err != nil {
		return fail()
	}
	if c.sasl.Authenticated() {
		c.setUser(c.sasl.Username())
		if err := c.authenticated(c.sasl.Tenant()); err != nil {
			c.log.Warn("tenant bind failed", "err", err)
			return fail()
		}
	}
	if done {
		c.sasl = nil
	}
	return saslReply(done, out)
}

// handleOIDC completes MONGODB-OIDC's machine flow: the client sends
// {jwt: "<token>"} in saslStart.
func (c *conn) handleOIDC(payload []byte) bsoncore.Document {
	tok, ok := bsoncore.Document(payload).Lookup("jwt").StringValueOK()
	if !ok || tok == "" {
		c.log.Warn("oidc authentication failed", "err", "no jwt in payload (only the machine flow is supported)")
		return authFailed()
	}
	tenant, err := c.s.auth.OIDC(tok)
	if err == nil {
		err = c.authenticated(tenant)
	}
	if err != nil {
		c.log.Warn("oidc authentication failed", "err", err)
		return authFailed()
	}
	return saslReply(true, []byte{})
}

// handleAuthenticate serves the legacy "authenticate" command, which drivers
// use for MONGODB-X509 (identity comes from the TLS client certificate).
func (c *conn) handleAuthenticate(cmd bsoncore.Document) bsoncore.Document {
	mech, _ := cmd.Lookup("mechanism").StringValueOK()
	if mech != auth.MechX509 {
		return errorDoc(334, "MechanismUnavailable", "tenant proxy: unsupported mechanism "+mech)
	}
	if !c.s.auth.Has("x509") {
		return errorDoc(334, "MechanismUnavailable", "tenant proxy: MONGODB-X509 is not enabled")
	}
	tc, ok := c.nc.(*tls.Conn)
	if !ok {
		return authFailed()
	}
	state := tc.ConnectionState()
	user, _ := cmd.Lookup("user").StringValueOK()
	tenant, err := c.s.auth.X509(&state, user)
	if err == nil {
		err = c.authenticated(tenant)
	}
	if err != nil {
		c.log.Warn("x509 authentication failed", "err", err)
		return authFailed()
	}
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "dbname", "$external"),
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
		if cmd.Func != nil {
			if err := cmd.Func(connUp{c}); err != nil {
				return c.runErrorDoc(err)
			}
			continue
		}
		resp, err := c.runUp(c.rt, cmd.DB, cmd.Body)
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

// noteIDCursor remembers cursors whose documents need their _id unwrapped.
func (c *conn) noteIDCursor(cmd string, getMoreID int64, resp bsoncore.Document) {
	cur, ok := resp.Lookup("cursor").DocumentOK()
	if !ok {
		return
	}
	id, _ := cur.Lookup("id").AsInt64OK()
	switch {
	case id == 0 && cmd == "getMore":
		delete(c.idCursors, getMoreID)
	case id != 0 && cmd != "getMore":
		if c.idCursors == nil {
			c.idCursors = map[int64]bool{}
		}
		c.idCursors[id] = true
	}
}
