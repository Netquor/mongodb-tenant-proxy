package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
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
	if err := rewrite.ValidateBody(m.Body); err != nil {
		return c.reply(h, toErrorDoc(err))
	}

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
		c.s.M.Command(name, "denied")
		return c.reply(h, errorDoc(13, "Unauthorized", "tenant proxy: authentication required"))
	}

	if handled, err := c.maybeView(h, m, name, db); handled || err != nil {
		return err
	}

	res, err := c.s.rw.Rewrite(c.tenant, db, m.Body, m.Seqs)
	if err == nil && name == "listCollections" {
		c.hookListCollections(res, m.Body, db)
	}
	if err != nil {
		c.s.M.Command(name, "denied")
		c.log.Warn("command denied", "db", db, "command", name, "reason", err.Error())
		if m.Flags&wire.FlagMoreToCome != 0 {
			return nil
		}
		return c.reply(h, toErrorDoc(err))
	}
	if res.Reply != nil {
		c.s.M.Command(name, "ok")
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
		c.s.M.Command(res.Command, "error")
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
		c.s.M.Command(res.Command, "error")
		return c.reply(h, bad)
	}
	out := wire.Msg{
		Flags: flags &^ (wire.FlagExhaustAllowed | wire.FlagChecksumPresent),
		Body:  res.Body,
		Seqs:  res.Seqs,
	}
	if err := c.writeUp(h.RequestID, res.Command, out.Encode()); err != nil {
		return fmt.Errorf("upstream write: %w", err)
	}
	if flags&wire.FlagMoreToCome != 0 {
		c.s.M.Command(res.Command, "ok")
		return nil // unacknowledged write: no reply
	}
	needParse := res.Post != nil || res.Alias != "" || len(res.After) > 0 || tracksCursor(res.Command)
	rh, rb, raw, err := c.readUp(needParse)
	if err != nil {
		return err
	}
	if needParse {
		rm, err := wire.ParseMsg(rb)
		if err != nil {
			return err
		}
		if len(res.After) > 0 {
			if ok, _ := rm.Body.Lookup("ok").AsInt64OK(); ok == 1 {
				if bad := c.runSteps(res.After); bad != nil {
					c.s.M.Command(res.Command, "error")
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
	c.s.M.Command(res.Command, "ok")
	c.s.M.BytesOut.Add(int64(len(rb) + 16))
	if raw {
		// Compressed by the upstream with the compressor the client
		// negotiated: relay it without recompressing.
		return wire.WriteFrame(c.nc, rh.RequestID, h.RequestID, wire.OpCompressed, rb)
	}
	return c.send(rh.RequestID, h.RequestID, wire.OpMsg, rb)
}

// writeUp sends a request upstream, compressing it when the upstream
// connection negotiated compression and the command may be compressed.
func (c *conn) writeUp(requestID int32, cmd string, body []byte) error {
	if c.up.Comp != wire.CompNone && wire.Compressible(cmd) {
		cb, err := wire.Compress(c.up.Comp, wire.OpMsg, body)
		if err != nil {
			return err
		}
		return wire.WriteFrame(c.up, requestID, 0, wire.OpCompressed, cb)
	}
	return wire.WriteFrame(c.up, requestID, 0, wire.OpMsg, body)
}

// readUp reads the upstream reply as an uncompressed OP_MSG body. When the
// reply is OP_COMPRESSED with the compressor the client expects and the
// caller does not need to parse it, the compressed body is returned as is
// (raw=true) so it can be relayed without touching the payload.
func (c *conn) readUp(needParse bool) (h wire.Header, body []byte, raw bool, err error) {
	h, body, err = wire.ReadFrame(c.up.R, c.s.cfg.MaxMessageBytes)
	if err != nil {
		return h, nil, false, fmt.Errorf("upstream read: %w", err)
	}
	switch h.OpCode {
	case wire.OpMsg:
		return h, body, false, nil
	case wire.OpCompressed:
		if id, ok := wire.CompressorID(body); ok && !needParse && id == c.reqComp && id != wire.CompNone {
			return h, body, true, nil
		}
		op, _, data, err := wire.Decompress(body, c.s.cfg.MaxMessageBytes)
		if err != nil {
			return h, nil, false, fmt.Errorf("upstream read: %w", err)
		}
		if op == wire.OpMsg {
			return h, data, false, nil
		}
	}
	return h, nil, false, errors.New("unexpected upstream opcode")
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
		c.s.M.Command("getMore", "denied")
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
	if c.s.auth.Has("appname") && c.tenant == nil {
		if name, ok := req.Lookup("client", "application", "name").StringValueOK(); ok {
			id, err := c.s.auth.ResolveAppName(name)
			if err == nil {
				err = c.bindTenant(id)
			}
			if err != nil {
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
	return c.bindTenant(tenant)
}

func (c *conn) handleSASL(name string, cmd bsoncore.Document) bsoncore.Document {
	fail := func() bsoncore.Document {
		c.sasl = nil
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
			skip, _ := cmd.Lookup("options", "skipEmptyExchange").BooleanOK()
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
