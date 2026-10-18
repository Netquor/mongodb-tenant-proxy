package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Tenant-scoped views.
//
// A physical view is shared by every tenant, so it cannot hold a per-tenant
// definition. Instead each tenant view becomes its own hidden physical view
// `__mtp_v.<tenant hash>.<name>` whose pipeline starts with the tenant filter,
// and the proxy maps the tenant's view name to it. Definitions are kept in
// `__mtp_views` (per database), which also lets two tenants use the same view
// name with different definitions. Tenants never see the hidden names.

const (
	viewsColl = "__mtp_views"
	viewTTL   = 5 * time.Second
)

type viewDef struct {
	Name, ViewOn, Phys string
	Pipeline           bsoncore.Array
}

type viewSet struct {
	at time.Time
	m  map[string]*viewDef
}

type viewCache struct{ m sync.Map } // db + "\x00" + tenant -> *viewSet

func physName(tenant, name string) string {
	h := sha256.Sum256([]byte(tenant))
	return "__mtp_v." + hex.EncodeToString(h[:6]) + "." + name
}

func viewDocID(tenant, name string) string { return physName(tenant, name) }

func (c *conn) cacheKey(db string) string { return db + "\x00" + c.tenant.ID }

func (c *conn) invalidateViews(db string) { c.s.views.m.Delete(c.cacheKey(db)) }

// views returns the tenant's views in db (cached for a few seconds).
func (c *conn) viewsIn(db string) (map[string]*viewDef, error) {
	if v, ok := c.s.views.m.Load(c.cacheKey(db)); ok {
		if vs := v.(*viewSet); time.Since(vs.at) < viewTTL {
			return vs.m, nil
		}
	}
	if err := c.ensureUp(); err != nil {
		return nil, err
	}
	filter := bsoncore.BuildDocument(nil, valueElem(c.s.cfg.Tenant.Field, c.tenant.Value))
	resp, err := c.s.dial.RunCommand(c.up, db, bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "find", viewsColl),
		bsoncore.AppendDocumentElement(nil, "filter", filter),
		bsoncore.AppendInt32Element(nil, "batchSize", 100000),
		bsoncore.AppendBooleanElement(nil, "singleBatch", true)))
	if err != nil {
		return nil, err
	}
	out := map[string]*viewDef{}
	if batch, ok := wire.LookupPath(resp, "cursor", "firstBatch").ArrayOK(); ok {
		vals, _ := batch.Values()
		for _, v := range vals {
			d, ok := v.DocumentOK()
			if !ok {
				continue
			}
			def := &viewDef{}
			def.Name, _ = d.Lookup("name").StringValueOK()
			def.ViewOn, _ = d.Lookup("viewOn").StringValueOK()
			def.Phys, _ = d.Lookup("phys").StringValueOK()
			def.Pipeline, _ = d.Lookup("pipeline").ArrayOK()
			if def.Name != "" && def.Phys != "" {
				out[def.Name] = def
			}
		}
	}
	c.s.views.m.Store(c.cacheKey(db), &viewSet{at: time.Now(), m: out})
	return out, nil
}

func valueElem(key string, v bsoncore.Value) []byte { return bsoncore.AppendValueElement(nil, key, v) }

var viewReadCmds = map[string]bool{"find": true, "aggregate": true, "count": true, "distinct": true}
var viewWriteCmds = map[string]bool{"insert": true, "update": true, "delete": true, "findAndModify": true,
	"findandmodify": true, "createIndexes": true, "dropIndexes": true, "listIndexes": true, "mapReduce": true}

// maybeView intercepts commands that name one of the tenant's views (or that
// create, drop or modify one). handled is false when the command is not
// view-related and should take the normal path.
func (c *conn) maybeView(h wire.Header, m *wire.Msg, name, db string) (handled bool, err error) {
	if c.s.cfg.DisableViews {
		return false, nil
	}
	switch {
	case name == "create", name == "drop", name == "collMod", viewReadCmds[name], viewWriteCmds[name]:
	default:
		return false, nil
	}
	coll, ok := m.Body.Index(0).Value().StringValueOK()
	if !ok {
		return false, nil
	}
	if name == "collMod" {
		// collMod on a collection (validators) is handled by the rewriter.
		if !c.s.rw.AllowedDB(db) || c.s.rw.Denied(name) {
			return false, nil
		}
		views, verr := c.viewsIn(db)
		if verr != nil {
			return true, c.reply(h, errorDoc(6, "HostUnreachable", "tenant proxy: upstream unavailable"))
		}
		if views[coll] == nil {
			return false, nil
		}
		return true, c.viewDDL(h, m, name, db, coll)
	}
	if name == "create" && m.Body.Lookup("viewOn").Type != 0 {
		return true, c.viewDDL(h, m, name, db, coll)
	}
	if !c.s.rw.AllowedDB(db) || c.s.rw.Denied(name) {
		return false, nil // let the normal path produce the right error
	}
	views, verr := c.viewsIn(db)
	if verr != nil {
		c.log.Error("loading views failed", "err", verr)
		return true, c.reply(h, errorDoc(6, "HostUnreachable", "tenant proxy: upstream unavailable"))
	}
	def := views[coll]
	switch {
	case def == nil:
		return false, nil
	case name == "create":
		return true, c.reply(h, errorDoc(48, "NamespaceExists", "Collection already exists. NS: "+db+"."+coll))
	case name == "drop":
		return true, c.dropView(h, db, def)
	case viewReadCmds[name]:
		res, err := c.s.rw.RewriteView(c.tenant, db, m.Body, m.Seqs, def.Phys)
		if err != nil {
			c.s.M.Command(name, "denied")
			return true, c.reply(h, toErrorDoc(err))
		}
		res.Alias, res.Phys = coll, def.Phys
		return true, c.forward(h, m.Flags, res, 0)
	default:
		return true, c.reply(h, errorDoc(166, "CommandNotSupportedOnView", name+" is not supported on views"))
	}
}

func (c *conn) run(db string, cmd bsoncore.Document) (bsoncore.Document, error) {
	if err := c.ensureUp(); err != nil {
		return nil, err
	}
	return c.s.dial.RunCommand(c.up, db, cmd)
}

func failed(resp bsoncore.Document) bool {
	ok, _ := resp.Lookup("ok").AsInt64OK()
	return ok != 1
}

// viewDDL handles create (with viewOn) and collMod on a view.
func (c *conn) viewDDL(h wire.Header, m *wire.Msg, name, db, coll string) error {
	fail := func(err error) error { return c.reply(h, toErrorDoc(err)) }
	if !c.s.rw.AllowedDB(db) || c.s.rw.Denied(name) {
		return c.reply(h, errorDoc(13, "Unauthorized", "tenant proxy: command not allowed"))
	}
	if err := rewrite.CheckCollName(coll); err != nil {
		return fail(err)
	}
	views, err := c.viewsIn(db)
	if err != nil {
		return c.reply(h, errorDoc(6, "HostUnreachable", "tenant proxy: upstream unavailable"))
	}
	existing := views[coll]
	if name == "collMod" && existing == nil {
		return c.reply(h, errorDoc(13, "Unauthorized", "tenant proxy: collMod is only supported on views"))
	}
	if name == "create" && existing != nil {
		return c.reply(h, errorDoc(48, "NamespaceExists", "Collection already exists. NS: "+db+"."+coll))
	}

	viewOn, hasViewOn := m.Body.Lookup("viewOn").StringValueOK()
	pipeline, hasPipe := m.Body.Lookup("pipeline").ArrayOK()
	if name == "collMod" {
		if !hasViewOn {
			viewOn = existing.ViewOn
		}
		if !hasPipe {
			pipeline = existing.Pipeline
		}
	} else if !hasViewOn {
		return fail(&rewrite.Error{Code: 2, CodeName: "BadValue", Msg: "viewOn must be a string"})
	}
	if pipeline == nil {
		pipeline = bsoncore.BuildArray(nil)
	}
	if viewOn == coll {
		return c.reply(h, errorDoc(2, "BadValue", "a view cannot be defined on itself"))
	}

	// The view reads a shared collection (scoped by injected filter) or one of
	// the tenant's own views (already scoped).
	physOn, inject := viewOn, true
	if src, ok := views[viewOn]; ok {
		physOn, inject = src.Phys, false
	} else if err := rewrite.CheckCollName(viewOn); err != nil {
		return fail(err)
	}
	scoped, err := c.s.rw.ScopeViewPipeline(c.tenant, pipeline, inject)
	if err != nil {
		return fail(err)
	}

	phys := physName(c.tenant.ID, coll)
	if name == "create" {
		// A view may not shadow documents the tenant already has under that name.
		probe, err := c.run(db, bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "find", coll),
			bsoncore.AppendDocumentElement(nil, "filter", bsoncore.BuildDocument(nil, valueElem(c.s.cfg.Tenant.Field, c.tenant.Value))),
			bsoncore.AppendInt32Element(nil, "limit", 1),
			bsoncore.AppendBooleanElement(nil, "singleBatch", true)))
		if err == nil && !failed(probe) {
			if b, _ := wire.LookupPath(probe, "cursor", "firstBatch").ArrayOK(); b != nil {
				if vals, _ := b.Values(); len(vals) > 0 {
					return c.reply(h, errorDoc(48, "NamespaceExists", "Collection already exists. NS: "+db+"."+coll))
				}
			}
		}
		cmd := bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "create", phys),
			bsoncore.AppendStringElement(nil, "viewOn", physOn),
			bsoncore.AppendArrayElement(nil, "pipeline", scoped))
		if col := m.Body.Lookup("collation"); col.Type != 0 {
			if err := rewrite.CheckCollation(col); err != nil {
				return fail(err)
			}
			cmd = appendRaw(cmd, valueElem("collation", col))
		}
		if resp, err := c.run(db, cmd); err != nil || failed(resp) {
			return c.relay(h, resp, err)
		}
	} else {
		cmd := bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "collMod", phys),
			bsoncore.AppendStringElement(nil, "viewOn", physOn),
			bsoncore.AppendArrayElement(nil, "pipeline", scoped))
		if resp, err := c.run(db, cmd); err != nil || failed(resp) {
			return c.relay(h, resp, err)
		}
	}

	field := c.s.cfg.Tenant.Field
	def := bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "_id", viewDocID(c.tenant.ID, coll)),
		valueElem(field, c.tenant.Value),
		bsoncore.AppendStringElement(nil, "name", coll),
		bsoncore.AppendStringElement(nil, "viewOn", viewOn),
		bsoncore.AppendArrayElement(nil, "pipeline", pipeline),
		bsoncore.AppendStringElement(nil, "phys", phys))
	upsert := bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "update", viewsColl),
		bsoncore.AppendArrayElement(nil, "updates", arrayOfDocs(bsoncore.BuildDocument(nil,
			bsoncore.AppendDocumentElement(nil, "q", bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "_id", viewDocID(c.tenant.ID, coll)))),
			bsoncore.AppendDocumentElement(nil, "u", def),
			bsoncore.AppendBooleanElement(nil, "upsert", true)))))
	if resp, err := c.run(db, upsert); err != nil || failed(resp) {
		if name == "create" {
			c.run(db, bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "drop", phys)))
		}
		return c.relay(h, resp, err)
	}
	c.invalidateViews(db)
	c.s.M.Command(name, "ok")
	return c.reply(h, okDoc())
}

func (c *conn) dropView(h wire.Header, db string, def *viewDef) error {
	if resp, err := c.run(db, bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "drop", def.Phys))); err != nil || failed(resp) {
		return c.relay(h, resp, err)
	}
	del := bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "delete", viewsColl),
		bsoncore.AppendArrayElement(nil, "deletes", arrayOfDocs(bsoncore.BuildDocument(nil,
			bsoncore.AppendDocumentElement(nil, "q", bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "_id", viewDocID(c.tenant.ID, def.Name)))),
			bsoncore.AppendInt32Element(nil, "limit", 1)))))
	if resp, err := c.run(db, del); err != nil || failed(resp) {
		return c.relay(h, resp, err)
	}
	c.invalidateViews(db)
	c.s.M.Command("drop", "ok")
	return c.reply(h, bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "ns", db+"."+def.Name),
		bsoncore.AppendInt32Element(nil, "ok", 1)))
}

// relay returns an upstream failure to the client.
func (c *conn) relay(h wire.Header, resp bsoncore.Document, err error) error {
	if err != nil {
		return c.reply(h, errorDoc(6, "HostUnreachable", "tenant proxy: "+err.Error()))
	}
	return c.reply(h, resp)
}

func arrayOfDocs(docs ...bsoncore.Document) bsoncore.Array {
	vals := make([]bsoncore.Value, len(docs))
	for i, d := range docs {
		vals[i] = bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: d}
	}
	return bsoncore.BuildArray(nil, vals...)
}

func appendRaw(d bsoncore.Document, elem []byte) bsoncore.Document {
	out := make([]byte, 0, len(d)+len(elem))
	out = append(out, d[:len(d)-1]...)
	out = append(out, elem...)
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// withString returns doc with the string field `key` set to val.
func withString(d bsoncore.Document, key, val string) bsoncore.Document {
	elems, err := d.Elements()
	if err != nil {
		return d
	}
	out := make([]byte, 4, len(d)+len(val))
	for _, e := range elems {
		if e.Key() == key {
			out = bsoncore.AppendStringElement(out, key, val)
		} else {
			out = append(out, e...)
		}
	}
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// patchCursorNS rewrites cursor.ns in a find/aggregate/getMore reply.
func patchCursorNS(resp bsoncore.Document, ns string) bsoncore.Document {
	cur, ok := resp.Lookup("cursor").DocumentOK()
	if !ok {
		return resp
	}
	nc := withString(cur, "ns", ns)
	elems, err := resp.Elements()
	if err != nil {
		return resp
	}
	out := make([]byte, 4, len(resp)+len(ns))
	for _, e := range elems {
		if e.Key() == "cursor" {
			out = bsoncore.AppendDocumentElement(out, "cursor", nc)
		} else {
			out = append(out, e...)
		}
	}
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// noteViewCursor remembers which physical view a new cursor reads.
func (c *conn) noteViewCursor(resp bsoncore.Document, phys string, getMoreID int64) {
	if getMoreID != 0 {
		return
	}
	if id, _ := wire.LookupPath(resp, "cursor", "id").AsInt64OK(); id != 0 {
		c.viewPhys[id] = phys
	}
}

// ---- listCollections --------------------------------------------------------

// hookListCollections hides internal collections and lists the tenant's views.
func (c *conn) hookListCollections(res *rewrite.Result, body bsoncore.Document, db string) {
	var views map[string]*viewDef
	if !c.s.cfg.DisableViews {
		views, _ = c.viewsIn(db)
	}
	nameOnly, _ := body.Lookup("nameOnly").BooleanOK()
	filterName := ""
	if f, ok := body.Lookup("filter").DocumentOK(); ok {
		filterName, _ = f.Lookup("name").StringValueOK()
		if t, ok := f.Lookup("type").StringValueOK(); ok && t == "collection" {
			views = nil
		}
	}
	validators := c.validatorsIn(db)
	res.Post = func(resp bsoncore.Document) bsoncore.Document {
		cur, ok := resp.Lookup("cursor").DocumentOK()
		if !ok {
			return resp
		}
		batch, _ := cur.Lookup("firstBatch").ArrayOK()
		vals, _ := batch.Values()
		var keep []bsoncore.Value
		for _, v := range vals {
			d, ok := v.DocumentOK()
			if !ok {
				continue
			}
			n, _ := d.Lookup("name").StringValueOK()
			if strings.HasPrefix(n, "__mtp_") {
				continue
			}
			keep = append(keep, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: c.ownValidator(d, n, validators)})
		}
		for name, def := range views {
			if filterName != "" && filterName != name {
				continue
			}
			d := bsoncore.BuildDocument(nil,
				bsoncore.AppendStringElement(nil, "name", name),
				bsoncore.AppendStringElement(nil, "type", "view"))
			if !nameOnly {
				d = appendRaw(d, bsoncore.AppendDocumentElement(nil, "options", bsoncore.BuildDocument(nil,
					bsoncore.AppendStringElement(nil, "viewOn", def.ViewOn),
					bsoncore.AppendArrayElement(nil, "pipeline", def.Pipeline))))
				d = appendRaw(d, bsoncore.AppendDocumentElement(nil, "info", bsoncore.BuildDocument(nil,
					bsoncore.AppendBooleanElement(nil, "readOnly", true))))
			}
			keep = append(keep, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: d})
		}
		nc := bsoncore.BuildDocument(nil,
			bsoncore.AppendArrayElement(nil, "firstBatch", bsoncore.BuildArray(nil, keep...)),
			valueElem("id", cur.Lookup("id")),
			valueElem("ns", cur.Lookup("ns")))
		return patchTop(resp, "cursor", bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: nc})
	}
}

func patchTop(d bsoncore.Document, key string, v bsoncore.Value) bsoncore.Document {
	elems, err := d.Elements()
	if err != nil {
		return d
	}
	out := make([]byte, 4, len(d))
	for _, e := range elems {
		if e.Key() == key {
			out = bsoncore.AppendValueElement(out, key, v)
		} else {
			out = append(out, e...)
		}
	}
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// validatorsIn returns the tenant's own collMod validators in db by collection.
func (c *conn) validatorsIn(db string) map[string]bsoncore.Document {
	out := map[string]bsoncore.Document{}
	resp, err := c.run(db, bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "find", rewrite.ValidatorsColl),
		bsoncore.AppendDocumentElement(nil, "filter", bsoncore.BuildDocument(nil, valueElem(c.s.cfg.Tenant.Field, c.tenant.Value))),
		bsoncore.AppendInt32Element(nil, "batchSize", 100000),
		bsoncore.AppendBooleanElement(nil, "singleBatch", true)))
	if err != nil || failed(resp) {
		return out
	}
	if batch, ok := resp.Lookup("cursor", "firstBatch").ArrayOK(); ok {
		vals, _ := batch.Values()
		for _, v := range vals {
			d, ok := v.DocumentOK()
			if !ok {
				continue
			}
			coll, _ := d.Lookup("coll").StringValueOK()
			if vd, ok := d.Lookup("validator").DocumentOK(); ok && coll != "" {
				out[coll] = vd
			}
		}
	}
	return out
}

// ownValidator replaces the collection's physical validator, which combines
// every tenant's, with the tenant's own (or none).
func (c *conn) ownValidator(entry bsoncore.Document, name string, own map[string]bsoncore.Document) bsoncore.Document {
	opts, ok := entry.Lookup("options").DocumentOK()
	if !ok {
		return entry
	}
	els, err := opts.Elements()
	if err != nil {
		return entry
	}
	no := make([]byte, 4)
	for _, e := range els {
		switch e.Key() {
		case "validator", "validationLevel", "validationAction":
		default:
			no = append(no, e...)
		}
	}
	if v, ok := own[name]; ok {
		no = bsoncore.AppendDocumentElement(no, "validator", v)
		no = bsoncore.AppendStringElement(no, "validationLevel", "strict")
		no = bsoncore.AppendStringElement(no, "validationAction", "error")
	}
	no = append(no, 0)
	n := len(no)
	no[0], no[1], no[2], no[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return patchTop(entry, "options", bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: no})
}
