// Package rewrite enforces tenant isolation by rewriting MongoDB commands so
// that they can only ever touch documents whose tenant field equals the
// connection's tenant.
//
// The rewriter works on raw BSON (no struct decoding) and follows an
// allow-list policy: any command, aggregation stage or update operator that
// is not explicitly understood is rejected rather than passed through.
package rewrite

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Tenant identifies the tenant a connection is bound to.
type Tenant struct {
	ID    string
	Value bsoncore.Value // the value stored in the tenant field
}

// NewTenant builds a Tenant whose stored value has the given type
// ("string", "objectId" or "int").
func NewTenant(idType, id string) (*Tenant, error) {
	t := &Tenant{ID: id}
	switch idType {
	case "", "string":
		t.Value = value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, id)}
	case "objectId":
		b, err := hex.DecodeString(id)
		if err != nil || len(b) != 12 {
			return nil, fmt.Errorf("tenant id %q is not a valid ObjectID", id)
		}
		t.Value = value{Type: bsoncore.TypeObjectID, Data: b}
	case "int":
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("tenant id %q is not an integer", id)
		}
		t.Value = value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, n)}
	default:
		return nil, fmt.Errorf("unknown tenant id type %q", idType)
	}
	return t, nil
}

// Config controls the rewriter.
type Config struct {
	// Field is the top-level document field that holds the tenant id.
	Field string
	// Databases lists the databases tenants may use. If empty, every
	// database except admin, local and config is allowed.
	Databases []string
	// DenyCommands lists commands to reject even though they are supported.
	DenyCommands []string
	// AllowJS permits $where/$function/$accumulator.
	AllowJS bool
}

// Rewriter rewrites commands for a tenant. It is safe for concurrent use.
type Rewriter struct {
	field string
	dbs   map[string]struct{}
	deny  map[string]struct{}
	js    bool
	cmds  map[string]cmdFn
}

// New creates a Rewriter.
func New(cfg Config) *Rewriter {
	if cfg.Field == "" {
		cfg.Field = "tenantId"
	}
	r := &Rewriter{field: cfg.Field, js: cfg.AllowJS, dbs: map[string]struct{}{}, deny: map[string]struct{}{}}
	for _, d := range cfg.Databases {
		r.dbs[d] = struct{}{}
	}
	for _, c := range cfg.DenyCommands {
		r.deny[c] = struct{}{}
	}
	r.cmds = map[string]cmdFn{
		"find":            (*Rewriter).cmdFind,
		"count":           (*Rewriter).cmdCount,
		"distinct":        (*Rewriter).cmdCount,
		"aggregate":       (*Rewriter).cmdAggregate,
		"insert":          (*Rewriter).cmdInsert,
		"update":          (*Rewriter).cmdUpdate,
		"delete":          (*Rewriter).cmdDelete,
		"findAndModify":   (*Rewriter).cmdFindAndModify,
		"createIndexes":   (*Rewriter).cmdCreateIndexes,
		"dropIndexes":     (*Rewriter).cmdDropIndexes,
		"listIndexes":     (*Rewriter).cmdListIndexes,
		"listCollections": (*Rewriter).cmdListCollections,
		"create":          (*Rewriter).cmdCreate,
		"drop":            (*Rewriter).cmdDrop,
		"explain":         (*Rewriter).cmdExplain,
		"listDatabases":   (*Rewriter).cmdListDatabases,

		// Session / transaction plumbing: carries no collection data.
		"commitTransaction": passAdmin,
		"abortTransaction":  passAdmin,
		"endSessions":       passAdmin,
		"refreshSessions":   passAdmin,
		"startSession":      passAdmin,
		"buildInfo":         passAdmin,
		"whatsmyuri":        passAdmin,

		"ping":             replyOK,
		"logout":           replyOK,
		"connectionStatus": replyConnectionStatus,
	}
	return r
}

var aliases = map[string]string{
	"findandmodify": "findAndModify",
	"buildinfo":     "buildInfo",
}

// Result is the outcome of rewriting a command.
type Result struct {
	Command string
	DB      string
	Body    bsoncore.Document
	Seqs    []wire.Seq
	// Reply, when non-nil, is sent to the client without contacting the
	// upstream server.
	Reply bsoncore.Document
	// Post, when non-nil, transforms the upstream reply before it is sent.
	Post func(bsoncore.Document) bsoncore.Document
}

type request struct {
	t    *Tenant
	db   string
	cmd  string
	body doc
	seqs []wire.Seq
	e    []bsoncore.Element
}

type cmdFn func(r *Rewriter, q *request) (*Result, error)

// CommandName returns the name of the command in body.
func CommandName(body bsoncore.Document) string {
	e, err := body.IndexErr(0)
	if err != nil {
		return ""
	}
	return e.Key()
}

// Rewrite applies tenant scoping to a command.
func (r *Rewriter) Rewrite(t *Tenant, db string, body bsoncore.Document, seqs []wire.Seq) (*Result, error) {
	elems, err := body.Elements()
	if err != nil || len(elems) == 0 {
		return nil, badValue("malformed command document")
	}
	if err := checkNoDuplicateKeys(elems); err != nil {
		return nil, err
	}
	name := elems[0].Key()
	if a, ok := aliases[name]; ok {
		name = a
	}
	if _, denied := r.deny[name]; denied {
		return nil, deny("command %q is disabled", name)
	}
	fn, ok := r.cmds[name]
	if !ok {
		return nil, deny("command %q is not allowed through the tenant proxy", name)
	}
	if !r.adminCmd(name) && !r.dbAllowed(db) {
		return nil, deny("database %q is not accessible", db)
	}
	q := &request{t: t, db: db, cmd: name, body: body, seqs: seqs, e: elems}
	res, err := fn(r, q)
	if err != nil {
		return nil, err
	}
	res.Command = name
	res.DB = db
	return res, nil
}

func (r *Rewriter) adminCmd(name string) bool {
	switch name {
	case "commitTransaction", "abortTransaction", "endSessions", "refreshSessions",
		"startSession", "buildInfo", "whatsmyuri", "ping", "logout", "connectionStatus", "listDatabases":
		return true
	}
	return false
}

func (r *Rewriter) dbAllowed(db string) bool {
	if db == "" {
		return false
	}
	if len(r.dbs) > 0 {
		_, ok := r.dbs[db]
		return ok
	}
	switch db {
	case "admin", "local", "config":
		return false
	}
	return true
}

// ---- helpers -------------------------------------------------------------

func (r *Rewriter) tenantDoc(t *Tenant) doc { return buildDoc(valElem(r.field, t.Value)) }

// scopeFilter returns a filter equivalent to old AND field == tenant.
func (r *Rewriter) scopeFilter(t *Tenant, old *value) (value, error) {
	tenant := r.tenantDoc(t)
	if old == nil {
		return docValue(tenant), nil
	}
	od, ok := old.DocumentOK()
	if !ok {
		return value{}, badValue("filter must be a document")
	}
	if len(od) == 5 { // empty document
		return docValue(tenant), nil
	}
	if !r.js {
		if err := scanDoc(od); err != nil {
			return value{}, err
		}
	}
	and := arrayOf(docValue(tenant), docValue(od))
	return docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$and", and))), nil
}

func (r *Rewriter) scopeField(q *request, body doc, key string) (doc, error) {
	return setField(body, key, func(old *value) (value, bool, error) {
		v, err := r.scopeFilter(q.t, old)
		return v, true, err
	})
}

// collection validates and returns the collection a command targets.
func (r *Rewriter) collection(q *request) (string, error) {
	s, ok := q.e[0].Value().StringValueOK()
	if !ok {
		return "", badValue("%s requires a collection name", q.cmd)
	}
	return s, checkCollName(s)
}

func checkCollName(s string) error {
	if s == "" {
		return badValue("empty collection name")
	}
	if strings.HasPrefix(s, "system.") {
		return deny("access to %q is not permitted", s)
	}
	if strings.ContainsAny(s, "$\x00") {
		return badValue("invalid collection name %q", s)
	}
	return nil
}

// noSeqs rejects unexpected OP_MSG document sequences.
func noSeqs(q *request, allowed ...string) error {
outer:
	for _, s := range q.seqs {
		for _, a := range allowed {
			if s.ID == a {
				continue outer
			}
		}
		return badValue("unexpected document sequence %q for %s", s.ID, q.cmd)
	}
	return nil
}

func passAdmin(r *Rewriter, q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	return &Result{Body: q.body}, nil
}

func replyOK(r *Rewriter, q *request) (*Result, error) {
	return &Result{Reply: buildDoc(bsoncore.AppendInt32Element(nil, "ok", 1))}, nil
}

func replyConnectionStatus(r *Rewriter, q *request) (*Result, error) {
	auth := buildDoc(
		bsoncore.AppendArrayElement(nil, "authenticatedUsers", arrayOf()),
		bsoncore.AppendArrayElement(nil, "authenticatedUserRoles", arrayOf()),
		bsoncore.AppendArrayElement(nil, "authenticatedUserPrivileges", arrayOf()),
	)
	return &Result{Reply: buildDoc(
		bsoncore.AppendDocumentElement(nil, "authInfo", auth),
		bsoncore.AppendInt32Element(nil, "ok", 1),
	)}, nil
}

// ---- reads ---------------------------------------------------------------

func (r *Rewriter) cmdFind(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	b, err := r.scopeField(q, q.body, "filter")
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}

func (r *Rewriter) cmdCount(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	b, err := r.scopeField(q, q.body, "query")
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}

func (r *Rewriter) cmdAggregate(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	b, err := setField(q.body, "pipeline", func(old *value) (value, bool, error) {
		if old == nil {
			return value{}, false, badValue("aggregate requires a pipeline")
		}
		p, ok := old.ArrayOK()
		if !ok {
			return value{}, false, badValue("pipeline must be an array")
		}
		np, err := r.scopePipeline(q.t, p, true)
		return arrValue(np), true, err
	})
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}

// ---- writes --------------------------------------------------------------

// ensureTenant makes sure d carries the tenant field with the right value.
func (r *Rewriter) ensureTenant(t *Tenant, d doc) (doc, error) {
	elems, err := d.Elements()
	if err != nil {
		return nil, badValue("malformed document: %v", err)
	}
	found := false
	for _, e := range elems {
		if e.Key() != r.field {
			continue
		}
		if !e.Value().Equal(t.Value) {
			return nil, deny("document %s does not match the connection's tenant", r.field)
		}
		found = true
	}
	if found {
		return d, nil
	}
	out := make([]byte, 0, len(d)+len(r.field)+len(t.Value.Data)+3)
	out = append(out, d[:len(d)-1]...)
	out = bsoncore.AppendValueElement(out, r.field, t.Value)
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out, nil
}

func (r *Rewriter) cmdInsert(q *request) (*Result, error) {
	if err := noSeqs(q, "documents"); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	res := &Result{Body: q.body}
	var err error
	if _, ok := q.body.Lookup("documents").ArrayOK(); ok {
		res.Body, err = setField(q.body, "documents", func(old *value) (value, bool, error) {
			a, _ := old.ArrayOK()
			na, err := mapDocs(a, func(d doc) (doc, error) { return r.ensureTenant(q.t, d) })
			return arrValue(na), true, err
		})
		if err != nil {
			return nil, err
		}
	}
	for _, s := range q.seqs {
		ns := wire.Seq{ID: s.ID, Docs: make([]bsoncore.Document, len(s.Docs))}
		for i, d := range s.Docs {
			if ns.Docs[i], err = r.ensureTenant(q.t, d); err != nil {
				return nil, err
			}
		}
		res.Seqs = append(res.Seqs, ns)
	}
	return res, nil
}

func (r *Rewriter) rewriteStatements(q *request, key string, fn func(doc) (doc, error)) (*Result, error) {
	res := &Result{Body: q.body}
	var err error
	if _, ok := q.body.Lookup(key).ArrayOK(); ok {
		res.Body, err = setField(q.body, key, func(old *value) (value, bool, error) {
			a, _ := old.ArrayOK()
			na, err := mapDocs(a, fn)
			return arrValue(na), true, err
		})
		if err != nil {
			return nil, err
		}
	}
	for _, s := range q.seqs {
		ns := wire.Seq{ID: s.ID, Docs: make([]bsoncore.Document, len(s.Docs))}
		for i, d := range s.Docs {
			if ns.Docs[i], err = fn(d); err != nil {
				return nil, err
			}
		}
		res.Seqs = append(res.Seqs, ns)
	}
	return res, nil
}

func (r *Rewriter) cmdDelete(q *request) (*Result, error) {
	if err := noSeqs(q, "deletes"); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	return r.rewriteStatements(q, "deletes", func(d doc) (doc, error) {
		return r.scopeField(q, d, "q")
	})
}

func (r *Rewriter) cmdUpdate(q *request) (*Result, error) {
	if err := noSeqs(q, "updates"); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	return r.rewriteStatements(q, "updates", func(d doc) (doc, error) {
		return r.rewriteUpdateStmt(q.t, d)
	})
}

func (r *Rewriter) rewriteUpdateStmt(t *Tenant, d doc) (doc, error) {
	d, err := setField(d, "q", func(old *value) (value, bool, error) {
		v, err := r.scopeFilter(t, old)
		return v, true, err
	})
	if err != nil {
		return nil, err
	}
	return setField(d, "u", func(old *value) (value, bool, error) {
		if old == nil {
			return value{}, false, badValue("update statement requires u")
		}
		v, err := r.rewriteUpdateSpec(t, *old)
		return v, true, err
	})
}

var pipelineUpdateStages = map[string]struct{}{
	"$addFields": {}, "$set": {}, "$project": {}, "$unset": {}, "$replaceRoot": {}, "$replaceWith": {},
}

// rewriteUpdateSpec secures the "u" part of an update: operator updates may
// not touch the tenant field, replacements and pipelines are forced to
// carry it.
func (r *Rewriter) rewriteUpdateSpec(t *Tenant, u value) (value, error) {
	switch u.Type {
	case bsoncore.TypeArray:
		stages, err := u.Array().Values()
		if err != nil {
			return value{}, badValue("malformed update pipeline")
		}
		out := make([]value, 0, len(stages)+1)
		for _, s := range stages {
			sd, ok := s.DocumentOK()
			if !ok {
				return value{}, badValue("update pipeline stages must be documents")
			}
			e, err := sd.IndexErr(0)
			if err != nil || len(sd) != len(e)+5 {
				return value{}, badValue("each pipeline stage must have exactly one field")
			}
			if _, ok := pipelineUpdateStages[e.Key()]; !ok {
				return value{}, deny("pipeline update stage %s is not permitted", e.Key())
			}
			if !r.js {
				if err := scanForbidden(e.Value()); err != nil {
					return value{}, err
				}
			}
			out = append(out, s)
		}
		// Re-assert the tenant after whatever the pipeline did.
		out = append(out, docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$set", r.tenantDoc(t)))))
		return arrValue(arrayOf(out...)), nil

	case bsoncore.TypeEmbeddedDocument:
		d := u.Document()
		elems, err := d.Elements()
		if err != nil {
			return value{}, badValue("malformed update document")
		}
		if len(elems) > 0 && strings.HasPrefix(elems[0].Key(), "$") {
			for _, op := range elems {
				if !strings.HasPrefix(op.Key(), "$") {
					return value{}, badValue("cannot mix update operators and fields")
				}
				od, ok := op.Value().DocumentOK()
				if !ok {
					return value{}, badValue("%s requires a document", op.Key())
				}
				fields, err := od.Elements()
				if err != nil {
					return value{}, badValue("malformed update operator")
				}
				for _, f := range fields {
					if r.touchesTenant(f.Key()) {
						return value{}, deny("updating %q is not permitted", r.field)
					}
					if op.Key() == "$rename" {
						if to, ok := f.Value().StringValueOK(); ok && r.touchesTenant(to) {
							return value{}, deny("renaming onto %q is not permitted", r.field)
						}
					}
				}
			}
			return u, nil
		}
		for _, e := range elems {
			if strings.HasPrefix(e.Key(), "$") {
				return value{}, badValue("replacement document may not contain operator %q", e.Key())
			}
		}
		nd, err := r.ensureTenant(t, d)
		return docValue(nd), err
	}
	return value{}, badValue("update must be a document or pipeline")
}

func (r *Rewriter) touchesTenant(path string) bool {
	return path == r.field || strings.HasPrefix(path, r.field+".")
}

func (r *Rewriter) cmdFindAndModify(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	b, err := r.scopeField(q, q.body, "query")
	if err != nil {
		return nil, err
	}
	if q.body.Lookup("update").Type != 0 {
		b, err = setField(b, "update", func(old *value) (value, bool, error) {
			v, err := r.rewriteUpdateSpec(q.t, *old)
			return v, true, err
		})
		if err != nil {
			return nil, err
		}
	}
	return &Result{Body: b}, nil
}

// ---- collections & indexes ----------------------------------------------

func (r *Rewriter) cmdCreate(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	for _, k := range []string{"viewOn", "pipeline", "clone", "timeseries"} {
		if q.body.Lookup(k).Type != 0 {
			return nil, deny("create option %q is not permitted", k)
		}
	}
	return &Result{Body: q.body}, nil
}

// cmdDrop turns a collection drop into "delete all of this tenant's
// documents", because the physical collection is shared.
func (r *Rewriter) cmdDrop(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	coll, err := r.collection(q)
	if err != nil {
		return nil, err
	}
	del := buildDoc(
		valElem("q", docValue(r.tenantDoc(q.t))),
		bsoncore.AppendInt32Element(nil, "limit", 0),
	)
	out := make([]byte, 4, len(q.body)+64)
	out = bsoncore.AppendStringElement(out, "delete", coll)
	for _, e := range q.e[1:] {
		switch e.Key() {
		case "comment", "writeConcern", "lsid", "txnNumber", "$clusterTime", "$db", "$readPreference",
			"autocommit", "startTransaction", "readConcern", "apiVersion", "apiStrict", "apiDeprecationErrors", "$audit":
			out = append(out, e...)
		}
	}
	out = bsoncore.AppendArrayElement(out, "deletes", arrayOf(docValue(del)))
	body := finishDoc(out)
	ns := q.db + "." + coll
	return &Result{Body: body, Post: func(resp bsoncore.Document) bsoncore.Document {
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 || resp.Lookup("writeErrors").Type != 0 {
			return resp
		}
		out := make([]byte, 4, 128)
		out = bsoncore.AppendStringElement(out, "ns", ns)
		out = bsoncore.AppendInt32Element(out, "nIndexesWas", 1)
		if els, err := resp.Elements(); err == nil {
			for _, e := range els {
				if k := e.Key(); strings.HasPrefix(k, "$") || k == "operationTime" {
					out = append(out, e...)
				}
			}
		}
		out = bsoncore.AppendInt32Element(out, "ok", 1)
		return finishDoc(out)
	}}, nil
}

func (r *Rewriter) cmdListCollections(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	return &Result{Body: q.body}, nil
}

func (r *Rewriter) cmdListDatabases(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	return &Result{Body: q.body, Post: r.filterDatabases}, nil
}

// filterDatabases removes inaccessible databases and size information from a
// listDatabases reply.
func (r *Rewriter) filterDatabases(resp bsoncore.Document) bsoncore.Document {
	dbs, ok := resp.Lookup("databases").ArrayOK()
	if !ok {
		return resp
	}
	vals, _ := dbs.Values()
	var keep []value
	for _, v := range vals {
		d, ok := v.DocumentOK()
		if !ok {
			continue
		}
		name, _ := d.Lookup("name").StringValueOK()
		if !r.dbAllowed(name) {
			continue
		}
		keep = append(keep, docValue(buildDoc(
			bsoncore.AppendStringElement(nil, "name", name),
			bsoncore.AppendInt64Element(nil, "sizeOnDisk", 0),
			bsoncore.AppendBooleanElement(nil, "empty", false),
		)))
	}
	out := make([]byte, 4, 256)
	out = bsoncore.AppendArrayElement(out, "databases", arrayOf(keep...))
	out = bsoncore.AppendInt64Element(out, "totalSize", 0)
	out = bsoncore.AppendInt32Element(out, "ok", 1)
	return finishDoc(out)
}

var explainable = map[string]struct{}{
	"find": {}, "count": {}, "distinct": {}, "aggregate": {}, "update": {}, "delete": {}, "findAndModify": {},
}

func (r *Rewriter) cmdExplain(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	inner, ok := q.e[0].Value().DocumentOK()
	if !ok {
		return nil, badValue("explain requires a command document")
	}
	elems, err := inner.Elements()
	if err != nil || len(elems) == 0 {
		return nil, badValue("malformed explain command")
	}
	if err := checkNoDuplicateKeys(elems); err != nil {
		return nil, err
	}
	name := elems[0].Key()
	if a, ok := aliases[name]; ok {
		name = a
	}
	if _, ok := explainable[name]; !ok {
		return nil, deny("explain of %q is not permitted", name)
	}
	if _, denied := r.deny[name]; denied {
		return nil, deny("command %q is disabled", name)
	}
	res, err := r.cmds[name](r, &request{t: q.t, db: q.db, cmd: name, body: inner, e: elems})
	if err != nil {
		return nil, err
	}
	b, err := setField(q.body, "explain", func(*value) (value, bool, error) {
		return docValue(res.Body), true, nil
	})
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}

// indexKey prefixes an index key with the tenant field so that unique
// indexes are per-tenant and tenant-scoped queries can use every index.
func (r *Rewriter) indexKey(key doc) (doc, error) {
	elems, err := key.Elements()
	if err != nil || len(elems) == 0 {
		return nil, badValue("invalid index key")
	}
	if elems[0].Key() == r.field || (len(elems) == 1 && elems[0].Key() == "_id") {
		return key, nil
	}
	out := make([]byte, 4, len(key)+16)
	out = bsoncore.AppendInt32Element(out, r.field, 1)
	for _, e := range elems {
		if e.Key() == r.field {
			return nil, badValue("%q may only appear first in an index key", r.field)
		}
		out = append(out, e...)
	}
	return finishDoc(out), nil
}

func (r *Rewriter) cmdCreateIndexes(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	b, err := setField(q.body, "indexes", func(old *value) (value, bool, error) {
		if old == nil {
			return value{}, false, badValue("createIndexes requires indexes")
		}
		a, ok := old.ArrayOK()
		if !ok {
			return value{}, false, badValue("indexes must be an array")
		}
		na, err := mapDocs(a, func(spec doc) (doc, error) {
			if !r.js && spec.Lookup("partialFilterExpression").Type != 0 {
				if err := scanForbidden(spec.Lookup("partialFilterExpression")); err != nil {
					return nil, err
				}
			}
			// TTL indexes must be single-field, so they cannot carry the
			// tenant prefix; a unique TTL index would be global, so refuse it.
			if spec.Lookup("expireAfterSeconds").Type != 0 {
				if u, _ := spec.Lookup("unique").BooleanOK(); u {
					return nil, deny("unique TTL indexes cannot be tenant-scoped")
				}
				return spec, nil
			}
			return setField(spec, "key", func(old *value) (value, bool, error) {
				if old == nil {
					return value{}, false, badValue("index requires key")
				}
				kd, ok := old.DocumentOK()
				if !ok {
					return value{}, false, badValue("index key must be a document")
				}
				nk, err := r.indexKey(kd)
				return docValue(nk), true, err
			})
		})
		return arrValue(na), true, err
	})
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}

func (r *Rewriter) cmdDropIndexes(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	b, err := setField(q.body, "index", func(old *value) (value, bool, error) {
		if old == nil {
			return value{}, false, badValue("dropIndexes requires index")
		}
		switch old.Type {
		case bsoncore.TypeString:
			s := old.StringValue()
			if s == "*" {
				return value{}, false, deny("dropping all indexes would affect other tenants")
			}
			if s == "_id_" {
				return value{}, false, deny("the _id index cannot be dropped")
			}
			return *old, true, nil
		case bsoncore.TypeEmbeddedDocument:
			nk, err := r.indexKey(old.Document())
			return docValue(nk), true, err
		case bsoncore.TypeArray:
			return value{}, false, deny("dropping multiple indexes at once is not supported")
		}
		return value{}, false, badValue("index must be a name or key document")
	})
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}

func (r *Rewriter) cmdListIndexes(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	return &Result{Body: q.body, Post: r.unprefixIndexes}, nil
}

// unprefixIndexes hides the tenant prefix from listIndexes output so clients
// see the keys they originally asked for.
func (r *Rewriter) unprefixIndexes(resp bsoncore.Document) bsoncore.Document {
	cur, ok := resp.Lookup("cursor").DocumentOK()
	if !ok {
		return resp
	}
	batch, ok := cur.Lookup("firstBatch").ArrayOK()
	if !ok {
		return resp
	}
	nb, err := mapDocs(batch, func(spec doc) (doc, error) {
		key, ok := spec.Lookup("key").DocumentOK()
		if !ok {
			return spec, nil
		}
		els, err := key.Elements()
		if err != nil || len(els) < 2 || els[0].Key() != r.field {
			return spec, nil
		}
		out := make([]byte, 4, len(key))
		for _, e := range els[1:] {
			out = append(out, e...)
		}
		nk := finishDoc(out)
		return setField(spec, "key", func(*value) (value, bool, error) { return docValue(nk), true, nil })
	})
	if err != nil {
		return resp
	}
	ncur, err := setField(cur, "firstBatch", func(*value) (value, bool, error) { return arrValue(nb), true, nil })
	if err != nil {
		return resp
	}
	nr, err := setField(resp, "cursor", func(*value) (value, bool, error) { return docValue(ncur), true, nil })
	if err != nil {
		return resp
	}
	return nr
}
