package rewrite

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Upstream is what multi-step commands (dropDatabase, renameCollection,
// collMod, dbStats, currentOp, mapReduce output, atomic $out…) need from the
// proxy: a way to run commands on the tenant's upstream connection plus a few
// pieces of proxy state.
type Upstream interface {
	// Run executes a command and returns the reply, even when ok is 0.
	Run(db string, cmd bsoncore.Document) (bsoncore.Document, error)
	// Txn reports whether the upstream supports multi-document transactions.
	Txn() bool
	// TenantViews lists the names of the tenant's views in db.
	TenantViews(db string) ([]string, error)
	// DropTenantViews drops every view the tenant has in db.
	DropTenantViews(db string) error
	// OwnClients lists the "host:port" strings under which the upstream sees
	// this tenant's proxy connections (the "client" field of $currentOp).
	OwnClients() []string
}

// ValidatorsColl is the per-database registry of tenant collMod validators.
const ValidatorsColl = "__mtp_validators"

const validatorsColl = ValidatorsColl

// ---- small BSON builders -----------------------------------------------------

func bStr(k, v string) []byte       { return bsoncore.AppendStringElement(nil, k, v) }
func bI32(k string, v int32) []byte { return bsoncore.AppendInt32Element(nil, k, v) }
func bI64(k string, v int64) []byte { return bsoncore.AppendInt64Element(nil, k, v) }
func bBool(k string, v bool) []byte { return bsoncore.AppendBooleanElement(nil, k, v) }
func bDoc(k string, d doc) []byte   { return bsoncore.AppendDocumentElement(nil, k, d) }
func bArr(k string, a arr) []byte   { return bsoncore.AppendArrayElement(nil, k, a) }
func strVal(s string) value {
	return value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, s)}
}

func okDoc() doc { return buildDoc(bI32("ok", 1)) }

// replyError converts a failed server reply into an *Error.
func replyError(resp bsoncore.Document) error {
	code, _ := resp.Lookup("code").AsInt64OK()
	name, _ := resp.Lookup("codeName").StringValueOK()
	msg, _ := resp.Lookup("errmsg").StringValueOK()
	return &Error{Code: safeconv.Sat32(code), CodeName: name, Msg: msg}
}

func replyOKd(resp bsoncore.Document) bool {
	ok, _ := resp.Lookup("ok").AsInt64OK()
	if ok == 0 {
		if f, fok := resp.Lookup("ok").AsFloat64OK(); fok && f == 1 {
			return true
		}
	}
	return ok == 1
}

// run executes a command and turns a failed reply into an error.
func run(u Upstream, db string, cmd doc) (bsoncore.Document, error) {
	resp, err := u.Run(db, cmd)
	if err != nil {
		return nil, err
	}
	if !replyOKd(resp) {
		return nil, replyError(resp)
	}
	if err := writeError(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// writeError reports the first write error of a write command reply.
func writeError(resp bsoncore.Document) error {
	we, ok := resp.Lookup("writeErrors").ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := we.Values()
	if len(vals) == 0 {
		return nil
	}
	d, _ := vals[0].DocumentOK()
	code, _ := d.Lookup("code").AsInt64OK()
	msg, _ := d.Lookup("errmsg").StringValueOK()
	name := ""
	if code == 11000 {
		name = "DuplicateKey"
	}
	return &Error{Code: safeconv.Sat32(code), CodeName: name, Msg: msg}
}

// runIgnoring is run, but a failed reply with one of the codes counts as success.
func runIgnoring(u Upstream, db string, cmd doc, codes ...int64) (bsoncore.Document, error) {
	resp, err := u.Run(db, cmd)
	if err != nil {
		return nil, err
	}
	if !replyOKd(resp) {
		c, _ := resp.Lookup("code").AsInt64OK()
		for _, ig := range codes {
			if c == ig {
				return resp, nil
			}
		}
		return nil, replyError(resp)
	}
	if err := writeError(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (r *Rewriter) deleteTenantDocs(u bound, db, coll string) error {
	_, err := runIgnoring(u, db, buildDoc(
		bStr("delete", coll),
		bArr("deletes", arrayOf(docValue(buildDoc(bDoc("q", r.tenantDoc(u.t)), bI32("limit", 0)))))), 26)
	return err
}

// bound wraps an Upstream with the tenant a command runs for.
type bound struct {
	Upstream
	t *Tenant
}

// firstBatch returns the documents of a cursor reply (all of the first batch).
func firstBatch(resp bsoncore.Document) []doc {
	b, ok := resp.Lookup("cursor", "firstBatch").ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := b.Values()
	var out []doc
	for _, v := range vals {
		if d, ok := v.DocumentOK(); ok {
			out = append(out, d)
		}
	}
	return out
}

func internalColl(n string) bool {
	return strings.HasPrefix(n, "__mtp_") || strings.HasPrefix(n, "system.")
}

// listColls lists the plain (non-view, non-internal) collections of db.
func listColls(u Upstream, db string) ([]string, error) {
	resp, err := run(u, db, buildDoc(bI32("listCollections", 1), bBool("nameOnly", true),
		bDoc("filter", buildDoc(bStr("type", "collection")))))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range firstBatch(resp) {
		if n, _ := d.Lookup("name").StringValueOK(); n != "" && !internalColl(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

func collExists(u Upstream, db, coll string) (bool, error) {
	resp, err := run(u, db, buildDoc(bI32("listCollections", 1), bBool("nameOnly", true),
		bDoc("filter", buildDoc(bStr("name", coll), bStr("type", "collection")))))
	if err != nil {
		return false, err
	}
	return len(firstBatch(resp)) > 0, nil
}

// noTxn rejects commands sent inside a client transaction: the proxy runs them
// on its own session and cannot make them part of the client's.
func noTxn(q *request) error {
	for _, k := range []string{"txnNumber", "startTransaction", "autocommit"} {
		if q.body.Lookup(k).Type != 0 {
			return &Error{Code: 263, CodeName: "OperationNotSupportedInTransaction",
				Msg: "tenant proxy: " + q.cmd + " cannot run inside a transaction"}
		}
	}
	return nil
}

// withRun builds a Result whose reply is produced by fn.
func (r *Rewriter) withRun(q *request, fn func(b bound) (doc, error)) *Result {
	t := q.t
	return &Result{Run: func(u Upstream) (bsoncore.Document, error) { return fn(bound{u, t}) }}
}

// ---- dropDatabase --------------------------------------------------------------

// cmdDropDatabase deletes the tenant's documents in every collection of the
// database and removes the tenant's views and validators. The physical
// collections are shared, so they are never dropped.
func (r *Rewriter) cmdDropDatabase(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if err := noTxn(q); err != nil {
		return nil, err
	}
	db := q.db
	return r.withRun(q, func(b bound) (doc, error) {
		colls, err := listColls(b, db)
		if err != nil {
			return nil, err
		}
		for _, c := range colls {
			if err := r.deleteTenantDocs(b, db, c); err != nil {
				return nil, err
			}
		}
		if err := b.DropTenantViews(db); err != nil {
			return nil, err
		}
		if err := r.clearValidators(b, db); err != nil {
			return nil, err
		}
		return buildDoc(bStr("dropped", db), bI32("ok", 1)), nil
	}), nil
}

// ---- renameCollection -------------------------------------------------------------

func splitNS(ns string) (db, coll string, ok bool) {
	db, coll, ok = strings.Cut(ns, ".")
	return db, coll, ok && db != "" && coll != ""
}

// cmdRenameCollection renames the tenant's slice of a shared collection: its
// documents are copied into the target with $merge and then deleted from the
// source. The copy is not atomic with the delete; a failure in between leaves
// the documents in both collections, never in neither.
func (r *Rewriter) cmdRenameCollection(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if err := noTxn(q); err != nil {
		return nil, err
	}
	from, ok1 := q.e[0].Value().StringValueOK()
	to, ok2 := q.body.Lookup("to").StringValueOK()
	if !ok1 || !ok2 {
		return nil, badValue("renameCollection requires string namespaces")
	}
	fdb, fcoll, ok1 := splitNS(from)
	tdb, tcoll, ok2 := splitNS(to)
	if !ok1 || !ok2 {
		return nil, badValue("invalid namespace in renameCollection")
	}
	for _, d := range []string{fdb, tdb} {
		if !r.dbAllowed(d) {
			return nil, deny("database %q is not accessible", d)
		}
	}
	if err := checkCollName(fcoll); err != nil {
		return nil, err
	}
	if err := checkCollName(tcoll); err != nil {
		return nil, err
	}
	if from == to {
		return nil, badValue("cannot rename a collection to itself")
	}
	dropTarget := false
	switch v := q.body.Lookup("dropTarget"); v.Type {
	case 0:
	case bsoncore.TypeBoolean:
		dropTarget = v.Boolean()
	default:
		return nil, badValue("dropTarget must be a boolean")
	}
	return r.withRun(q, func(b bound) (doc, error) {
		for _, db := range []string{fdb, tdb} {
			views, err := b.TenantViews(db)
			if err != nil {
				return nil, err
			}
			for _, v := range views {
				if db == fdb && v == fcoll {
					return nil, &Error{Code: 166, CodeName: "CommandNotSupportedOnView", Msg: "tenant proxy: cannot rename a view"}
				}
				if db == tdb && v == tcoll {
					return nil, &Error{Code: 48, CodeName: "NamespaceExists", Msg: "target namespace exists"}
				}
			}
		}
		if ok, err := collExists(b, fdb, fcoll); err != nil {
			return nil, err
		} else if !ok {
			return nil, &Error{Code: 26, CodeName: "NamespaceNotFound", Msg: "source namespace does not exist"}
		}
		// Does the tenant already own documents in the target?
		resp, err := runIgnoring(b, tdb, buildDoc(bStr("find", tcoll), bDoc("filter", r.tenantDoc(b.t)),
			bI32("limit", 1), bBool("singleBatch", true)), 26)
		if err != nil {
			return nil, err
		}
		if len(firstBatch(resp)) > 0 {
			if !dropTarget {
				return nil, &Error{Code: 48, CodeName: "NamespaceExists", Msg: "target namespace exists"}
			}
			if err := r.deleteTenantDocs(b, tdb, tcoll); err != nil {
				return nil, err
			}
		}
		if err := r.copyIndexes(b, fdb, fcoll, tdb, tcoll); err != nil {
			return nil, err
		}
		un := r.uniqueIndex(tdb, tcoll, []string{r.field, "_id"})
		if _, err := runIgnoring(b, un.DB, un.Body, 68, 85, 86); err != nil {
			return nil, err
		}
		merge := buildDoc(
			bDoc("into", buildDoc(bStr("db", tdb), bStr("coll", tcoll))),
			bArr("on", arrayOf(strVal(r.field), strVal("_id"))),
			bStr("whenMatched", "fail"), bStr("whenNotMatched", "insert"))
		if _, err := run(b, fdb, buildDoc(bStr("aggregate", fcoll), bArr("pipeline", arrayOf(
			docValue(buildDoc(bDoc("$match", r.tenantDoc(b.t)))),
			docValue(buildDoc(bDoc("$merge", merge))))), bDoc("cursor", buildDoc()))); err != nil {
			return nil, err
		}
		if err := r.deleteTenantDocs(b, fdb, fcoll); err != nil {
			return nil, err
		}
		return okDoc(), nil
	}), nil
}

// copyIndexes recreates the source's secondary indexes on the target, except
// TTL indexes: a TTL index on the target would also expire other tenants'
// documents there.
func (r *Rewriter) copyIndexes(u Upstream, fdb, fcoll, tdb, tcoll string) error {
	resp, err := run(u, fdb, buildDoc(bStr("listIndexes", fcoll)))
	if err != nil {
		return err
	}
	var specs []value
	for _, d := range firstBatch(resp) {
		if n, _ := d.Lookup("name").StringValueOK(); n == "_id_" {
			continue
		}
		if d.Lookup("expireAfterSeconds").Type != 0 {
			continue
		}
		specs = append(specs, docValue(stripKeys(d, "v", "ns")))
	}
	if len(specs) == 0 {
		return nil
	}
	_, err = runIgnoring(u, tdb, buildDoc(bStr("createIndexes", tcoll), bArr("indexes", arrayOf(specs...))), 68, 85, 86)
	return err
}

func stripKeys(d doc, keys ...string) doc {
	els, err := d.Elements()
	if err != nil {
		return d
	}
	out := make([]byte, 4, len(d))
outer:
	for _, e := range els {
		for _, k := range keys {
			if e.Key() == k {
				continue outer
			}
		}
		out = append(out, e...)
	}
	return finishDoc(out)
}

// ---- collMod -----------------------------------------------------------------

var collModContext = map[string]struct{}{
	"collMod": {}, "$db": {}, "lsid": {}, "maxTimeMS": {}, "$clusterTime": {}, "comment": {}, "writeConcern": {},
	"$readPreference": {}, "apiVersion": {}, "apiStrict": {}, "apiDeprecationErrors": {}, "$audit": {},
}

var collModDenied = map[string]string{
	"index":                        "it changes a physical index shared with every other tenant (a TTL expiry change would delete their documents)",
	"expireAfterSeconds":           "a TTL setting applies to all tenants sharing the collection",
	"cappedSize":                   "capped sizes are a property of the shared collection",
	"cappedMax":                    "capped sizes are a property of the shared collection",
	"changeStreamPreAndPostImages": "pre/post images are managed by the proxy for change streams",
	"recordPreImages":              "pre-images are managed by the proxy for change streams",
	"timeseries":                   "time-series options apply to the whole shared collection",
	"viewOn":                       "viewOn only applies to views",
	"pipeline":                     "pipeline only applies to views",
	"validationLevel":              "the validation level is global to the shared collection and cannot be set per tenant (only \"strict\", the default, is accepted)",
	"validationAction":             "the validation action is global to the shared collection and cannot be set per tenant (only \"error\", the default, is accepted)",
	"prepareUnique":                "it changes a physical index shared with every other tenant",
	"unique":                       "it changes a physical index shared with every other tenant",
	"dryRun":                       "it changes a physical index shared with every other tenant",
}

// cmdCollMod supports `validator` on a collection (confined to the tenant's
// documents). Everything else is a property of the shared physical collection
// and is refused with an explanation.
func (r *Rewriter) cmdCollMod(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if err := noTxn(q); err != nil {
		return nil, err
	}
	coll, err := r.collection(q)
	if err != nil {
		return nil, err
	}
	var validator *doc
	for _, e := range q.e {
		k := e.Key()
		if _, ok := collModContext[k]; ok {
			continue
		}
		switch k {
		case "validator":
			d, ok := e.Value().DocumentOK()
			if !ok {
				return nil, badValue("validator must be a document")
			}
			if err := r.scan(e.Value()); err != nil {
				return nil, err
			}
			validator = &d
			continue
		case "validationLevel":
			if s, _ := e.Value().StringValueOK(); s == "strict" {
				continue
			}
		case "validationAction":
			if s, _ := e.Value().StringValueOK(); s == "error" {
				continue
			}
		}
		why, known := collModDenied[k]
		if !known {
			why = "it is not supported on a collection shared between tenants"
		}
		return nil, deny("collMod option %q is not permitted: %s", k, why)
	}
	db := q.db
	return r.withRun(q, func(b bound) (doc, error) {
		if validator != nil {
			if err := r.setValidator(b, db, coll, *validator); err != nil {
				return nil, err
			}
		}
		return okDoc(), nil
	}), nil
}

func validatorID(t *Tenant, coll string) string {
	h := sha256.Sum256([]byte(t.ID))
	return hex.EncodeToString(h[:6]) + "." + coll
}

// setValidator stores the tenant's validator and recomputes the collection's
// effective validator. Each tenant's validator only constrains that tenant's
// documents: {$or: [{tenantId: {$ne: T}}, <validator>]}, ANDed together.
func (r *Rewriter) setValidator(u bound, db, coll string, v doc) error {
	id := validatorID(u.t, coll)
	resp, err := runIgnoring(u, db, buildDoc(bStr("find", validatorsColl), bDoc("filter", buildDoc(bStr("coll", coll))),
		bI32("batchSize", 100000), bBool("singleBatch", true)), 26)
	if err != nil {
		return err
	}
	type row struct {
		tenant value
		v      doc
	}
	var rows []row
	for _, d := range firstBatch(resp) {
		if rid, _ := d.Lookup("_id").StringValueOK(); rid == id {
			continue
		}
		vd, ok := d.Lookup("validator").DocumentOK()
		if !ok {
			continue
		}
		rows = append(rows, row{d.Lookup(r.field), vd})
	}
	if len(v) > 5 {
		rows = append(rows, row{u.t.Value, v})
	}
	parts := make([]value, 0, len(rows))
	for _, rw := range rows {
		ne := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, r.field, buildDoc(valElem("$ne", rw.tenant)))))
		parts = append(parts, docValue(buildDoc(bArr("$or", arrayOf(ne, docValue(rw.v))))))
	}
	combined := buildDoc()
	if len(parts) > 0 {
		combined = buildDoc(bArr("$and", arrayOf(parts...)))
	}
	if _, err := run(u, db, buildDoc(bStr("collMod", coll), bDoc("validator", combined))); err != nil {
		return err
	}
	if len(v) > 5 {
		row := buildDoc(bStr("_id", id), valElem(r.field, u.t.Value), bStr("coll", coll), bDoc("validator", v))
		_, err = run(u, db, buildDoc(bStr("update", validatorsColl), bArr("updates", arrayOf(docValue(buildDoc(
			bDoc("q", buildDoc(bStr("_id", id))), bDoc("u", row), bBool("upsert", true)))))))
		return err
	}
	_, err = runIgnoring(u, db, buildDoc(bStr("delete", validatorsColl), bArr("deletes", arrayOf(docValue(buildDoc(
		bDoc("q", buildDoc(bStr("_id", id))), bI32("limit", 1)))))), 26)
	return err
}

// clearValidators removes all of the tenant's validators in db and recomputes
// the affected collections.
func (r *Rewriter) clearValidators(u bound, db string) error {
	resp, err := runIgnoring(u, db, buildDoc(bStr("find", validatorsColl), bDoc("filter", r.tenantDoc(u.t)),
		bI32("batchSize", 100000), bBool("singleBatch", true)), 26)
	if err != nil {
		return err
	}
	for _, d := range firstBatch(resp) {
		coll, _ := d.Lookup("coll").StringValueOK()
		if coll == "" {
			continue
		}
		// collMod fails if the collection is gone; the row is stale then.
		if err := r.setValidator(u, db, coll, buildDoc()); err != nil {
			var e *Error
			if asErr(err, &e) && (e.Code == 26) {
				continue
			}
			return err
		}
	}
	return nil
}

func asErr(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

// ---- stats ------------------------------------------------------------------

type collStats struct {
	count, size, storage, nindexes, indexSize int64
	indexSizes                                []bsoncore.Element
}

func numOf(v value) int64 {
	if n, ok := v.AsInt64OK(); ok {
		return n
	}
	if f, ok := v.AsFloat64OK(); ok {
		return int64(f)
	}
	return 0
}

// tenantCollStats estimates the tenant's share of a collection. count and
// size are exact (a scan of the tenant's documents); storage and index sizes
// are the collection's totals scaled by the tenant's share of the data.
func (r *Rewriter) tenantCollStats(u bound, db, coll string) (*collStats, error) {
	size := buildDoc(bDoc("$sum", buildDoc(bStr("$bsonSize", "$$ROOT"))))
	grp := buildDoc(bsoncore.AppendNullElement(nil, "_id"), bDoc("n", buildDoc(bI32("$sum", 1))), bDoc("size", size))
	resp, err := runIgnoring(u, db, buildDoc(bStr("aggregate", coll), bArr("pipeline", arrayOf(
		docValue(buildDoc(bDoc("$match", r.tenantDoc(u.t)))),
		docValue(buildDoc(bDoc("$group", grp))))), bDoc("cursor", buildDoc())), 26)
	if err != nil {
		return nil, err
	}
	st := &collStats{}
	rows := firstBatch(resp)
	if len(rows) == 0 {
		return st, nil
	}
	st.count, st.size = numOf(rows[0].Lookup("n")), numOf(rows[0].Lookup("size"))
	cs, err := runIgnoring(u, db, buildDoc(bStr("aggregate", coll), bArr("pipeline", arrayOf(
		docValue(buildDoc(bDoc("$collStats", buildDoc(bDoc("storageStats", buildDoc())))))),
	), bDoc("cursor", buildDoc())), 26, 166)
	if err != nil {
		return nil, err
	}
	if cr := firstBatch(cs); len(cr) > 0 {
		ss := cr[0].Lookup("storageStats")
		if sd, ok := ss.DocumentOK(); ok {
			rsize, rcount := numOf(sd.Lookup("size")), numOf(sd.Lookup("count"))
			share := func(total int64, num, den int64) int64 {
				if den <= 0 || num >= den {
					return total
				}
				return total * num / den
			}
			st.storage = share(numOf(sd.Lookup("storageSize")), st.size, rsize)
			st.nindexes = numOf(sd.Lookup("nindexes"))
			st.indexSize = share(numOf(sd.Lookup("totalIndexSize")), st.count, rcount)
			if is, ok := sd.Lookup("indexSizes").DocumentOK(); ok {
				els, _ := is.Elements()
				for _, e := range els {
					st.indexSizes = append(st.indexSizes, bI64(e.Key(), share(numOf(e.Value()), st.count, rcount)))
				}
			}
		}
	}
	return st, nil
}

func scaleOf(q *request) (int64, error) {
	v := q.body.Lookup("scale")
	if v.Type == 0 {
		return 1, nil
	}
	n := numOf(v)
	if n < 1 {
		return 0, badValue("scale must be a positive number")
	}
	return n, nil
}

// cmdDbStats computes tenant-scoped database statistics. Counts and data
// sizes are exact for the tenant's documents; storage and index sizes are
// estimates (see tenantCollStats). A collection counts if the tenant has at
// least one document in it. Cost: one scan of the tenant's documents per
// collection.
func (r *Rewriter) cmdDbStats(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	scale, err := scaleOf(q)
	if err != nil {
		return nil, err
	}
	db := q.db
	return r.withRun(q, func(b bound) (doc, error) {
		colls, err := listColls(b, db)
		if err != nil {
			return nil, err
		}
		views, err := b.TenantViews(db)
		if err != nil {
			return nil, err
		}
		var n, objs, dataSize, storage, idx, idxSize int64
		for _, c := range colls {
			st, err := r.tenantCollStats(b, db, c)
			if err != nil {
				return nil, err
			}
			if st.count == 0 {
				continue
			}
			n++
			objs += st.count
			dataSize += st.size
			storage += st.storage
			idx += st.nindexes
			idxSize += st.indexSize
		}
		avg := float64(0)
		if objs > 0 {
			avg = float64(dataSize) / float64(objs)
		}
		return buildDoc(
			bStr("db", db), bI32("collections", safeconv.Sat32(n)), bI32("views", safeconv.Sat32(len(views))),
			bI64("objects", objs), bsoncore.AppendDoubleElement(nil, "avgObjSize", avg),
			bsoncore.AppendDoubleElement(nil, "dataSize", float64(dataSize)/float64(scale)),
			bsoncore.AppendDoubleElement(nil, "storageSize", float64(storage)/float64(scale)),
			bI32("indexes", int32(idx)),
			bsoncore.AppendDoubleElement(nil, "indexSize", float64(idxSize)/float64(scale)),
			bsoncore.AppendDoubleElement(nil, "totalSize", float64(storage+idxSize)/float64(scale)),
			bI64("scaleFactor", scale), bBool("tenantScoped", true), bI32("ok", 1)), nil
	}), nil
}

func (r *Rewriter) cmdCollStats(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	coll, err := r.collection(q)
	if err != nil {
		return nil, err
	}
	scale, err := scaleOf(q)
	if err != nil {
		return nil, err
	}
	db := q.db
	return r.withRun(q, func(b bound) (doc, error) {
		if err := r.notView(b, db, coll); err != nil {
			return nil, err
		}
		st, err := r.tenantCollStats(b, db, coll)
		if err != nil {
			return nil, err
		}
		sc := func(n int64) int64 { return n / scale }
		avg := int64(0)
		if st.count > 0 {
			avg = st.size / st.count
		}
		isz := make([]byte, 4)
		for _, e := range st.indexSizes {
			v := bsoncore.Element(e).Value()
			isz = bI64Append(isz, bsoncore.Element(e).Key(), sc(numOf(v)))
		}
		return buildDoc(
			bStr("ns", db+"."+coll), bI64("size", sc(st.size)), bI64("count", st.count),
			bI64("avgObjSize", avg), bI64("storageSize", sc(st.storage)),
			bI32("nindexes", safeconv.Sat32(st.nindexes)), bI64("totalIndexSize", sc(st.indexSize)),
			bDoc("indexSizes", finishDoc(isz)),
			bI64("scaleFactor", scale), bBool("tenantScoped", true), bI32("ok", 1)), nil
	}), nil
}

func bI64Append(b []byte, k string, v int64) []byte { return bsoncore.AppendInt64Element(b, k, v) }

func (r *Rewriter) notView(u bound, db, coll string) error {
	views, err := u.TenantViews(db)
	if err != nil {
		return err
	}
	for _, v := range views {
		if v == coll {
			return &Error{Code: 166, CodeName: "CommandNotSupportedOnView", Msg: "tenant proxy: not supported on views"}
		}
	}
	return nil
}

// cmdValidate is refused: it scans (and locks) the entire shared collection
// and reports index key counts that include other tenants' documents.
func (r *Rewriter) cmdValidate(q *request) (*Result, error) {
	return nil, deny("validate is not permitted: it scans and locks the whole shared collection and reports counts of every tenant's documents")
}

// statsStage handles an aggregate whose first stage is $collStats. The output
// is one synthesized document for the tenant, fed through $documents into the
// rest of the (tenant-scoped) pipeline.
func (r *Rewriter) statsStage(q *request, stages []value) (*Result, error) {
	if err := noTxn(q); err != nil {
		return nil, err
	}
	coll, err := r.collection(q)
	if err != nil {
		return nil, err
	}
	spec, ok := stages[0].Document().Lookup("$collStats").DocumentOK()
	if !ok {
		return nil, badValue("$collStats requires a document")
	}
	wantCount, wantStorage := false, false
	scale := int64(1)
	els, err := spec.Elements()
	if err != nil {
		return nil, badValue("malformed $collStats")
	}
	for _, e := range els {
		switch e.Key() {
		case "count":
			wantCount = true
		case "storageStats":
			wantStorage = true
			if sd, ok := e.Value().DocumentOK(); ok {
				if s := sd.Lookup("scale"); s.Type != 0 {
					if scale = numOf(s); scale < 1 {
						return nil, badValue("scale must be a positive number")
					}
				}
			}
		case "latencyStats", "queryExecStats":
			return nil, deny("$collStats.%s reports usage of the whole shared collection and is not permitted", e.Key())
		default:
			return nil, badValue("unknown $collStats option %q", e.Key())
		}
	}
	rest, err := r.scopePipeline(q.t, arrayOf(stages[1:]...), false, nil)
	if err != nil {
		return nil, err
	}
	db := q.db
	restVals, _ := rest.Values()
	return r.withRun(q, func(b bound) (doc, error) {
		if err := r.notView(b, db, coll); err != nil {
			return nil, err
		}
		st, err := r.tenantCollStats(b, db, coll)
		if err != nil {
			return nil, err
		}
		sc := func(n int64) int64 { return n / scale }
		out := buildDoc(bStr("ns", db+"."+coll), bStr("host", "mongodb-tenant-proxy"),
			bsoncore.AppendDateTimeElement(nil, "localTime", time.Now().UnixMilli()))
		if wantStorage {
			avg := int64(0)
			if st.count > 0 {
				avg = st.size / st.count
			}
			out = appendRaw(out, bDoc("storageStats", buildDoc(
				bI64("size", sc(st.size)), bI64("count", st.count), bI64("avgObjSize", avg),
				bI64("storageSize", sc(st.storage)), bI32("nindexes", safeconv.Sat32(st.nindexes)),
				bI64("totalIndexSize", sc(st.indexSize)), bI64("scaleFactor", scale), bBool("tenantScoped", true))))
		}
		if wantCount {
			out = appendRaw(out, bI64("count", st.count))
		}
		pipe := append([]value{docValue(buildDoc(bArr("$documents", arrayOf(docValue(out)))))}, restVals...)
		return run(b, db, buildDoc(bI32("aggregate", 1), bArr("pipeline", arrayOf(pipe...)), bDoc("cursor", buildDoc())))
	}), nil
}

func appendRaw(d doc, elem []byte) doc {
	out := make([]byte, 0, len(d)+len(elem))
	out = append(out, d[:len(d)-1]...)
	out = append(out, elem...)
	out = append(out, 0)
	return finishDocFull(out)
}

func finishDocFull(b []byte) doc {
	n := len(b)
	safeconv.PutLen(b, n)
	return b
}

// ---- currentOp / killOp -------------------------------------------------------------

// ownOps returns an aggregate on admin listing only the operations running on
// the tenant's own upstream connections. $currentOp reports the upstream peer
// of each operation, and every client connection owns a dedicated upstream
// connection, so that is an exact attribution.
func (r *Rewriter) ownOpsMatch(clients []string) doc {
	vals := make([]value, len(clients))
	for i, c := range clients {
		vals[i] = strVal(c)
	}
	return buildDoc(bDoc("client", buildDoc(bArr("$in", arrayOf(vals...)))))
}

func (r *Rewriter) currentOps(u bound, idle bool, extra ...value) ([]doc, error) {
	clients := u.OwnClients()
	if len(clients) == 0 {
		return nil, nil
	}
	pipe := []value{
		docValue(buildDoc(bDoc("$currentOp", buildDoc(bBool("allUsers", true), bBool("idleConnections", idle),
			bBool("idleCursors", idle))))),
		docValue(buildDoc(bDoc("$match", r.ownOpsMatch(clients)))),
	}
	pipe = append(pipe, extra...)
	resp, err := run(u, "admin", buildDoc(bI32("aggregate", 1), bArr("pipeline", arrayOf(pipe...)),
		bDoc("cursor", buildDoc(bI32("batchSize", 100000)))))
	if err != nil {
		return nil, err
	}
	return firstBatch(resp), nil
}

var currentOpControl = map[string]struct{}{
	"currentOp": {}, "maxTimeMS": {}, "$ownOps": {}, "$all": {}, "$db": {}, "lsid": {}, "$clusterTime": {}, "comment": {},
	"$readPreference": {}, "apiVersion": {}, "apiStrict": {}, "apiDeprecationErrors": {}, "$audit": {},
	"readConcern": {}, "writeConcern": {},
}

// cmdCurrentOp lists the tenant's own operations. The command's extra fields
// are a filter, as with a real currentOp.
func (r *Rewriter) cmdCurrentOp(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	all, _ := q.body.Lookup("$all").BooleanOK()
	filter := make([]byte, 4)
	for _, e := range q.e[1:] {
		if _, ok := currentOpControl[e.Key()]; ok {
			continue
		}
		filter = append(filter, e...)
	}
	f := finishDoc(filter)
	if err := r.scan(docValue(f)); err != nil {
		return nil, err
	}
	var extra []value
	if len(f) > 5 {
		extra = append(extra, docValue(buildDoc(bDoc("$match", f))))
	}
	return r.withRun(q, func(b bound) (doc, error) {
		ops, err := r.currentOps(b, all, extra...)
		if err != nil {
			return nil, err
		}
		vals := make([]value, len(ops))
		for i, o := range ops {
			vals[i] = docValue(o)
		}
		return buildDoc(bArr("inprog", arrayOf(vals...)), bI32("ok", 1)), nil
	}), nil
}

// currentOpAggregate handles `aggregate: 1` on admin whose first stage is $currentOp.
func (r *Rewriter) currentOpAggregate(q *request, stages []value) (*Result, error) {
	if err := noTxn(q); err != nil {
		return nil, err
	}
	spec, ok := stages[0].Document().Lookup("$currentOp").DocumentOK()
	if !ok {
		return nil, badValue("$currentOp requires a document")
	}
	idle := false
	els, err := spec.Elements()
	if err != nil {
		return nil, badValue("malformed $currentOp")
	}
	for _, e := range els {
		switch e.Key() {
		case "idleConnections":
			idle, _ = e.Value().BooleanOK()
		case "allUsers", "localOps", "idleSessions", "idleCursors", "truncateOps",
			"backtrace":
		default:
			return nil, badValue("unknown $currentOp option %q", e.Key())
		}
	}
	rest, err := r.scopePipeline(q.t, arrayOf(stages[1:]...), false, nil)
	if err != nil {
		return nil, err
	}
	restVals, _ := rest.Values()
	return r.withRun(q, func(b bound) (doc, error) {
		clients := b.OwnClients()
		pipe := []value{
			docValue(buildDoc(bDoc("$currentOp", buildDoc(bBool("allUsers", true), bBool("idleConnections", idle))))),
			docValue(buildDoc(bDoc("$match", r.ownOpsMatch(clients)))),
		}
		pipe = append(pipe, restVals...)
		return run(b, "admin", buildDoc(bI32("aggregate", 1), bArr("pipeline", arrayOf(pipe...)),
			bDoc("cursor", buildDoc(bI32("batchSize", 100000)))))
	}), nil
}

// cmdKillOp kills one of the tenant's own operations. Operations of other
// tenants are reported exactly like an unknown opid, so nothing leaks.
func (r *Rewriter) cmdKillOp(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	opv := q.body.Lookup("op")
	if opv.Type != bsoncore.TypeInt32 && opv.Type != bsoncore.TypeInt64 && opv.Type != bsoncore.TypeDouble {
		return nil, badValue("killOp requires a numeric op")
	}
	op := numOf(opv)
	return r.withRun(q, func(b bound) (doc, error) {
		match := docValue(buildDoc(bDoc("$match", buildDoc(bI64("opid", op)))))
		ops, err := r.currentOps(b, true, match)
		if err != nil {
			return nil, err
		}
		info := "attempting to kill op"
		if len(ops) > 0 {
			if _, err := run(b, "admin", buildDoc(bI32("killOp", 1), bI64("op", op))); err != nil {
				return nil, err
			}
		}
		return buildDoc(bStr("info", info), bI32("ok", 1)), nil
	}), nil
}

// cmdServerStatus synthesizes the harmless, tenant-independent subset of
// serverStatus. Real counters aggregate every tenant's activity.
func (r *Rewriter) cmdServerStatus(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	return r.withRun(q, func(b bound) (doc, error) {
		version := ""
		if bi, err := run(b, "admin", buildDoc(bI32("buildInfo", 1))); err == nil {
			version, _ = bi.Lookup("version").StringValueOK()
		}
		up := time.Since(r.started)
		return buildDoc(
			bStr("host", "mongodb-tenant-proxy"), bStr("version", version), bStr("process", "mongos"),
			bI64("uptime", int64(up.Seconds())), bI64("uptimeMillis", up.Milliseconds()),
			bsoncore.AppendDateTimeElement(nil, "localTime", time.Now().UnixMilli()),
			bDoc("connections", buildDoc(bI32("current", safeconv.Sat32(len(b.OwnClients()))))),
			bI32("ok", 1)), nil
	}), nil
}
