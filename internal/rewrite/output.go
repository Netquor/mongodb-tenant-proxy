package rewrite

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Command is a housekeeping command the proxy runs itself.
type Command struct {
	DB   string
	Body bsoncore.Document
	// CacheKey, when set, lets the proxy skip the command once it has
	// succeeded (used for idempotent index creation).
	CacheKey string
	// IgnoreCodes are server error codes that count as success.
	IgnoreCodes []int32
	// Func, when set, is run instead of Body (After steps that need several
	// commands, such as the transactional $out swap).
	Func func(Upstream) error
}

type extras struct {
	db            string
	dbLevel       bool
	before, after []Command
}

const outMarker = "__mtp_out"

// rewriteWrite turns $merge/$out into a tenant-confined $merge.
//
// The target collection is shared by all tenants, so writes are matched on
// (tenantId, <on fields>) backed by a unique index with that exact key, which
// means a tenant can never overwrite another tenant's document. Documents are
// stamped with the tenant immediately before the write.
func (r *Rewriter) rewriteWrite(t *Tenant, stage string, spec value, ex *extras) ([]value, error) {
	stamp := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$set", r.tenantDoc(t))))
	if stage == "$out" {
		return r.rewriteOut(t, spec, ex, stamp)
	}

	var (
		into        value
		onFields    = []string{"_id"}
		whenMatched value
		hasMatched  bool
		whenNot     = "insert"
		let         *value
	)
	switch spec.Type {
	case bsoncore.TypeString:
		into = spec
	case bsoncore.TypeEmbeddedDocument:
		els, err := spec.Document().Elements()
		if err != nil {
			return nil, badValue("malformed $merge")
		}
		if err := checkNoDuplicateKeys(els); err != nil {
			return nil, err
		}
		for _, e := range els {
			v := e.Value()
			switch e.Key() {
			case "into":
				into = v
			case "on":
				onFields = nil
				if s, ok := v.StringValueOK(); ok {
					onFields = []string{s}
				} else if a, ok := v.ArrayOK(); ok {
					vals, _ := a.Values()
					for _, x := range vals {
						s, ok := x.StringValueOK()
						if !ok {
							return nil, badValue("$merge on must contain field names")
						}
						onFields = append(onFields, s)
					}
				} else {
					return nil, badValue("$merge on must be a string or array")
				}
			case "let":
				lv := v
				if err := r.scan(lv); err != nil {
					return nil, err
				}
				let = &lv
			case "whenMatched":
				whenMatched, hasMatched = v, true
			case "whenNotMatched":
				whenNot, _ = v.StringValueOK()
			default:
				return nil, badValue("unknown $merge option %q", e.Key())
			}
		}
	default:
		return nil, badValue("$merge requires a collection or document")
	}
	db, coll, err := r.target(ex.db, into)
	if err != nil {
		return nil, err
	}
	// "on" always includes the tenant field so matching stays inside the tenant.
	on := []string{r.field}
	for _, f := range onFields {
		if f == r.field {
			continue
		}
		on = append(on, f)
	}
	ex.before = append(ex.before, r.uniqueIndex(db, coll, on))

	out := make([]byte, 4, 128)
	out = bsoncore.AppendDocumentElement(out, "into", buildDoc(
		bsoncore.AppendStringElement(nil, "db", db), bsoncore.AppendStringElement(nil, "coll", coll)))
	vals := make([]value, len(on))
	for i, f := range on {
		vals[i] = value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, f)}
	}
	out = bsoncore.AppendArrayElement(out, "on", arrayOf(vals...))
	if let != nil {
		out = bsoncore.AppendValueElement(out, "let", *let)
	}
	if hasMatched {
		wm, err := r.mergeMatched(t, whenMatched)
		if err != nil {
			return nil, err
		}
		out = bsoncore.AppendValueElement(out, "whenMatched", wm)
	}
	out = bsoncore.AppendStringElement(out, "whenNotMatched", whenNot)
	merge := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$merge", finishDoc(out))))
	return []value{stamp, merge}, nil
}

// mergeMatched validates whenMatched. A pipeline form may not move the
// document to another tenant, so the tenant is re-asserted at its end.
func (r *Rewriter) mergeMatched(t *Tenant, v value) (value, error) {
	if s, ok := v.StringValueOK(); ok {
		switch s {
		case "replace", "keepExisting", "merge", "fail":
			return v, nil
		}
		return value{}, badValue("invalid whenMatched %q", s)
	}
	if v.Type != bsoncore.TypeArray {
		return value{}, badValue("whenMatched must be a string or pipeline")
	}
	// Same stage rules as pipeline-style updates.
	res, err := r.rewriteUpdateSpec(t, v)
	return res, err
}

func (r *Rewriter) rewriteOut(t *Tenant, spec value, ex *extras, stamp value) ([]value, error) {
	var tgt value
	switch spec.Type {
	case bsoncore.TypeString:
		tgt = spec
	case bsoncore.TypeEmbeddedDocument:
		if spec.Document().Lookup("timeseries").Type != 0 {
			return nil, deny("$out with timeseries is not supported")
		}
		tgt = spec
	default:
		return nil, badValue("$out requires a collection or document")
	}
	db, coll, err := r.target(ex.db, tgt)
	if err != nil {
		return nil, err
	}
	ex.before = append(ex.before, r.uniqueIndex(db, coll, []string{r.field, "_id"}))
	if r.atomicOut != nil && r.atomicOut() {
		return r.rewriteAtomicOut(t, db, coll, ex, stamp), nil
	}

	// $out replaces the whole collection; on a shared collection that means
	// "replace this tenant's documents". Stamp a run marker, merge, then
	// remove the tenant's documents that were not part of this run.
	var rb [8]byte
	rand.Read(rb[:])
	run := hex.EncodeToString(rb[:])
	marker := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$set",
		buildDoc(bsoncore.AppendStringElement(nil, outMarker, run)))))
	merge := buildDoc(
		bsoncore.AppendDocumentElement(nil, "into", buildDoc(
			bsoncore.AppendStringElement(nil, "db", db), bsoncore.AppendStringElement(nil, "coll", coll))),
		bsoncore.AppendArrayElement(nil, "on", arrayOf(
			value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, r.field)},
			value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "_id")})),
		bsoncore.AppendStringElement(nil, "whenMatched", "replace"),
		bsoncore.AppendStringElement(nil, "whenNotMatched", "insert"),
	)
	stale := buildDoc(
		valElem(r.field, t.Value),
		bsoncore.AppendDocumentElement(nil, outMarker, buildDoc(bsoncore.AppendStringElement(nil, "$ne", run))))
	ex.after = append(ex.after,
		Command{DB: db, Body: buildDoc(
			bsoncore.AppendStringElement(nil, "delete", coll),
			bsoncore.AppendArrayElement(nil, "deletes", arrayOf(docValue(buildDoc(
				bsoncore.AppendDocumentElement(nil, "q", stale),
				bsoncore.AppendInt32Element(nil, "limit", 0))))))},
		Command{DB: db, Body: buildDoc(
			bsoncore.AppendStringElement(nil, "update", coll),
			bsoncore.AppendArrayElement(nil, "updates", arrayOf(docValue(buildDoc(
				bsoncore.AppendDocumentElement(nil, "q", r.tenantDoc(t)),
				bsoncore.AppendDocumentElement(nil, "u", buildDoc(bsoncore.AppendDocumentElement(nil, "$unset",
					buildDoc(bsoncore.AppendStringElement(nil, outMarker, ""))))),
				bsoncore.AppendBooleanElement(nil, "multi", true))))))},
	)
	return []value{stamp, marker, docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$merge", merge)))}, nil
}

// target resolves the db and collection of an output spec.
func (r *Rewriter) target(curDB string, v value) (db, coll string, err error) {
	db = curDB
	switch v.Type {
	case bsoncore.TypeString:
		coll = v.StringValue()
	case bsoncore.TypeEmbeddedDocument:
		d := v.Document()
		c, ok := d.Lookup("coll").StringValueOK()
		if !ok {
			return "", "", badValue("output target requires coll")
		}
		coll = c
		if x, ok := d.Lookup("db").StringValueOK(); ok {
			db = x
		}
	default:
		return "", "", badValue("invalid output target")
	}
	if err := checkCollName(coll); err != nil {
		return "", "", err
	}
	if !r.dbAllowed(db) {
		return "", "", deny("database %q is not accessible", db)
	}
	return db, coll, nil
}

func (r *Rewriter) uniqueIndex(db, coll string, keys []string) Command {
	key := make([]byte, 4)
	for _, k := range keys {
		key = bsoncore.AppendInt32Element(key, k, 1)
	}
	name := "mtp_" + strings.ReplaceAll(strings.Join(keys, "_"), ".", "_")
	spec := buildDoc(
		bsoncore.AppendDocumentElement(nil, "key", finishDoc(key)),
		bsoncore.AppendStringElement(nil, "name", name),
		bsoncore.AppendBooleanElement(nil, "unique", true))
	return Command{
		DB: db,
		Body: buildDoc(
			bsoncore.AppendStringElement(nil, "createIndexes", coll),
			bsoncore.AppendArrayElement(nil, "indexes", arrayOf(docValue(spec)))),
		CacheKey:    db + "." + coll + "#" + name,
		IgnoreCodes: []int32{68, 85, 86}, // already exists / name or spec conflict: an equivalent index is there
	}
}

// ---- mapReduce -------------------------------------------------------------

// cmdMapReduce supports mapReduce with inline output or output to a
// collection (replace, merge or reduce). The functions run inside mongod over
// the tenant's documents only. Collection output is staged in a private
// collection and then installed into the shared target for the tenant, so
// "replace" only replaces the tenant's results and every result document
// carries the tenant field.
func (r *Rewriter) cmdMapReduce(q *request) (*Result, error) {
	if err := noSeqs(q); err != nil {
		return nil, err
	}
	if _, err := r.collection(q); err != nil {
		return nil, err
	}
	if !r.js {
		return nil, deny("mapReduce runs server-side JavaScript, which is disabled")
	}
	b, err := r.scopeField(q, q.body, "query")
	if err != nil {
		return nil, err
	}
	outV := q.body.Lookup("out")
	if od, ok := outV.DocumentOK(); ok && od.Lookup("inline").Type != 0 {
		return &Result{Body: b}, nil
	}

	mode, target := modeReplace, value{}
	switch outV.Type {
	case bsoncore.TypeString:
		target = docValue(buildDoc(bsoncore.AppendStringElement(nil, "coll", outV.StringValue())))
	case bsoncore.TypeEmbeddedDocument:
		od := outV.Document()
		els, err := od.Elements()
		if err != nil || len(els) == 0 {
			return nil, badValue("malformed mapReduce out")
		}
		coll, dbName := "", ""
		picked := 0
		for _, e := range els {
			switch e.Key() {
			case "replace", "merge", "reduce":
				picked++
				mode = map[string]installMode{"replace": modeReplace, "merge": modeMerge, "reduce": modeReduce}[e.Key()]
				coll, _ = e.Value().StringValueOK()
			case "db":
				dbName, _ = e.Value().StringValueOK()
			case "sharded", "nonAtomic":
			default:
				return nil, badValue("unknown mapReduce out option %q", e.Key())
			}
		}
		if picked != 1 || coll == "" {
			return nil, badValue("mapReduce out requires exactly one of replace, merge, reduce, inline")
		}
		t := buildDoc(bsoncore.AppendStringElement(nil, "coll", coll))
		if dbName != "" {
			t = buildDoc(bsoncore.AppendStringElement(nil, "coll", coll), bsoncore.AppendStringElement(nil, "db", dbName))
		}
		target = docValue(t)
	default:
		return nil, badValue("mapReduce requires out")
	}
	dstDB, dst, err := r.target(q.db, target)
	if err != nil {
		return nil, err
	}
	reduceFn := ""
	if mode == modeReduce {
		rv := q.body.Lookup("reduce")
		if s, ok := rv.StringValueOK(); ok {
			reduceFn = s
		} else if c, ok := rv.JavaScriptOK(); ok {
			reduceFn = c
		} else {
			return nil, badValue("mapReduce reduce must be a function")
		}
	}
	if err := noTxn(q); err != nil {
		return nil, err
	}

	var rb [8]byte
	rand.Read(rb[:])
	tmp := "__mtp_mr_" + hex.EncodeToString(rb[:])
	srcDB := q.db
	// Stage in a private collection; drop the client's out/db/$db options.
	staged := make([]byte, 4, len(b)+64)
	els, _ := b.Elements()
	for _, e := range els {
		switch e.Key() {
		case "out", "$db":
		default:
			staged = append(staged, e...)
		}
	}
	staged = bsoncore.AppendDocumentElement(staged, "out", buildDoc(bsoncore.AppendStringElement(nil, "replace", tmp)))
	stagedCmd := finishDoc(staged)
	t := q.t
	res := &Result{}
	res.Run = func(u Upstream) (bsoncore.Document, error) {
		bu := bound{u, t}
		resp, err := run(bu, srcDB, stagedCmd)
		if err != nil {
			return nil, err
		}
		defer u.Run(srcDB, buildDoc(bStr("drop", tmp)))
		if err := r.install(bu, srcDB, tmp, dstDB, dst, mode, reduceFn); err != nil {
			return nil, err
		}
		result := strVal(dst)
		if dstDB != srcDB {
			result = docValue(buildDoc(bStr("db", dstDB), bStr("collection", dst)))
		}
		out := buildDoc(valElem("result", result))
		if c := resp.Lookup("counts"); c.Type != 0 {
			out = appendRaw(out, valElem("counts", c))
		}
		if tm := resp.Lookup("timeMillis"); tm.Type != 0 {
			out = appendRaw(out, valElem("timeMillis", tm))
		}
		return appendRaw(out, bI32("ok", 1)), nil
	}
	return res, nil
}

// rewriteAtomicOut makes $out write to a private staging collection and then
// swap the tenant's documents in the target in one transaction (see install).
func (r *Rewriter) rewriteAtomicOut(t *Tenant, db, coll string, ex *extras, stamp value) []value {
	var rb [8]byte
	rand.Read(rb[:])
	tmp := "__mtp_out_" + hex.EncodeToString(rb[:])
	out := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$out", buildDoc(
		bsoncore.AppendStringElement(nil, "db", db), bsoncore.AppendStringElement(nil, "coll", tmp)))))
	ex.after = append(ex.after, Command{DB: db, Func: func(u Upstream) error {
		b := bound{u, t}
		defer u.Run(db, buildDoc(bStr("drop", tmp)))
		return r.install(b, db, tmp, db, coll, modeReplace, "")
	}})
	return []value{stamp, out}
}
