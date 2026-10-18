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

// cmdMapReduce supports inline mapReduce over the tenant's documents. The
// functions run inside mongod without access to other collections.
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
	if out, ok := q.body.Lookup("out").DocumentOK(); !ok || out.Lookup("inline").Type == 0 {
		return nil, deny("mapReduce output to a collection is not supported; use inline output or $merge")
	}
	b, err := r.scopeField(q, q.body, "query")
	if err != nil {
		return nil, err
	}
	return &Result{Body: b}, nil
}
