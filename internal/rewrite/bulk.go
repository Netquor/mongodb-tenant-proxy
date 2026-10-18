package rewrite

import (
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// bulkWrite (MongoDB 8.0, used by client.bulkWrite in newer drivers) is a
// cross-namespace command that runs against the admin database. Each op names
// a namespace through an index into nsInfo, so the rewriter validates every
// namespace itself and then rewrites each op exactly like the single-collection
// insert/update/delete handlers.

var bulkOpKeys = map[string]map[string]struct{}{
	"insert": {"insert": {}, "document": {}},
	"update": {"update": {}, "filter": {}, "updateMods": {}, "multi": {}, "upsert": {}, "arrayFilters": {},
		"hint": {}, "collation": {}, "constants": {}, "sort": {}},
	"delete": {"delete": {}, "filter": {}, "multi": {}, "hint": {}, "collation": {}},
}

var bulkNsKeys = map[string]struct{}{"ns": {}, "shardKey": {}, "collectionUUID": {}}

func (r *Rewriter) cmdBulkWrite(q *request) (*Result, error) {
	if err := noSeqs(q, "ops", "nsInfo"); err != nil {
		return nil, err
	}
	if q.body.Lookup("encryptionInformation").Type != 0 {
		return nil, deny("bulkWrite with encryptionInformation is not supported")
	}
	if l := q.body.Lookup("let"); l.Type != 0 {
		if err := r.scan(l); err != nil {
			return nil, err
		}
	}

	nsDocs, nsFromSeq, err := bulkSource(q, "nsInfo")
	if err != nil {
		return nil, err
	}
	nss := make([]string, len(nsDocs))
	for i, d := range nsDocs {
		els, err := d.Elements()
		if err != nil {
			return nil, badValue("malformed nsInfo entry")
		}
		if err := checkNoDuplicateKeys(els); err != nil {
			return nil, err
		}
		for _, e := range els {
			if _, ok := bulkNsKeys[e.Key()]; !ok {
				return nil, badValue("unknown nsInfo field %q", e.Key())
			}
		}
		ns, ok := d.Lookup("ns").StringValueOK()
		if !ok {
			return nil, badValue("nsInfo entry %d requires ns", i)
		}
		db, coll, found := strings.Cut(ns, ".")
		if !found {
			return nil, badValue("invalid namespace %q", ns)
		}
		if !r.dbAllowed(db) {
			return nil, deny("database %q is not accessible", db)
		}
		if err := checkCollName(coll); err != nil {
			return nil, err
		}
		nss[i] = ns
	}
	if len(nss) == 0 {
		return nil, badValue("bulkWrite requires nsInfo")
	}

	opDocs, opsFromSeq, err := bulkSource(q, "ops")
	if err != nil {
		return nil, err
	}
	newOps := make([]doc, len(opDocs))
	for i, d := range opDocs {
		if newOps[i], err = r.rewriteBulkOp(q.t, d, len(nss)); err != nil {
			return nil, err
		}
	}

	res := &Result{Body: q.body, Namespaces: nss}
	if !opsFromSeq {
		res.Body, err = setField(res.Body, "ops", func(*value) (value, bool, error) {
			vals := make([]value, len(newOps))
			for i, d := range newOps {
				vals[i] = docValue(d)
			}
			return arrValue(arrayOf(vals...)), true, nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		res.Seqs = append(res.Seqs, wire.Seq{ID: "ops", Docs: toDocs(newOps)})
	}
	if nsFromSeq {
		res.Seqs = append(res.Seqs, wire.Seq{ID: "nsInfo", Docs: toDocs(nsDocs)})
	}
	return res, nil
}

func toDocs(ds []doc) []bsoncore.Document {
	out := make([]bsoncore.Document, len(ds))
	for i, d := range ds {
		out[i] = d
	}
	return out
}

// bulkSource returns the documents of an `ops`/`nsInfo` argument, which a
// driver sends either as an OP_MSG document sequence or as a body array.
func bulkSource(q *request, key string) (docs []doc, fromSeq bool, err error) {
	var seq *wire.Seq
	for i := range q.seqs {
		if q.seqs[i].ID == key {
			if seq != nil {
				return nil, false, badValue("duplicate document sequence %q", key)
			}
			seq = &q.seqs[i]
		}
	}
	v := q.body.Lookup(key)
	switch {
	case seq != nil && v.Type != 0:
		return nil, false, badValue("%q given both as a sequence and in the body", key)
	case seq != nil:
		for _, d := range seq.Docs {
			docs = append(docs, doc(d))
		}
		return docs, true, nil
	case v.Type == 0:
		return nil, false, badValue("bulkWrite requires %s", key)
	}
	a, ok := v.ArrayOK()
	if !ok {
		return nil, false, badValue("%s must be an array", key)
	}
	vals, err := a.Values()
	if err != nil {
		return nil, false, badValue("malformed %s", key)
	}
	for _, x := range vals {
		d, ok := x.DocumentOK()
		if !ok {
			return nil, false, badValue("%s entries must be documents", key)
		}
		docs = append(docs, d)
	}
	return docs, false, nil
}

func (r *Rewriter) rewriteBulkOp(t *Tenant, d doc, nsCount int) (doc, error) {
	els, err := d.Elements()
	if err != nil || len(els) == 0 {
		return nil, badValue("malformed bulkWrite op")
	}
	if err := checkNoDuplicateKeys(els); err != nil {
		return nil, err
	}
	kind := els[0].Key()
	allowed, ok := bulkOpKeys[kind]
	if !ok {
		return nil, badValue("unknown bulkWrite op %q", kind)
	}
	for _, e := range els {
		if _, ok := allowed[e.Key()]; !ok {
			return nil, badValue("unknown field %q in bulkWrite %s op", e.Key(), kind)
		}
	}
	idx, ok := els[0].Value().AsInt64OK()
	if !ok || idx < 0 || idx >= int64(nsCount) {
		return nil, badValue("bulkWrite op has an invalid namespace index")
	}
	out := make([]byte, 4, len(d)+64)
	for _, e := range els {
		v := e.Value()
		switch {
		case e.Key() == "document":
			dd, ok := v.DocumentOK()
			if !ok {
				return nil, badValue("insert document must be a document")
			}
			nd, err := r.ensureTenant(t, dd)
			if err != nil {
				return nil, err
			}
			out = bsoncore.AppendDocumentElement(out, "document", nd)
		case e.Key() == "filter":
			f, err := r.scopeFilter(t, &v)
			if err != nil {
				return nil, err
			}
			out = bsoncore.AppendValueElement(out, "filter", f)
		case e.Key() == "updateMods":
			u, err := r.rewriteUpdateSpec(t, v)
			if err != nil {
				return nil, err
			}
			out = bsoncore.AppendValueElement(out, "updateMods", u)
		case e.Key() == "constants" || e.Key() == "arrayFilters" || e.Key() == "sort":
			if err := r.scan(v); err != nil {
				return nil, err
			}
			out = append(out, e...)
		default:
			out = append(out, e...)
		}
	}
	// Update and delete ops always carry a filter; add one if the client omitted it.
	if kind != "insert" && !hasKey(els, "filter") {
		f, _ := r.scopeFilter(t, nil)
		out = bsoncore.AppendValueElement(out, "filter", f)
	}
	return finishDoc(out), nil
}

func hasKey(els []bsoncore.Element, k string) bool {
	for _, e := range els {
		if e.Key() == k {
			return true
		}
	}
	return false
}
