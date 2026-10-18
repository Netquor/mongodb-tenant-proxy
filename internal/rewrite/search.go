package rewrite

import (
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Atlas Search ($search, $searchMeta) and Atlas Vector Search ($vectorSearch).
//
// These stages run inside mongot, which indexes the shared collection, so the
// tenant restriction has to be part of the search itself:
//
//   - $search / $searchMeta: the client's operator is wrapped as
//     compound.must and an `equals` clause on the tenant field is added to
//     compound.filter. A filter clause does not influence scoring.
//   - $vectorSearch: the tenant equality is ANDed into the `filter` option.
//
// Both require the tenant field to be indexed: mapped as `token` (string
// tenant ids), `objectId` or `number` in the search index, and declared as a
// `filter` field in the vector index definition. Without that the search
// fails on the server (it never returns unscoped results).

var searchOperators = map[string]struct{}{
	"autocomplete": {}, "compound": {}, "embeddedDocument": {}, "equals": {}, "exists": {}, "geoShape": {},
	"geoWithin": {}, "in": {}, "knnBeta": {}, "moreLikeThis": {}, "near": {}, "phrase": {}, "queryString": {},
	"range": {}, "regex": {}, "text": {}, "wildcard": {}, "vectorSearch": {},
}

func (r *Rewriter) searchEquals(t *Tenant) value {
	return docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "equals", buildDoc(
		bsoncore.AppendStringElement(nil, "path", r.field),
		valElem("value", t.Value)))))
}

// wrapOperator returns {compound: {filter: [tenant], must: [{name: spec}]}}.
func (r *Rewriter) wrapOperator(t *Tenant, name string, spec value) []byte {
	must := arrayOf(docValue(buildDoc(valElem(name, spec))))
	return bsoncore.AppendDocumentElement(nil, "compound", buildDoc(
		bsoncore.AppendArrayElement(nil, "filter", arrayOf(r.searchEquals(t))),
		bsoncore.AppendArrayElement(nil, "must", must)))
}

// rewriteSearchOperator scopes an operator document such as {text: {...}}.
func (r *Rewriter) rewriteSearchOperator(t *Tenant, opDoc doc) (value, error) {
	els, err := opDoc.Elements()
	if err != nil || len(els) != 1 {
		return value{}, badValue("a search operator document must contain exactly one operator")
	}
	name, spec := els[0].Key(), els[0].Value()
	if _, ok := searchOperators[name]; !ok {
		return value{}, badValue("unknown search operator %q", name)
	}
	if name == "knnBeta" {
		kd, ok := spec.DocumentOK()
		if !ok {
			return value{}, badValue("knnBeta requires a document")
		}
		nk, err := setField(kd, "filter", func(old *value) (value, bool, error) {
			if old == nil {
				return r.searchEquals(t), true, nil
			}
			od, ok := old.DocumentOK()
			if !ok {
				return value{}, false, badValue("knnBeta filter must be an operator document")
			}
			inner, err := r.rewriteSearchOperator(t, od)
			return inner, true, err
		})
		if err != nil {
			return value{}, err
		}
		return docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "knnBeta", nk))), nil
	}
	return docValue(buildDoc(r.wrapOperator(t, name, spec))), nil
}

// rewriteSearch scopes the spec of $search, $searchMeta or $vectorSearch.
func (r *Rewriter) rewriteSearch(t *Tenant, stage string, spec value) (value, error) {
	d, ok := spec.DocumentOK()
	if !ok {
		return value{}, badValue("%s requires a document", stage)
	}
	els, err := d.Elements()
	if err != nil {
		return value{}, badValue("malformed %s", stage)
	}
	if err := checkNoDuplicateKeys(els); err != nil {
		return value{}, err
	}

	if stage == "$vectorSearch" {
		nd, err := setField(d, "filter", func(old *value) (value, bool, error) {
			eq := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, r.field, buildDoc(valElem("$eq", t.Value)))))
			if old == nil {
				return eq, true, nil
			}
			if _, ok := old.DocumentOK(); !ok {
				return value{}, false, badValue("$vectorSearch filter must be a document")
			}
			return docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$and", arrayOf(eq, *old)))), true, nil
		})
		return docValue(nd), err
	}

	out := make([]byte, 4, len(d)+128)
	scoped := false
	for _, e := range els {
		k, v := e.Key(), e.Value()
		switch {
		case k == "facet" && stage == "$searchMeta":
			fd, ok := v.DocumentOK()
			if !ok {
				return value{}, badValue("facet requires a document")
			}
			nf, err := setField(fd, "operator", func(old *value) (value, bool, error) {
				if old == nil {
					return docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "compound", buildDoc(
						bsoncore.AppendArrayElement(nil, "filter", arrayOf(r.searchEquals(t))))))), true, nil
				}
				od, ok := old.DocumentOK()
				if !ok {
					return value{}, false, badValue("facet operator must be an operator document")
				}
				nv, err := r.rewriteSearchOperator(t, od)
				return nv, true, err
			})
			if err != nil {
				return value{}, err
			}
			out = bsoncore.AppendDocumentElement(out, "facet", nf)
			scoped = true
		default:
			if _, isOp := searchOperators[k]; isOp {
				if scoped {
					return value{}, badValue("%s accepts exactly one operator", stage)
				}
				scoped = true
				if k == "knnBeta" {
					// Approximate search: the tenant filter has to be part of
					// the nearest-neighbour search, not applied afterwards.
					nv, err := r.rewriteSearchOperator(t, buildDoc(valElem(k, v)))
					if err != nil {
						return value{}, err
					}
					out = append(out, nv.Document()[4:len(nv.Document())-1]...)
					continue
				}
				out = append(out, r.wrapOperator(t, k, v)...)
				continue
			}
			out = append(out, e...)
		}
	}
	if !scoped {
		return value{}, badValue("%s requires an operator", stage)
	}
	return docValue(finishDoc(out)), nil
}

func returnsStoredSource(spec value) bool {
	d, ok := spec.DocumentOK()
	if !ok {
		return false
	}
	b, _ := d.Lookup("returnStoredSource").BooleanOK()
	return b
}
