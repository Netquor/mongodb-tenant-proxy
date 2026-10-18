package rewrite

import (
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// _id policies.
//
// Every tenant shares the physical collections, and MongoDB's built-in _id
// index is unique per collection, so by default two tenants cannot use the
// same natural _id and a duplicate-key error reveals that another tenant's
// document exists. Three policies are available:
//
//	native             today's behaviour.
//	require-generated  _id must be an ObjectId or UUID (collisions between
//	                   tenants are then astronomically unlikely) and
//	                   duplicate-key errors on _id are made generic.
//	namespace          (experimental) _id is stored as {t: <tenant>, id: <_id>}
//	                   so it is unique per tenant, and unwrapped on the way out.
const (
	PolicyNative           = "native"
	PolicyRequireGenerated = "require-generated"
	PolicyNamespace        = "namespace"
)

func (r *Rewriter) nsOn() bool  { return r.idPolicy == PolicyNamespace }
func (r *Rewriter) genOn() bool { return r.idPolicy == PolicyRequireGenerated }

func nsUnsupported(what string) error {
	return deny("%s is not supported with tenant.idPolicy \"namespace\"", what)
}

// generatedID reports whether v is an ObjectId or a UUID (binary subtype 4).
func generatedID(v value) bool {
	switch v.Type {
	case bsoncore.TypeObjectID:
		return true
	case bsoncore.TypeBinary:
		sub, data, ok := v.BinaryOK()
		return ok && sub == 4 && len(data) == 16
	}
	return false
}

func badIDType() error {
	return deny("_id must be an ObjectId or UUID in this deployment")
}

// ---- inserts -------------------------------------------------------------

// policyInsertDoc applies the _id policy to a document being inserted.
func (r *Rewriter) policyInsertDoc(t *Tenant, d doc) (doc, error) {
	if r.idPolicy == "" || r.idPolicy == PolicyNative {
		return d, nil
	}
	elems, err := d.Elements()
	if err != nil {
		return nil, badValue("malformed document: %v", err)
	}
	n := 0
	for _, e := range elems {
		if e.Key() == "_id" {
			n++
		}
	}
	if n > 1 {
		return nil, badValue("duplicate _id field in document")
	}
	if r.genOn() {
		for _, e := range elems {
			if e.Key() == "_id" && !generatedID(e.Value()) {
				return nil, badIDType()
			}
		}
		return d, nil
	}
	// namespace
	out := make([]byte, 4, len(d)+48)
	for _, e := range elems {
		if e.Key() != "_id" {
			out = append(out, e...)
			continue
		}
		v := e.Value()
		switch v.Type {
		case bsoncore.TypeArray, bsoncore.TypeRegex, bsoncore.TypeUndefined:
			return nil, badValue("_id cannot be of this type")
		}
		out = bsoncore.AppendValueElement(out, "_id", r.wrapID(t, v))
	}
	if n == 0 {
		out = bsoncore.AppendValueElement(out, "_id", r.wrapID(t, newObjectID()))
	}
	return finishDoc(out), nil
}

func newObjectID() value {
	id := bson.NewObjectID()
	return value{Type: bsoncore.TypeObjectID, Data: id[:]}
}

func (r *Rewriter) wrapID(t *Tenant, id value) value {
	return docValue(buildDoc(valElem("t", t.Value), valElem("id", id)))
}

// unwrapID returns the client's _id if v is this tenant's wrapper.
func (r *Rewriter) unwrapID(t *Tenant, v value) (value, bool) {
	d, ok := v.DocumentOK()
	if !ok {
		return v, false
	}
	els, err := d.Elements()
	if err != nil || len(els) != 2 || els[0].Key() != "t" || els[1].Key() != "id" || !els[0].Value().Equal(t.Value) {
		return v, false
	}
	return els[1].Value(), true
}

// ---- upserts and update specs --------------------------------------------

// policyUpdate checks (require-generated) or adapts (namespace) the "u" of an
// update statement or findAndModify. q is the client's original filter.
func (r *Rewriter) policyUpdate(t *Tenant, q *value, u value, upsert bool) (value, error) {
	switch {
	case r.genOn():
		if !upsert {
			return u, nil // _id is immutable, so only upserts can introduce one
		}
		if q != nil {
			if qd, ok := q.DocumentOK(); ok {
				if err := genUpsertFilter(qd); err != nil {
					return value{}, err
				}
			}
		}
		return u, genUpsertSpec(u)
	case r.nsOn():
		return r.nsUpdateSpec(t, q, u, upsert)
	}
	return u, nil
}

// genUpsertFilter requires any _id the filter would pass on to an upserted
// document to be an ObjectId or UUID.
func genUpsertFilter(f doc) error {
	els, err := f.Elements()
	if err != nil {
		return badValue("malformed filter")
	}
	for _, e := range els {
		k, v := e.Key(), e.Value()
		switch {
		case k == "_id":
			if od, ok := v.DocumentOK(); ok && firstKeyIsOp(od) {
				oels, _ := od.Elements()
				if len(oels) == 1 && oels[0].Key() == "$eq" {
					if !generatedID(oels[0].Value()) {
						return badIDType()
					}
					continue
				}
				return deny("upserts must match _id by equality with an ObjectId or UUID")
			}
			if !generatedID(v) {
				return badIDType()
			}
		case strings.HasPrefix(k, "_id."):
			return deny("upserts may not build _id from a dotted path")
		case k == "$and":
			if a, ok := v.ArrayOK(); ok {
				vals, _ := a.Values()
				for _, x := range vals {
					if xd, ok := x.DocumentOK(); ok {
						if err := genUpsertFilter(xd); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func firstKeyIsOp(d doc) bool {
	e, err := d.IndexErr(0)
	return err == nil && strings.HasPrefix(e.Key(), "$")
}

func genUpsertSpec(u value) error {
	switch u.Type {
	case bsoncore.TypeEmbeddedDocument:
		d := u.Document()
		els, err := d.Elements()
		if err != nil {
			return badValue("malformed update document")
		}
		if len(els) > 0 && strings.HasPrefix(els[0].Key(), "$") {
			for _, op := range els {
				if op.Key() != "$set" && op.Key() != "$setOnInsert" {
					continue
				}
				if od, ok := op.Value().DocumentOK(); ok {
					if v := od.Lookup("_id"); v.Type != 0 && !generatedID(v) {
						return badIDType()
					}
				}
			}
			return nil
		}
		if v := d.Lookup("_id"); v.Type != 0 && !generatedID(v) {
			return badIDType()
		}
	case bsoncore.TypeArray:
		stages, _ := u.Array().Values()
		for _, s := range stages {
			sd, ok := s.DocumentOK()
			if !ok {
				continue
			}
			e, err := sd.IndexErr(0)
			if err != nil {
				continue
			}
			switch e.Key() {
			case "$replaceRoot", "$replaceWith":
				return deny("pipeline upserts with %s are not supported with this _id policy", e.Key())
			case "$set", "$addFields", "$project":
				if sp, ok := e.Value().DocumentOK(); ok && sp.Lookup("_id").Type != 0 {
					return deny("pipeline upserts may not set _id with this _id policy")
				}
			}
		}
	}
	return nil
}

// nsUpdateSpec adapts an update for the namespace policy.
func (r *Rewriter) nsUpdateSpec(t *Tenant, q *value, u value, upsert bool) (value, error) {
	hasEq := false
	if q != nil {
		if qd, ok := q.DocumentOK(); ok {
			hasEq = idEquality(qd)
		}
	}
	switch u.Type {
	case bsoncore.TypeArray:
		if refsID(u) {
			return value{}, nsUnsupported("referencing _id in an update pipeline")
		}
		stages, _ := u.Array().Values()
		for _, s := range stages {
			sd, _ := s.DocumentOK()
			if e, err := sd.IndexErr(0); err == nil {
				if sp, ok := e.Value().DocumentOK(); ok && (sp.Lookup("_id").Type != 0 || e.Key() == "$unset") {
					return value{}, nsUnsupported("changing _id in an update pipeline")
				}
				if e.Key() == "$unset" && refsIDName(e.Value()) {
					return value{}, nsUnsupported("changing _id in an update pipeline")
				}
			}
		}
		if upsert && !hasEq {
			return value{}, nsUnsupported("a pipeline upsert without an _id equality in the filter")
		}
		return u, nil
	case bsoncore.TypeEmbeddedDocument:
		d := u.Document()
		els, err := d.Elements()
		if err != nil {
			return value{}, badValue("malformed update document")
		}
		if len(els) > 0 && strings.HasPrefix(els[0].Key(), "$") {
			for _, op := range els {
				od, _ := op.Value().DocumentOK()
				fields, _ := od.Elements()
				for _, f := range fields {
					if f.Key() == "_id" || strings.HasPrefix(f.Key(), "_id.") {
						return value{}, nsUnsupported("modifying _id in an update")
					}
					if op.Key() == "$rename" {
						if to, ok := f.Value().StringValueOK(); ok && (to == "_id" || strings.HasPrefix(to, "_id.")) {
							return value{}, nsUnsupported("renaming onto _id")
						}
					}
				}
			}
			if upsert && !hasEq {
				// Give inserted documents a (wrapped) generated _id.
				return setOnInsertID(d, r.wrapID(t, newObjectID()))
			}
			return u, nil
		}
		// Replacement document.
		if v := d.Lookup("_id"); v.Type != 0 {
			nd, err := r.policyInsertDoc(t, d) // wraps the explicit _id
			return docValue(nd), err
		}
		if upsert && !hasEq {
			return value{}, nsUnsupported("a replacement upsert without an _id equality in the filter")
		}
		return u, nil
	}
	return u, nil
}

// setOnInsertID merges {$setOnInsert: {_id: id}} into an operator update.
func setOnInsertID(d doc, id value) (value, error) {
	out, err := setField(d, "$setOnInsert", func(old *value) (value, bool, error) {
		if old == nil {
			return docValue(buildDoc(valElem("_id", id))), true, nil
		}
		od, _ := old.DocumentOK()
		b := append([]byte{}, od[:len(od)-1]...)
		b = bsoncore.AppendValueElement(b, "_id", id)
		b = append(b, 0)
		n := len(b)
		safeconv.PutLen(b, n)
		return docValue(b), true, nil
	})
	return docValue(out), err
}

// idEquality reports whether the filter pins _id by equality (top level or
// inside $and), which MongoDB copies into upserted documents.
func idEquality(f doc) bool {
	els, err := f.Elements()
	if err != nil {
		return false
	}
	for _, e := range els {
		switch e.Key() {
		case "_id":
			if od, ok := e.Value().DocumentOK(); ok && firstKeyIsOp(od) {
				oels, _ := od.Elements()
				if len(oels) == 1 && oels[0].Key() == "$eq" {
					return true
				}
				continue
			}
			return true
		case "$and":
			if a, ok := e.Value().ArrayOK(); ok {
				vals, _ := a.Values()
				for _, x := range vals {
					if xd, ok := x.DocumentOK(); ok && idEquality(xd) {
						return true
					}
				}
			}
		}
	}
	return false
}

// ---- namespace: filters --------------------------------------------------

// nsFilterVal rewrites a filter document so that conditions on _id address
// the wrapped form.
func (r *Rewriter) nsFilterVal(t *Tenant, v value) (value, error) {
	d, ok := v.DocumentOK()
	if !ok {
		return value{}, badValue("filter must be a document")
	}
	nd, err := r.nsFilter(t, d)
	return docValue(nd), err
}

func (r *Rewriter) nsFilter(t *Tenant, d doc) (doc, error) {
	els, err := d.Elements()
	if err != nil {
		return nil, badValue("malformed filter: %v", err)
	}
	out := make([]byte, 4, len(d)+32)
	for _, e := range els {
		k, v := e.Key(), e.Value()
		switch {
		case k == "$and" || k == "$or" || k == "$nor":
			a, ok := v.ArrayOK()
			if !ok {
				return nil, badValue("%s requires an array", k)
			}
			na, err := mapDocs(a, func(x doc) (doc, error) { return r.nsFilter(t, x) })
			if err != nil {
				return nil, err
			}
			out = bsoncore.AppendArrayElement(out, k, na)
		case k == "$expr":
			if refsID(v) {
				return nil, nsUnsupported("$expr that references _id or $$ROOT")
			}
			out = append(out, e...)
		case k == "$where" || k == "$jsonSchema":
			return nil, nsUnsupported(k)
		case k == "$comment" || k == "$text":
			out = append(out, e...)
		case strings.HasPrefix(k, "$"):
			return nil, nsUnsupported("top-level operator " + k)
		case k == "_id":
			nv, err := r.nsIDCond(t, v)
			if err != nil {
				return nil, err
			}
			out = bsoncore.AppendValueElement(out, k, nv)
		case strings.HasPrefix(k, "_id."):
			out = bsoncore.AppendValueElement(out, "_id.id."+k[len("_id."):], v)
		default:
			out = append(out, e...)
		}
	}
	return finishDoc(out), nil
}

func (r *Rewriter) nsWrapOperand(t *Tenant, x value) (value, error) {
	if x.Type == bsoncore.TypeRegex {
		return value{}, nsUnsupported("regular expressions on _id")
	}
	return r.wrapID(t, x), nil
}

// nsIDCond rewrites the condition on _id: equality and the comparison and set
// operators are supported; everything else is rejected.
//
// Range operators compare the wrapper {t, id} as a whole. Because every query
// is also confined to the tenant, only ids are compared, but unlike a native
// range query the comparison is not limited to values of the operand's BSON
// type.
func (r *Rewriter) nsIDCond(t *Tenant, v value) (value, error) {
	d, ok := v.DocumentOK()
	if !ok || !firstKeyIsOp(d) {
		return r.nsWrapOperand(t, v)
	}
	els, err := d.Elements()
	if err != nil {
		return value{}, badValue("malformed _id condition")
	}
	out := make([]byte, 4, len(d)+32)
	for _, e := range els {
		k, x := e.Key(), e.Value()
		switch k {
		case "$eq", "$ne", "$gt", "$gte", "$lt", "$lte":
			w, err := r.nsWrapOperand(t, x)
			if err != nil {
				return value{}, err
			}
			out = bsoncore.AppendValueElement(out, k, w)
		case "$in", "$nin":
			a, ok := x.ArrayOK()
			if !ok {
				return value{}, badValue("%s needs an array", k)
			}
			vals, err := a.Values()
			if err != nil {
				return value{}, badValue("malformed %s", k)
			}
			ws := make([]value, len(vals))
			for i, y := range vals {
				if ws[i], err = r.nsWrapOperand(t, y); err != nil {
					return value{}, err
				}
			}
			out = bsoncore.AppendArrayElement(out, k, arrayOf(ws...))
		case "$exists":
			out = append(out, e...)
		case "$not":
			nd, ok := x.DocumentOK()
			if !ok || !firstKeyIsOp(nd) {
				return value{}, nsUnsupported("$not with a non-operator on _id")
			}
			nv, err := r.nsIDCond(t, x)
			if err != nil {
				return value{}, err
			}
			out = bsoncore.AppendValueElement(out, k, nv)
		default:
			return value{}, nsUnsupported("operator " + k + " on _id")
		}
	}
	return docValue(finishDoc(out)), nil
}

// refsID reports whether an expression mentions the document _id or the whole
// document, whose _id is stored in wrapped form.
func refsID(v value) bool {
	switch v.Type {
	case bsoncore.TypeString:
		s := v.StringValue()
		return s == "$_id" || strings.HasPrefix(s, "$_id.") ||
			strings.HasPrefix(s, "$$ROOT") || strings.HasPrefix(s, "$$CURRENT")
	case bsoncore.TypeEmbeddedDocument:
		els, err := v.Document().Elements()
		if err != nil {
			return true
		}
		for _, e := range els {
			if refsID(e.Value()) {
				return true
			}
		}
	case bsoncore.TypeArray:
		vals, err := v.Array().Values()
		if err != nil {
			return true
		}
		for _, x := range vals {
			if refsID(x) {
				return true
			}
		}
	}
	return false
}

// refsIDName reports whether a string or array of strings names _id.
func refsIDName(v value) bool {
	if s, ok := v.StringValueOK(); ok {
		return s == "_id" || strings.HasPrefix(s, "_id.")
	}
	if a, ok := v.ArrayOK(); ok {
		vals, _ := a.Values()
		for _, x := range vals {
			if refsIDName(x) {
				return true
			}
		}
	}
	return false
}
