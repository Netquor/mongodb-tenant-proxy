package rewrite

import (
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// ---- namespace: pipelines ------------------------------------------------

// nsStages are the aggregation stages usable with the namespace policy. Stages
// that read other collections, write, fan out into sub-pipelines or emit
// events would expose wrapped _id values the proxy cannot find to unwrap.
var nsStages = map[string]struct{}{
	"$addFields": {}, "$bucket": {}, "$bucketAuto": {}, "$count": {}, "$densify": {},
	"$fill": {}, "$geoNear": {}, "$group": {}, "$limit": {}, "$match": {}, "$project": {},
	"$redact": {}, "$replaceRoot": {}, "$replaceWith": {}, "$sample": {}, "$set": {},
	"$setWindowFields": {}, "$skip": {}, "$sort": {}, "$sortByCount": {}, "$unset": {}, "$unwind": {},
}

// nsPipeline validates a pipeline for the namespace policy and rewrites its
// _id conditions. wrapped reports whether documents leaving the pipeline
// still carry a wrapped _id (false after $group and similar stages, whose _id
// is a computed value the client must receive unchanged).
func (r *Rewriter) nsPipeline(t *Tenant, p arr) (out arr, wrapped bool, err error) {
	stages, err := p.Values()
	if err != nil {
		return nil, false, badValue("malformed pipeline")
	}
	wrapped = true
	res := make([]value, 0, len(stages))
	for i, s := range stages {
		sd, ok := s.DocumentOK()
		if !ok {
			return nil, false, badValue("pipeline stage %d must be a document", i)
		}
		e, err := sd.IndexErr(0)
		if err != nil || len(sd) != len(e)+5 {
			return nil, false, badValue("pipeline stage %d must have exactly one field", i)
		}
		name, spec := e.Key(), e.Value()
		if _, ok := nsStages[name]; !ok {
			return nil, false, nsUnsupported("aggregation stage " + name)
		}
		if err := scanForbidden(spec); err != nil { // JavaScript could read this._id
			return nil, false, err
		}
		if wrapped && refsID(spec) {
			return nil, false, nsUnsupported("expressions that reference _id or $$ROOT in " + name)
		}
		switch name {
		case "$match":
			if wrapped {
				if spec, err = r.nsFilterVal(t, spec); err != nil {
					return nil, false, err
				}
			}
		case "$group", "$bucket", "$bucketAuto", "$sortByCount", "$count", "$replaceRoot", "$replaceWith":
			wrapped = false
		case "$unset":
			if refsIDName(spec) {
				wrapped = false
			}
		case "$project", "$addFields", "$set":
			if sp, ok := spec.DocumentOK(); ok {
				els, _ := sp.Elements()
				for _, f := range els {
					switch {
					case strings.HasPrefix(f.Key(), "_id."):
						return nil, false, nsUnsupported("dotted _id paths in " + name)
					case f.Key() == "_id":
						// Inclusion keeps the wrapped value; anything else replaces or drops it.
						if n, ok := f.Value().AsInt64OK(); !(ok && n == 1 && name == "$project") {
							if b, isBool := f.Value().BooleanOK(); !(isBool && b && name == "$project") {
								wrapped = false
							}
						}
					}
				}
			}
		case "$sort":
			if sp, ok := spec.DocumentOK(); ok {
				els, _ := sp.Elements()
				for _, f := range els {
					if strings.HasPrefix(f.Key(), "_id.") {
						return nil, false, nsUnsupported("sorting by a dotted _id path")
					}
				}
			}
		}
		res = append(res, docValue(buildDoc(valElem(name, spec))))
	}
	return arrayOf(res...), wrapped, nil
}

// ---- unwrapping replies --------------------------------------------------

func (r *Rewriter) unwrapDoc(t *Tenant, d doc) doc {
	idv := d.Lookup("_id")
	if idv.Type == 0 {
		return d
	}
	u, ok := r.unwrapID(t, idv)
	if !ok {
		return d
	}
	nd, err := setField(d, "_id", func(*value) (value, bool, error) { return u, true, nil })
	if err != nil {
		return d
	}
	return nd
}

func (r *Rewriter) unwrapBatch(t *Tenant, a arr) arr {
	vals, err := a.Values()
	if err != nil {
		return a
	}
	out := make([]value, len(vals))
	for i, v := range vals {
		if d, ok := v.DocumentOK(); ok {
			out[i] = docValue(r.unwrapDoc(t, d))
		} else {
			out[i] = v
		}
	}
	return arrayOf(out...)
}

func (r *Rewriter) replaceField(d doc, key string, fn func(value) value) doc {
	v := d.Lookup(key)
	if v.Type == 0 {
		return d
	}
	nd, err := setField(d, key, func(*value) (value, bool, error) { return fn(v), true, nil })
	if err != nil {
		return d
	}
	return nd
}

// IDPost returns the reply transformer for the namespace policy: it unwraps
// _id in cursor batches, findAndModify results and upsert reports.
func (r *Rewriter) IDPost(t *Tenant) func(doc) doc {
	if !r.nsOn() {
		return nil
	}
	return func(resp doc) doc {
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			return resp
		}
		resp = r.replaceField(resp, "cursor", func(c value) value {
			cd, ok := c.DocumentOK()
			if !ok {
				return c
			}
			for _, k := range []string{"firstBatch", "nextBatch"} {
				cd = r.replaceField(cd, k, func(b value) value {
					if a, ok := b.ArrayOK(); ok {
						return arrValue(r.unwrapBatch(t, a))
					}
					return b
				})
			}
			return docValue(cd)
		})
		resp = r.replaceField(resp, "value", func(v value) value {
			if d, ok := v.DocumentOK(); ok {
				return docValue(r.unwrapDoc(t, d))
			}
			return v
		})
		resp = r.replaceField(resp, "lastErrorObject", func(v value) value {
			d, ok := v.DocumentOK()
			if !ok {
				return v
			}
			return docValue(r.replaceField(d, "upserted", func(x value) value {
				if u, ok := r.unwrapID(t, x); ok {
					return u
				}
				return x
			}))
		})
		resp = r.replaceField(resp, "upserted", func(v value) value {
			a, ok := v.ArrayOK()
			if !ok {
				return v
			}
			vals, _ := a.Values()
			out := make([]value, len(vals))
			for i, x := range vals {
				out[i] = x
				if d, ok := x.DocumentOK(); ok {
					out[i] = docValue(r.replaceField(d, "_id", func(id value) value {
						if u, ok := r.unwrapID(t, id); ok {
							return u
						}
						return id
					}))
				}
			}
			return arrValue(arrayOf(out...))
		})
		return resp
	}
}

func (r *Rewriter) distinctIDPost(t *Tenant) func(doc) doc {
	return func(resp doc) doc {
		return r.replaceField(resp, "values", func(v value) value {
			a, ok := v.ArrayOK()
			if !ok {
				return v
			}
			vals, _ := a.Values()
			out := make([]value, len(vals))
			for i, x := range vals {
				out[i] = x
				if u, ok := r.unwrapID(t, x); ok {
					out[i] = u
				}
			}
			return arrValue(arrayOf(out...))
		})
	}
}

// ---- duplicate-key errors ------------------------------------------------

const genericDupMsg = "E11000 duplicate key error"

func isIDDup(code int64, msg string, keyPattern value) bool {
	if code != 11000 {
		return false
	}
	if strings.Contains(msg, "index: _id_") {
		return true
	}
	if kp, ok := keyPattern.DocumentOK(); ok && kp.Lookup("_id").Type != 0 {
		return true
	}
	return false
}

// scrubDupKey replaces duplicate-key errors on _id with a generic message
// and drops keyPattern/keyValue/errInfo, so the reply carries nothing about
// the colliding document.
func scrubDupKey(resp doc) doc {
	resp = (&Rewriter{}).replaceField(resp, "writeErrors", func(v value) value {
		a, ok := v.ArrayOK()
		if !ok {
			return v
		}
		vals, _ := a.Values()
		out := make([]value, len(vals))
		for i, x := range vals {
			out[i] = x
			d, ok := x.DocumentOK()
			if !ok {
				continue
			}
			code, _ := d.Lookup("code").AsInt64OK()
			msg, _ := d.Lookup("errmsg").StringValueOK()
			if isIDDup(code, msg, d.Lookup("keyPattern")) {
				b := make([]byte, 4)
				b = bsoncore.AppendInt32Element(b, "index", int32(i))
				if idx, ok := d.Lookup("index").AsInt64OK(); ok {
					b = b[:4]
					b = bsoncore.AppendInt32Element(b, "index", safeconv.Sat32(idx))
				}
				b = bsoncore.AppendInt32Element(b, "code", 11000)
				b = bsoncore.AppendStringElement(b, "errmsg", genericDupMsg)
				out[i] = docValue(finishDoc(b))
			}
		}
		return arrValue(arrayOf(out...))
	})
	if ok, _ := resp.Lookup("ok").AsInt64OK(); ok == 0 {
		code, _ := resp.Lookup("code").AsInt64OK()
		msg, _ := resp.Lookup("errmsg").StringValueOK()
		if isIDDup(code, msg, resp.Lookup("keyPattern")) {
			els, _ := resp.Elements()
			b := make([]byte, 4)
			for _, e := range els {
				switch e.Key() {
				case "errmsg":
					b = bsoncore.AppendStringElement(b, "errmsg", genericDupMsg)
				case "keyPattern", "keyValue", "errInfo":
				default:
					b = append(b, e...)
				}
			}
			return finishDoc(b)
		}
	}
	return resp
}

// attachIDPost sets the reply transformation the _id policy needs.
func (r *Rewriter) attachIDPost(q *request, res *Result) {
	if r.idPolicy == "" || r.idPolicy == PolicyNative || res.Reply != nil {
		return
	}
	var posts []func(doc) doc
	switch q.cmd {
	case "insert", "update", "delete", "findAndModify":
		posts = append(posts, scrubDupKey)
	}
	if r.nsOn() {
		switch q.cmd {
		case "find", "aggregate":
			if res.IDCursor {
				posts = append(posts, r.IDPost(q.t))
			}
		case "update", "findAndModify":
			posts = append(posts, r.IDPost(q.t))
		case "distinct":
			if res.idDistinct {
				posts = append(posts, r.distinctIDPost(q.t))
			}
		}
	}
	if res.Post != nil {
		posts = append([]func(doc) doc{res.Post}, posts...)
	}
	if len(posts) == 0 {
		return
	}
	res.Post = func(d doc) doc {
		for _, p := range posts {
			d = p(d)
		}
		return d
	}
}

// ---- require-generated: pipeline writes ----------------------------------

// idCheckStage fails the pipeline when a document about to be written by
// $merge/$out has an _id that is not an ObjectId (an absent _id becomes one).
func idCheckStage() value {
	typ := func() value { return value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "$_id")} }
	str := func(s string) value { return value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, s)} }
	isType := func(name string) value {
		return docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$eq", arrayOf(
			docValue(buildDoc(valElem("$type", typ()))), str(name)))))
	}
	valid := docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$or", arrayOf(isType("objectId"), isType("missing")))))
	// $type keeps the expression from being folded into a constant (which
	// would raise the error while optimising instead of per document).
	fail := docValue(buildDoc(valElem("$toObjectId", docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$concat", arrayOf(
		str("tenant proxy: _id must be an ObjectId in this deployment (writes through $merge/$out); found "),
		docValue(buildDoc(valElem("$type", typ()))))))))))
	cond := docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$cond", arrayOf(valid, str("$$REMOVE"), fail))))
	return docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$set", buildDoc(valElem("__mtp_idcheck", cond)))))
}
