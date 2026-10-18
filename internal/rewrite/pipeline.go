package rewrite

import (
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// safeStages are aggregation stages that only operate on their input stream
// and cannot read or write other collections.
var safeStages = map[string]struct{}{
	"$addFields": {}, "$bucket": {}, "$bucketAuto": {}, "$count": {}, "$densify": {},
	"$fill": {}, "$group": {}, "$limit": {}, "$match": {}, "$project": {}, "$redact": {},
	"$replaceRoot": {}, "$replaceWith": {}, "$sample": {}, "$set": {}, "$setWindowFields": {},
	"$skip": {}, "$sort": {}, "$sortByCount": {}, "$unset": {}, "$unwind": {},
}

// scopePipeline rewrites an aggregation pipeline so it only sees the tenant's
// documents. When inject is true the pipeline reads directly from a
// collection and a tenant filter is added at the front; when false (for
// $facet branches) the input stream is already scoped, but nested stages are
// still rewritten.
func (r *Rewriter) scopePipeline(t *Tenant, p arr, inject bool, ex *extras) (arr, error) {
	stages, err := p.Values()
	if err != nil {
		return nil, badValue("malformed pipeline")
	}
	out := make([]value, 0, len(stages)+1)
	scopedFirst := false
	for i, s := range stages {
		sd, ok := s.DocumentOK()
		if !ok {
			return nil, badValue("pipeline stage %d must be a document", i)
		}
		e, err := sd.IndexErr(0)
		if err != nil || len(sd) != len(e)+5 {
			return nil, badValue("pipeline stage %d must have exactly one field", i)
		}
		name := e.Key()
		spec := e.Value()
		var ns value
		switch name {
		case "$match":
			if inject && i == 0 {
				// Wrap instead of prepending so $text stays in first position.
				f, err := r.scopeFilter(t, &spec)
				if err != nil {
					return nil, err
				}
				ns = f
				scopedFirst = true
			} else {
				if err := r.scan(spec); err != nil {
					return nil, err
				}
				ns = spec
			}
		case "$geoNear":
			d, ok := spec.DocumentOK()
			if !ok {
				return nil, badValue("$geoNear requires a document")
			}
			nd, err := r.scopeField(&request{t: t}, d, "query")
			if err != nil {
				return nil, err
			}
			ns = docValue(nd)
			if i == 0 {
				scopedFirst = true
			}
		case "$changeStream":
			if !r.cs {
				return nil, deny("change streams are not enabled")
			}
			if !inject || i != 0 {
				return nil, deny("$changeStream must be the first stage of a collection aggregate")
			}
			cs, err := r.rewriteChangeStream(t, spec, ex != nil && ex.dbLevel)
			if err != nil {
				return nil, err
			}
			out = append(out, cs...)
			scopedFirst = true
			continue
		case "$merge", "$out":
			if ex == nil || i != len(stages)-1 {
				return nil, deny("%s must be the last stage of a top-level aggregate", name)
			}
			w, err := r.rewriteWrite(t, name, spec, ex)
			if err != nil {
				return nil, err
			}
			out = append(out, w...)
			continue
		case "$lookup":
			ns, err = r.rewriteLookup(t, spec)
		case "$graphLookup":
			ns, err = r.rewriteGraphLookup(t, spec)
		case "$unionWith":
			ns, err = r.rewriteUnionWith(t, spec)
		case "$facet":
			ns, err = r.rewriteFacet(t, spec)
		default:
			if _, ok := safeStages[name]; !ok {
				return nil, deny("aggregation stage %s is not permitted", name)
			}
			if err = r.scan(spec); err == nil {
				ns = spec
			}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, docValue(buildDoc(valElem(name, ns))))
	}
	if inject && !scopedFirst {
		m := docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$match", r.tenantDoc(t))))
		out = append([]value{m}, out...)
	}
	return arrayOf(out...), nil
}

func (r *Rewriter) scan(v value) error {
	if r.js {
		return nil
	}
	return scanForbidden(v)
}

// checkFrom validates the "from" of $lookup/$graphLookup: a collection in an
// accessible database.
func (r *Rewriter) checkFrom(v value) error {
	switch v.Type {
	case bsoncore.TypeString:
		return checkCollName(v.StringValue())
	case bsoncore.TypeEmbeddedDocument:
		d := v.Document()
		db, ok1 := d.Lookup("db").StringValueOK()
		coll, ok2 := d.Lookup("coll").StringValueOK()
		if !ok1 || !ok2 {
			return badValue("from must contain db and coll")
		}
		if !r.dbAllowed(db) {
			return deny("database %q is not accessible", db)
		}
		return checkCollName(coll)
	}
	return badValue("from must be a collection name")
}

func (r *Rewriter) rewriteLookup(t *Tenant, spec value) (value, error) {
	d, ok := spec.DocumentOK()
	if !ok {
		return value{}, badValue("$lookup requires a document")
	}
	elems, err := d.Elements()
	if err != nil {
		return value{}, badValue("malformed $lookup")
	}
	if err := checkNoDuplicateKeys(elems); err != nil {
		return value{}, err
	}
	out := make([]byte, 4, len(d)+64)
	hasFrom, hasPipeline := false, false
	for _, e := range elems {
		switch e.Key() {
		case "from":
			if err := r.checkFrom(e.Value()); err != nil {
				return value{}, err
			}
			hasFrom = true
			out = append(out, e...)
		case "pipeline":
			p, ok := e.Value().ArrayOK()
			if !ok {
				return value{}, badValue("$lookup pipeline must be an array")
			}
			np, err := r.scopePipeline(t, p, true, nil)
			if err != nil {
				return value{}, err
			}
			hasPipeline = true
			out = bsoncore.AppendArrayElement(out, "pipeline", np)
		case "let":
			if err := r.scan(e.Value()); err != nil {
				return value{}, err
			}
			out = append(out, e...)
		default:
			out = append(out, e...)
		}
	}
	if !hasFrom {
		return value{}, deny("$lookup without from is not permitted")
	}
	if !hasPipeline {
		// MongoDB 5.0+ allows localField/foreignField together with a pipeline.
		np, _ := r.scopePipeline(t, arrayOf(), true, nil)
		out = bsoncore.AppendArrayElement(out, "pipeline", np)
	}
	return docValue(finishDoc(out)), nil
}

func (r *Rewriter) rewriteGraphLookup(t *Tenant, spec value) (value, error) {
	d, ok := spec.DocumentOK()
	if !ok {
		return value{}, badValue("$graphLookup requires a document")
	}
	elems, err := d.Elements()
	if err != nil {
		return value{}, badValue("malformed $graphLookup")
	}
	if err := checkNoDuplicateKeys(elems); err != nil {
		return value{}, err
	}
	hasFrom := false
	for _, e := range elems {
		if e.Key() == "from" {
			if err := r.checkFrom(e.Value()); err != nil {
				return value{}, err
			}
			hasFrom = true
		}
	}
	if !hasFrom {
		return value{}, deny("$graphLookup without from is not permitted")
	}
	nd, err := r.scopeField(&request{t: t}, d, "restrictSearchWithMatch")
	if err != nil {
		return value{}, err
	}
	return docValue(nd), nil
}

func (r *Rewriter) rewriteUnionWith(t *Tenant, spec value) (value, error) {
	scoped, _ := r.scopePipeline(t, arrayOf(), true, nil)
	switch spec.Type {
	case bsoncore.TypeString:
		if err := checkCollName(spec.StringValue()); err != nil {
			return value{}, err
		}
		return docValue(buildDoc(
			bsoncore.AppendStringElement(nil, "coll", spec.StringValue()),
			bsoncore.AppendArrayElement(nil, "pipeline", scoped),
		)), nil
	case bsoncore.TypeEmbeddedDocument:
		d := spec.Document()
		elems, err := d.Elements()
		if err != nil {
			return value{}, badValue("malformed $unionWith")
		}
		if err := checkNoDuplicateKeys(elems); err != nil {
			return value{}, err
		}
		out := make([]byte, 4, len(d)+64)
		hasColl, hasPipeline := false, false
		for _, e := range elems {
			switch e.Key() {
			case "coll":
				s, ok := e.Value().StringValueOK()
				if !ok {
					return value{}, badValue("$unionWith coll must be a string")
				}
				if err := checkCollName(s); err != nil {
					return value{}, err
				}
				hasColl = true
				out = append(out, e...)
			case "pipeline":
				p, ok := e.Value().ArrayOK()
				if !ok {
					return value{}, badValue("$unionWith pipeline must be an array")
				}
				np, err := r.scopePipeline(t, p, true, nil)
				if err != nil {
					return value{}, err
				}
				hasPipeline = true
				out = bsoncore.AppendArrayElement(out, "pipeline", np)
			default:
				out = append(out, e...)
			}
		}
		if !hasColl {
			return value{}, deny("$unionWith without coll is not permitted")
		}
		if !hasPipeline {
			out = bsoncore.AppendArrayElement(out, "pipeline", scoped)
		}
		return docValue(finishDoc(out)), nil
	}
	return value{}, badValue("$unionWith requires a collection or document")
}

func (r *Rewriter) rewriteFacet(t *Tenant, spec value) (value, error) {
	d, ok := spec.DocumentOK()
	if !ok {
		return value{}, badValue("$facet requires a document")
	}
	elems, err := d.Elements()
	if err != nil {
		return value{}, badValue("malformed $facet")
	}
	out := make([]byte, 4, len(d)+16)
	for _, e := range elems {
		p, ok := e.Value().ArrayOK()
		if !ok {
			return value{}, badValue("$facet branch %q must be an array", e.Key())
		}
		np, err := r.scopePipeline(t, p, false, nil)
		if err != nil {
			return value{}, err
		}
		out = bsoncore.AppendArrayElement(out, e.Key(), np)
	}
	return docValue(finishDoc(out)), nil
}

// rewriteChangeStream expands $changeStream into a tenant-safe sequence:
//
//  1. $changeStream with pre/post images forced on, so every insert, update,
//     replace and delete event carries the tenant field;
//  2. a $match on those images, placed before any client stage;
//  3. stages that reshape events back to what the client asked for.
//
// Events without a tenant image (drop, rename, invalidate, ...) are dropped.
func (r *Rewriter) rewriteChangeStream(t *Tenant, spec value, dbLevel bool) ([]value, error) {
	d, ok := spec.DocumentOK()
	if !ok {
		return nil, badValue("$changeStream requires a document")
	}
	elems, err := d.Elements()
	if err != nil {
		return nil, badValue("malformed $changeStream")
	}
	if err := checkNoDuplicateKeys(elems); err != nil {
		return nil, err
	}
	clientFull, clientBefore := "default", "off"
	out := make([]byte, 4, len(d)+64)
	for _, e := range elems {
		switch e.Key() {
		case "allChangesForCluster":
			return nil, deny("cluster-wide change streams are not permitted")
		case "fullDocument":
			clientFull, _ = e.Value().StringValueOK()
		case "fullDocumentBeforeChange":
			clientBefore, _ = e.Value().StringValueOK()
		default:
			out = append(out, e...)
		}
	}
	// Database-level streams span collections that may not have images yet;
	// events without an image carry no tenant and are dropped by the $match.
	mode := "required"
	if dbLevel {
		mode = "whenAvailable"
	}
	out = bsoncore.AppendStringElement(out, "fullDocument", mode)
	out = bsoncore.AppendStringElement(out, "fullDocumentBeforeChange", mode)
	stages := []value{docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$changeStream", finishDoc(out))))}

	lifecycle := arrayOf(
		value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "drop")},
		value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "rename")},
		value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "dropDatabase")},
		value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "invalidate")},
	)
	match := arrayOf(
		docValue(buildDoc(valElem("fullDocument."+r.field, t.Value))),
		docValue(buildDoc(valElem("fullDocumentBeforeChange."+r.field, t.Value))),
		// Lifecycle events hold no document data and apply to every tenant.
		docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "operationType",
			buildDoc(bsoncore.AppendArrayElement(nil, "$in", lifecycle))))),
	)
	filter := buildDoc(bsoncore.AppendArrayElement(nil, "$or", match))
	if dbLevel {
		// Never expose the proxy's own bookkeeping collections.
		internal := buildDoc(bsoncore.AppendDocumentElement(nil, "ns.coll", buildDoc(
			bsoncore.AppendDocumentElement(nil, "$not", buildDoc(
				bsoncore.AppendStringElement(nil, "$regex", "^__mtp_"))))))
		filter = buildDoc(bsoncore.AppendArrayElement(nil, "$and", arrayOf(docValue(internal), docValue(filter))))
	}
	stages = append(stages, docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$match", filter))))

	if clientBefore == "off" {
		stages = append(stages, docValue(buildDoc(bsoncore.AppendStringElement(nil, "$unset", "fullDocumentBeforeChange"))))
	}
	if clientFull == "default" {
		// Plain streams only expose fullDocument for inserts and replaces.
		cond := buildDoc(bsoncore.AppendArrayElement(nil, "$cond", arrayOf(
			docValue(buildDoc(bsoncore.AppendArrayElement(nil, "$eq", arrayOf(
				value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "$operationType")},
				value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "update")},
			)))),
			value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "$$REMOVE")},
			value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "$fullDocument")},
		)))
		stages = append(stages, docValue(buildDoc(bsoncore.AppendDocumentElement(nil, "$set",
			buildDoc(bsoncore.AppendDocumentElement(nil, "fullDocument", cond))))))
	}
	return stages, nil
}
