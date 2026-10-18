package rewrite

import (
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// guard is an independent checker for the rewriter's output. It does not share
// code with the rewriter: it walks the *rewritten* command and proves that every
// read it can perform is confined to the tenant, and that nothing it writes can
// carry another tenant's id. It is deliberately strict (it accepts exactly the
// shapes the rewriter is meant to emit), so a refactor that weakens the output
// shows up as a guard failure.
type guard struct {
	r *Rewriter
	t *Tenant
	// view is set for RewriteView output: the top-level read targets a tenant's
	// own view, so the top-level filter/first stage need not be guarded.
	view bool
}

func (g *guard) isTenantDoc(d bsoncore.Document) bool {
	els, err := d.Elements()
	return err == nil && len(els) == 1 && els[0].Key() == g.r.field && els[0].Value().Equal(g.t.Value)
}

// filterGuarded accepts {tenant} or {$and: [{tenant}, anything]}.
func (g *guard) filterGuarded(v bsoncore.Value) error {
	d, ok := v.DocumentOK()
	if !ok {
		return fmt.Errorf("filter is not a document: %v", v.Type)
	}
	if g.isTenantDoc(d) {
		return nil
	}
	els, err := d.Elements()
	if err != nil || len(els) != 1 || els[0].Key() != "$and" {
		return fmt.Errorf("filter is not tenant-guarded: %s", d)
	}
	a, ok := els[0].Value().ArrayOK()
	if !ok {
		return fmt.Errorf("$and is not an array")
	}
	vals, err := a.Values()
	if err != nil || len(vals) != 2 {
		return fmt.Errorf("$and has wrong arity")
	}
	first, ok := vals[0].DocumentOK()
	if !ok || !g.isTenantDoc(first) {
		return fmt.Errorf("$and does not start with the tenant constraint")
	}
	return nil
}

var guardSafeStages = map[string]bool{
	"$addFields": true, "$bucket": true, "$bucketAuto": true, "$count": true, "$densify": true,
	"$fill": true, "$group": true, "$limit": true, "$match": true, "$project": true, "$redact": true,
	"$replaceRoot": true, "$replaceWith": true, "$sample": true, "$set": true, "$setWindowFields": true,
	"$skip": true, "$sort": true, "$sortByCount": true, "$unset": true, "$unwind": true,
}

func (g *guard) noJS(v bsoncore.Value) error {
	if g.r.js {
		return nil
	}
	return jsFree(v)
}

func jsFree(v bsoncore.Value) error {
	switch v.Type {
	case bsoncore.TypeEmbeddedDocument:
		els, err := v.Document().Elements()
		if err != nil {
			return err
		}
		for _, e := range els {
			switch e.Key() {
			case "$where", "$function", "$accumulator":
				return fmt.Errorf("server-side JavaScript operator %s in output", e.Key())
			}
			if err := jsFree(e.Value()); err != nil {
				return err
			}
		}
	case bsoncore.TypeArray:
		vals, err := v.Array().Values()
		if err != nil {
			return err
		}
		for _, x := range vals {
			if err := jsFree(x); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *guard) stageParts(s bsoncore.Value) (string, bsoncore.Value, error) {
	sd, ok := s.DocumentOK()
	if !ok {
		return "", bsoncore.Value{}, fmt.Errorf("stage is not a document")
	}
	els, err := sd.Elements()
	if err != nil || len(els) != 1 {
		return "", bsoncore.Value{}, fmt.Errorf("stage must have exactly one field")
	}
	return els[0].Key(), els[0].Value(), nil
}

// pipeline proves a pipeline only reads tenant documents. injected is true when
// the pipeline reads straight from a collection (first stage must guard);
// false for $facet branches, whose input is already guarded.
func (g *guard) pipeline(a bsoncore.Array, injected, top bool) error {
	stages, err := a.Values()
	if err != nil {
		return err
	}
	for i, s := range stages {
		name, spec, err := g.stageParts(s)
		if err != nil {
			return fmt.Errorf("stage %d: %w", i, err)
		}
		if i == 0 && injected {
			switch name {
			case "$match":
				if err := g.filterGuarded(spec); err != nil {
					return fmt.Errorf("first $match: %w", err)
				}
			case "$geoNear":
				// checked below; query must be guarded
			case "$changeStream":
				if i+1 >= len(stages) {
					return fmt.Errorf("$changeStream without tenant $match")
				}
				_, next, err := g.stageParts(stages[i+1])
				if err != nil || !strings.Contains(next.String(), "fullDocument."+g.r.field) {
					return fmt.Errorf("$changeStream not followed by the tenant $match")
				}
			default:
				return fmt.Errorf("first stage %s is not tenant-guarded", name)
			}
		}
		switch {
		case name == "$changeStream":
			if i != 0 || !injected {
				return fmt.Errorf("$changeStream outside first position")
			}
			if err := g.noJS(spec); err != nil {
				return err
			}
		case guardSafeStages[name]:
			if err := g.noJS(spec); err != nil {
				return err
			}
		case name == "$geoNear":
			d, ok := spec.DocumentOK()
			if !ok {
				return fmt.Errorf("$geoNear spec")
			}
			q := d.Lookup("query")
			if err := g.filterGuarded(q); err != nil {
				return fmt.Errorf("$geoNear query: %w", err)
			}
			if err := g.noJS(spec); err != nil {
				return err
			}
		case name == "$lookup":
			d, ok := spec.DocumentOK()
			if !ok {
				return fmt.Errorf("$lookup spec")
			}
			if d.Lookup("from").Type == 0 {
				return fmt.Errorf("$lookup without from")
			}
			p, ok := d.Lookup("pipeline").ArrayOK()
			if !ok {
				return fmt.Errorf("$lookup without pipeline would read an unscoped collection")
			}
			if err := g.pipeline(p, true, false); err != nil {
				return fmt.Errorf("$lookup.pipeline: %w", err)
			}
			if err := g.checkFromLegal(d.Lookup("from")); err != nil {
				return err
			}
			if err := g.noJS(spec); err != nil {
				return err
			}
		case name == "$graphLookup":
			d, ok := spec.DocumentOK()
			if !ok {
				return fmt.Errorf("$graphLookup spec")
			}
			if err := g.filterGuarded(d.Lookup("restrictSearchWithMatch")); err != nil {
				return fmt.Errorf("$graphLookup.restrictSearchWithMatch: %w", err)
			}
			if err := g.checkFromLegal(d.Lookup("from")); err != nil {
				return err
			}
			if err := g.noJS(spec); err != nil {
				return err
			}
		case name == "$unionWith":
			d, ok := spec.DocumentOK()
			if !ok {
				return fmt.Errorf("$unionWith must be a document in output")
			}
			c, ok := d.Lookup("coll").StringValueOK()
			if !ok || checkCollName(c) != nil {
				return fmt.Errorf("$unionWith.coll")
			}
			p, ok := d.Lookup("pipeline").ArrayOK()
			if !ok {
				return fmt.Errorf("$unionWith without pipeline")
			}
			if err := g.pipeline(p, true, false); err != nil {
				return fmt.Errorf("$unionWith.pipeline: %w", err)
			}
			if err := g.noJS(spec); err != nil {
				return err
			}
		case name == "$facet":
			d, ok := spec.DocumentOK()
			if !ok {
				return fmt.Errorf("$facet spec")
			}
			els, err := d.Elements()
			if err != nil {
				return err
			}
			for _, e := range els {
				p, ok := e.Value().ArrayOK()
				if !ok {
					return fmt.Errorf("$facet branch not an array")
				}
				// A branch only sees the already-guarded stream, but its own
				// nested reads must be guarded.
				if err := g.pipeline(p, false, false); err != nil {
					return fmt.Errorf("$facet.%s: %w", e.Key(), err)
				}
			}
		case name == "$merge":
			if !top || i != len(stages)-1 {
				return fmt.Errorf("$merge outside last position of a top-level aggregate")
			}
			d, ok := spec.DocumentOK()
			if !ok {
				return fmt.Errorf("$merge spec")
			}
			on, ok := d.Lookup("on").ArrayOK()
			if !ok {
				return fmt.Errorf("$merge without on")
			}
			ov, _ := on.Values()
			if len(ov) == 0 {
				return fmt.Errorf("$merge on empty")
			}
			if s, _ := ov[0].StringValueOK(); s != g.r.field {
				return fmt.Errorf("$merge on does not start with the tenant field")
			}
			into, ok := d.Lookup("into").DocumentOK()
			if ic, ok2 := into.Lookup("coll").StringValueOK(); !ok || !ok2 || checkCollName(ic) != nil {
				return fmt.Errorf("$merge into")
			}
			// Some stage before must stamp the tenant, and nothing between the
			// stamp and the merge may undo it (only $set marker stages).
			stamped := false
			for j := i - 1; j >= 0; j-- {
				n2, sp2, _ := g.stageParts(stages[j])
				if n2 == "$set" {
					if sd, ok := sp2.DocumentOK(); ok && g.isTenantDoc(sd) {
						stamped = true
						break
					}
					if sd, ok := sp2.DocumentOK(); ok && sd.Lookup(outMarker).Type != 0 {
						continue
					}
				}
				break
			}
			if !stamped {
				return fmt.Errorf("$merge not preceded by the tenant stamp")
			}
			if wm := d.Lookup("whenMatched"); wm.Type == bsoncore.TypeArray {
				if err := g.updatePipeline(wm.Array()); err != nil {
					return fmt.Errorf("$merge.whenMatched: %w", err)
				}
			}
			if err := g.noJS(spec); err != nil {
				return err
			}
		default:
			return fmt.Errorf("stage %s must not appear in output", name)
		}
	}
	return nil
}

func (g *guard) checkFromLegal(v bsoncore.Value) error {
	switch v.Type {
	case bsoncore.TypeString:
		return checkCollName(v.StringValue())
	case bsoncore.TypeEmbeddedDocument:
		d := v.Document()
		db, ok1 := d.Lookup("db").StringValueOK()
		c, ok2 := d.Lookup("coll").StringValueOK()
		if !ok1 || !ok2 || !g.r.dbAllowed(db) {
			return fmt.Errorf("illegal from")
		}
		return checkCollName(c)
	}
	return fmt.Errorf("from has illegal type %v", v.Type)
}

// updatePipeline: last stage must restore the tenant, stages must be update-safe.
func (g *guard) updatePipeline(a bsoncore.Array) error {
	stages, err := a.Values()
	if err != nil || len(stages) == 0 {
		return fmt.Errorf("empty update pipeline")
	}
	for i, s := range stages {
		name, spec, err := g.stageParts(s)
		if err != nil {
			return err
		}
		if _, ok := pipelineUpdateStages[name]; !ok {
			return fmt.Errorf("update pipeline stage %s", name)
		}
		if err := g.noJS(spec); err != nil {
			return err
		}
		if i == len(stages)-1 {
			sd, ok := spec.DocumentOK()
			if name != "$set" || !ok || !g.isTenantDoc(sd) {
				return fmt.Errorf("update pipeline does not end by re-asserting the tenant")
			}
		}
	}
	return nil
}

func (g *guard) update(u bsoncore.Value) error {
	switch u.Type {
	case bsoncore.TypeArray:
		return g.updatePipeline(u.Array())
	case bsoncore.TypeEmbeddedDocument:
		els, err := u.Document().Elements()
		if err != nil {
			return err
		}
		if len(els) > 0 && strings.HasPrefix(els[0].Key(), "$") {
			for _, op := range els {
				od, ok := op.Value().DocumentOK()
				if !ok {
					return fmt.Errorf("operator %s without document", op.Key())
				}
				fs, err := od.Elements()
				if err != nil {
					return err
				}
				for _, f := range fs {
					if g.r.touchesTenant(f.Key()) {
						return fmt.Errorf("update %s touches the tenant field", op.Key())
					}
					if to, ok := f.Value().StringValueOK(); ok && op.Key() == "$rename" && g.r.touchesTenant(to) {
						return fmt.Errorf("$rename onto the tenant field")
					}
				}
			}
			return nil
		}
		return g.stamped(u.Document())
	}
	return fmt.Errorf("update has type %v", u.Type)
}

// stamped: document carries the tenant, and every tenant key equals it.
func (g *guard) stamped(d bsoncore.Document) error {
	els, err := d.Elements()
	if err != nil {
		return err
	}
	n := 0
	for _, e := range els {
		if e.Key() == g.r.field {
			n++
			if !e.Value().Equal(g.t.Value) {
				return fmt.Errorf("document carries another tenant id")
			}
		}
	}
	if n == 0 {
		return fmt.Errorf("document not stamped")
	}
	return nil
}

func safeCollation(v bsoncore.Value) bool {
	d, ok := v.DocumentOK()
	if !ok {
		return false
	}
	if loc, _ := d.Lookup("locale").StringValueOK(); loc == "simple" {
		return true
	}
	if s, ok := d.Lookup("strength").AsInt64OK(); (d.Lookup("strength").Type != 0 && !ok) || (ok && s < 3) {
		return false
	}
	if a := d.Lookup("alternate"); a.Type != 0 {
		if s, _ := a.StringValueOK(); s != "non-ignorable" {
			return false
		}
	}
	return true
}

// check validates a Result produced by Rewrite (cmd = the command that was sent).
func (g *guard) check(cmd string, res *Result, seqs []wire.Seq) error {
	if res.Reply != nil {
		return res.Reply.Validate()
	}
	if err := res.Body.Validate(); err != nil {
		return fmt.Errorf("invalid BSON body: %w", err)
	}
	for _, s := range res.Seqs {
		for _, d := range s.Docs {
			if err := d.Validate(); err != nil {
				return fmt.Errorf("invalid BSON in seq %s: %w", s.ID, err)
			}
		}
	}
	for _, c := range append(append([]Command{}, res.Before...), res.After...) {
		if err := c.Body.Validate(); err != nil {
			return fmt.Errorf("invalid housekeeping command: %w", err)
		}
		if a, ok := c.Body.Lookup("indexes").ArrayOK(); ok {
			vs, _ := a.Values()
			for _, v := range vs {
				spec := v.Document()
				if u, _ := spec.Lookup("unique").BooleanOK(); u {
					if ks, _ := spec.Lookup("key").Document().Elements(); len(ks) < 2 {
						return fmt.Errorf("housekeeping unique index on a single field would cap tenants: %s", spec)
					}
				}
			}
		}
	}
	return g.body(cmd, res.Body, res.Seqs)
}

func (g *guard) body(cmd string, b bsoncore.Document, seqs []wire.Seq) error {
	first := CommandName(b)
	want := cmd
	if cmd == "drop" {
		want = "delete"
	}
	if !strings.EqualFold(first, want) {
		return fmt.Errorf("command name moved: got %q want %q", first, want)
	}
	if !g.r.js && cmd != "insert" {
		if err := jsFree(bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: b}); err != nil {
			return err
		}
	}
	if c := b.Lookup("collation"); c.Type != 0 && !safeCollation(c) {
		return fmt.Errorf("unsafe collation in output: %s", c)
	}
	switch cmd {
	case "find":
		if !g.view {
			return g.filterGuarded(b.Lookup("filter"))
		}
	case "count", "distinct":
		if !g.view {
			return g.filterGuarded(b.Lookup("query"))
		}
	case "findAndModify":
		if err := g.filterGuarded(b.Lookup("query")); err != nil {
			return err
		}
		if u := b.Lookup("update"); u.Type != 0 {
			return g.update(u)
		}
	case "aggregate":
		p, ok := b.Lookup("pipeline").ArrayOK()
		if !ok {
			return fmt.Errorf("aggregate without pipeline")
		}
		return g.pipeline(p, !g.view, true)
	case "insert":
		var docs []bsoncore.Document
		if a, ok := b.Lookup("documents").ArrayOK(); ok {
			vs, _ := a.Values()
			for _, v := range vs {
				docs = append(docs, v.Document())
			}
		}
		for _, s := range seqs {
			docs = append(docs, s.Docs...)
		}
		for _, d := range docs {
			if err := g.stamped(d); err != nil {
				return err
			}
		}
	case "update", "delete", "drop":
		key := "updates"
		if cmd != "update" {
			key = "deletes"
		}
		var stmts []bsoncore.Document
		if a, ok := b.Lookup(key).ArrayOK(); ok {
			vs, _ := a.Values()
			for _, v := range vs {
				stmts = append(stmts, v.Document())
			}
		}
		for _, s := range seqs {
			stmts = append(stmts, s.Docs...)
		}
		for _, s := range stmts {
			if c := s.Lookup("collation"); c.Type != 0 && !safeCollation(c) {
				return fmt.Errorf("unsafe statement collation")
			}
			if err := g.filterGuarded(s.Lookup("q")); err != nil {
				return err
			}
			if cmd == "update" {
				if err := g.update(s.Lookup("u")); err != nil {
					return err
				}
			}
		}
	case "explain":
		inner, ok := b.Lookup("explain").DocumentOK()
		if !ok {
			return fmt.Errorf("explain without inner command")
		}
		return g.body(CommandName(inner), inner, nil)
	case "create":
		els, _ := b.Elements()
		for _, e := range els[1:] {
			switch e.Key() {
			case "comment", "writeConcern", "lsid", "txnNumber", "$clusterTime", "$db", "$readPreference",
				"autocommit", "startTransaction", "readConcern", "apiVersion", "apiStrict", "apiDeprecationErrors":
			default:
				return fmt.Errorf("create option %s would reconfigure the shared collection", e.Key())
			}
		}
	case "createIndexes":
		a, _ := b.Lookup("indexes").ArrayOK()
		vs, _ := a.Values()
		for _, v := range vs {
			spec := v.Document()
			if spec.Lookup("expireAfterSeconds").Type != 0 {
				// A TTL index is global to the collection unless confined to the tenant.
				pfe, ok := spec.Lookup("partialFilterExpression").DocumentOK()
				if !ok || !strings.Contains(pfe.String(), g.t.Value.String()) {
					return fmt.Errorf("TTL index is not confined to the tenant")
				}
			}
			if c := spec.Lookup("collation"); c.Type != 0 && !safeCollation(c) {
				return fmt.Errorf("unsafe index collation")
			}
			if u := spec.Lookup("unique"); u.Type != 0 && truthy(u) {
				ks, _ := spec.Lookup("key").Document().Elements()
				only := len(ks) > 0
				for _, k := range ks {
					if !g.r.touchesTenant(k.Key()) {
						only = false
					}
				}
				if only {
					return fmt.Errorf("unique index on the tenant field alone")
				}
			}
			if spec.Lookup("expireAfterSeconds").Type == 0 {
				ks, _ := spec.Lookup("key").Document().Elements()
				if len(ks) == 0 || (ks[0].Key() != g.r.field && !(len(ks) == 1 && ks[0].Key() == "_id")) {
					return fmt.Errorf("non-TTL index key is not tenant-prefixed: %s", spec)
				}
			}
			if n, _ := spec.Lookup("name").StringValueOK(); strings.HasPrefix(n, "mtp_") {
				return fmt.Errorf("index name in reserved namespace")
			}
		}
	}
	return nil
}
