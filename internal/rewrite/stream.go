package rewrite

import "go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

// StreamSpec describes a change stream simple enough to be served by the
// shared fan-out.
type StreamSpec struct {
	FullDocument string
	Before       string
	OpTypes      []string // nil = all operation types
}

// bodyBlockers are aggregate options the fan-out cannot honour.
var bodyBlockers = []string{"collation", "hint", "let", "explain", "allowDiskUse",
	"txnNumber", "startTransaction", "autocommit", "bypassDocumentValidation"}

// streamSpec reports whether the aggregate in q is a fresh, plain change
// stream: `[{$changeStream: {fullDocument?, fullDocumentBeforeChange?}}]`
// optionally followed by one `$match` on operationType. Anything that needs
// the real pipeline engine (resume tokens, projections, ...) returns nil and
// is served by a private server-side stream instead.
func streamSpec(q *request) *StreamSpec {
	for _, k := range bodyBlockers {
		if q.body.Lookup(k).Type != 0 {
			return nil
		}
	}
	pa, ok := q.body.Lookup("pipeline").ArrayOK()
	if !ok {
		return nil
	}
	stages, err := pa.Values()
	if err != nil || len(stages) == 0 || len(stages) > 2 {
		return nil
	}
	first, ok := stages[0].DocumentOK()
	if !ok {
		return nil
	}
	e, err := first.IndexErr(0)
	if err != nil || e.Key() != "$changeStream" {
		return nil
	}
	opts, ok := e.Value().DocumentOK()
	if !ok {
		return nil
	}
	spec := &StreamSpec{FullDocument: "default", Before: "off"}
	els, err := opts.Elements()
	if err != nil {
		return nil
	}
	for _, o := range els {
		v, ok := o.Value().StringValueOK()
		switch o.Key() {
		case "fullDocument":
			if !ok {
				return nil
			}
			spec.FullDocument = v
		case "fullDocumentBeforeChange":
			if !ok {
				return nil
			}
			spec.Before = v
		default:
			return nil // resumeAfter, startAfter, startAtOperationTime, showExpandedEvents, ...
		}
	}
	if len(stages) == 2 {
		m, ok := stages[1].DocumentOK()
		if !ok {
			return nil
		}
		me, err := m.IndexErr(0)
		if err != nil || me.Key() != "$match" {
			return nil
		}
		md, ok := me.Value().DocumentOK()
		if !ok {
			return nil
		}
		fields, err := md.Elements()
		if err != nil || len(fields) != 1 || fields[0].Key() != "operationType" {
			return nil
		}
		spec.OpTypes = opTypes(fields[0].Value())
		if spec.OpTypes == nil {
			return nil
		}
	}
	return spec
}

func opTypes(v bsoncore.Value) []string {
	if s, ok := v.StringValueOK(); ok {
		return []string{s}
	}
	d, ok := v.DocumentOK()
	if !ok {
		return nil
	}
	els, err := d.Elements()
	if err != nil || len(els) != 1 {
		return nil
	}
	switch els[0].Key() {
	case "$eq":
		if s, ok := els[0].Value().StringValueOK(); ok {
			return []string{s}
		}
	case "$in":
		arr, ok := els[0].Value().ArrayOK()
		if !ok {
			return nil
		}
		vals, err := arr.Values()
		if err != nil {
			return nil
		}
		var out []string
		for _, x := range vals {
			s, ok := x.StringValueOK()
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}
