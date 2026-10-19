package rewrite

import (
	"fmt"
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

type (
	doc   = bsoncore.Document
	arr   = bsoncore.Array
	value = bsoncore.Value
)

func docValue(d doc) value { return value{Type: bsoncore.TypeEmbeddedDocument, Data: d} }
func arrValue(a arr) value { return value{Type: bsoncore.TypeArray, Data: a} }

func buildDoc(elems ...[]byte) doc { return bsoncore.BuildDocument(nil, elems...) }

func valElem(key string, v value) []byte { return bsoncore.AppendValueElement(nil, key, v) }

func arrayOf(vals ...value) arr { return bsoncore.BuildArray(nil, vals...) }

// forbiddenKeys are server-side JavaScript entry points. They cannot reach
// other tenants' data, but they run arbitrary code inside mongod, so they are
// rejected unless explicitly allowed.
var forbiddenKeys = map[string]struct{}{
	"$where":       {},
	"$function":    {},
	"$accumulator": {},
}

// scanForbidden walks a value and returns an error if any document key is a
// server-side JavaScript operator.
func scanForbidden(v value) error {
	switch v.Type {
	case bsoncore.TypeEmbeddedDocument:
		return scanDoc(v.Document())
	case bsoncore.TypeArray:
		return scanArr(v.Array())
	}
	return nil
}

func scanDoc(d doc) error {
	elems, err := d.Elements()
	if err != nil {
		return badValue("malformed document: %v", err)
	}
	for _, e := range elems {
		k := e.Key()
		if _, bad := forbiddenKeys[k]; bad {
			return deny("operator %s is not permitted", k)
		}
		if err := scanForbidden(e.Value()); err != nil {
			return err
		}
	}
	return nil
}

func scanArr(a arr) error {
	vals, err := a.Values()
	if err != nil {
		return badValue("malformed array: %v", err)
	}
	for _, v := range vals {
		if err := scanForbidden(v); err != nil {
			return err
		}
	}
	return nil
}

// setField returns d with key set to fn(old). old is nil when the field is
// absent. If fn returns ok=false the field is removed. The original document
// is never modified.
func setField(d doc, key string, fn func(old *value) (value, bool, error)) (doc, error) {
	elems, err := d.Elements()
	if err != nil {
		return nil, badValue("malformed command: %v", err)
	}
	out := make([]byte, 4, len(d)+64)
	found := false
	for _, e := range elems {
		if e.Key() != key {
			out = append(out, e...)
			continue
		}
		if found {
			return nil, badValue("duplicate field %q", key)
		}
		found = true
		old := e.Value()
		nv, keep, err := fn(&old)
		if err != nil {
			return nil, err
		}
		if keep {
			out = bsoncore.AppendValueElement(out, key, nv)
		}
	}
	if !found {
		nv, keep, err := fn(nil)
		if err != nil {
			return nil, err
		}
		if keep {
			out = bsoncore.AppendValueElement(out, key, nv)
		}
	}
	return finishDoc(out), nil
}

// finishDoc terminates and length-prefixes a document built after a 4-byte
// placeholder.
func finishDoc(b []byte) doc {
	b = append(b, 0)
	safeconv.PutLen(b, len(b))
	return b
}

// mapDocs applies fn to every document in an array of documents.
func mapDocs(a arr, fn func(doc) (doc, error)) (arr, error) {
	vals, err := a.Values()
	if err != nil {
		return nil, badValue("malformed array: %v", err)
	}
	out := make([]value, len(vals))
	for i, v := range vals {
		d, ok := v.DocumentOK()
		if !ok {
			return nil, badValue("array element %d must be a document", i)
		}
		nd, err := fn(d)
		if err != nil {
			return nil, err
		}
		out[i] = docValue(nd)
	}
	return arrayOf(out...), nil
}

// checkNoDuplicateKeys rejects documents with repeated top-level keys, which
// different server code paths resolve differently.
func checkNoDuplicateKeys(elems []bsoncore.Element) error {
	if len(elems) < 2 {
		return nil
	}
	seen := make(map[string]struct{}, len(elems))
	for _, e := range elems {
		k := e.Key()
		if _, dup := seen[k]; dup {
			return badValue("duplicate field %q in command", k)
		}
		seen[k] = struct{}{}
	}
	return nil
}

// Error is a rejection that is reported to the client as a MongoDB error.
type Error struct {
	Code     int32
	CodeName string
	Msg      string
}

func (e *Error) Error() string { return e.Msg }

func deny(format string, a ...any) error {
	return &Error{Code: 13, CodeName: "Unauthorized", Msg: "tenant proxy: " + fmt.Sprintf(format, a...)}
}

func badValue(format string, a ...any) error {
	return &Error{Code: 2, CodeName: "BadValue", Msg: "tenant proxy: " + fmt.Sprintf(format, a...)}
}

// ValidateBody rejects command documents that are malformed, nested deeper than
// the server allows, or repeat a top-level key.
func ValidateBody(body bsoncore.Document) error {
	if err := validateDeep(body, 0); err != nil {
		return err
	}
	elems, err := body.Elements()
	if err != nil || len(elems) == 0 {
		return badValue("malformed command document")
	}
	return checkNoDuplicateKeys(elems)
}

// Limits. MongoDB itself rejects documents nested deeper than 100 levels and
// pipelines longer than 1000 stages; enforcing them here keeps the rewriter's
// recursive walks (which run on untrusted input before the server sees it)
// bounded, and gives the client a clear error instead of a stack overflow.
const (
	maxBSONDepth      = 100
	maxPipelineStages = 1000
)

// validateDeep checks that d is a well-formed BSON document no deeper than
// maxBSONDepth, without recursion beyond that bound. Everything the rewriter
// later reads with the panicking bsoncore accessors (Value.StringValue,
// Value.Document, ...) is therefore known to be structurally sound.
func validateDeep(d []byte, depth int) error {
	if depth > maxBSONDepth {
		return badValue("document nesting exceeds %d levels", maxBSONDepth)
	}
	length, _, ok := bsoncore.ReadLength(d)
	if !ok || length < 5 || int(length) != len(d) || d[len(d)-1] != 0 {
		return badValue("malformed BSON document")
	}
	rem := d[4 : len(d)-1]
	for len(rem) > 0 {
		var e bsoncore.Element
		e, rem, ok = bsoncore.ReadElement(rem)
		if !ok {
			return badValue("malformed BSON element")
		}
		switch bsoncore.Type(e[0]) {
		case bsoncore.TypeEmbeddedDocument, bsoncore.TypeArray:
			// Validate the container's own framing and recurse ourselves so the
			// depth bound applies.
			if err := validateDeep(e.Value().Data, depth+1); err != nil {
				return err
			}
		case bsoncore.TypeCodeWithScope:
			return badValue("code with scope is not supported")
		case bsoncore.TypeString, bsoncore.TypeJavaScript, bsoncore.TypeSymbol:
			// bsoncore's own validation accepts a zero length prefix, which
			// its panicking string accessors then trip over.
			if _, _, ok := bsoncore.ReadString(e.Value().Data); !ok {
				return badValue("malformed BSON string")
			}
			if err := e.Validate(); err != nil {
				return badValue("malformed BSON element: %v", err)
			}
		default:
			if err := e.Validate(); err != nil {
				return badValue("malformed BSON element: %v", err)
			}
		}
	}
	return nil
}

func validateCommand(body []byte, seqs []wire.Seq) error {
	if err := validateDeep(body, 0); err != nil {
		return err
	}
	for _, s := range seqs {
		for _, d := range s.Docs {
			if err := validateDeep(d, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkCollation rejects collations under which two different tenant ids can
// compare equal. The tenant filter is an ordinary equality on a string field,
// so a client-chosen case/diacritic-insensitive collation would make the
// filter for tenant "acme" also match tenant "ACME".
func checkCollation(v value) error {
	d, ok := v.DocumentOK()
	if !ok {
		return badValue("collation must be a document")
	}
	els, err := d.Elements()
	if err != nil {
		return badValue("malformed collation")
	}
	for _, e := range els {
		switch e.Key() {
		case "locale":
			if s, ok := e.Value().StringValueOK(); ok && s == "simple" {
				return nil // binary comparison; the remaining options are ignored
			}
		}
	}
	for _, e := range els {
		switch e.Key() {
		case "strength":
			n, ok := e.Value().AsInt64OK()
			if !ok || n < 3 {
				return deny("collation strength below 3 is not permitted: it would make tenant ids compare equal")
			}
		case "alternate":
			if s, ok := e.Value().StringValueOK(); !ok || s != "non-ignorable" {
				return deny("collation alternate=%v is not permitted: it would make tenant ids compare equal", e.Value())
			}
		case "numericOrdering":
			if b, ok := e.Value().BooleanOK(); !ok || b {
				return deny("collation numericOrdering is not permitted: it would make tenant ids compare equal")
			}
		}
	}
	return nil
}

// CheckCollation validates a collation a tenant supplied (see checkCollation).
func CheckCollation(v bsoncore.Value) error { return checkCollation(v) }
