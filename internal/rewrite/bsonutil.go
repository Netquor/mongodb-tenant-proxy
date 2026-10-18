package rewrite

import (
	"fmt"

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
	b[0], b[1], b[2], b[3] = byte(len(b)), byte(len(b)>>8), byte(len(b)>>16), byte(len(b)>>24)
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

// ValidateBody rejects command documents that repeat a top-level key.
func ValidateBody(body bsoncore.Document) error {
	elems, err := body.Elements()
	if err != nil || len(elems) == 0 {
		return badValue("malformed command document")
	}
	return checkNoDuplicateKeys(elems)
}
