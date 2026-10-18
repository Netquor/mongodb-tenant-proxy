package rewrite

import (
	"fmt"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// UsesJS reports whether a client command runs server-side JavaScript
// ($where, $function, $accumulator or mapReduce).
func UsesJS(cmd string, body bsoncore.Document) bool {
	if cmd == "mapReduce" {
		return true
	}
	return scanDoc(body) != nil
}

// maxTimeCmds accept maxTimeMS and get the tenant default when the client
// sends none. Writes other than findAndModify only get the cap applied.
var maxTimeDefaulted = map[string]bool{
	"find": true, "aggregate": true, "count": true, "distinct": true,
	"findAndModify": true, "mapReduce": true, "createIndexes": true,
}
var maxTimeCapped = map[string]bool{"update": true, "delete": true, "insert": true}

// ApplyMaxTime enforces a tenant's maxTimeMS policy on a rewritten command:
// values above cap are clamped, and def is added to commands that have none.
// Change streams and explain are left alone. getMore is never touched.
func ApplyMaxTime(cmd string, body bsoncore.Document, limit, def int64, skipDefault bool) (bsoncore.Document, error) {
	if limit <= 0 && def <= 0 {
		return body, nil
	}
	if !maxTimeDefaulted[cmd] && !maxTimeCapped[cmd] {
		return body, nil
	}
	cur := body.Lookup("maxTimeMS")
	if cur.Type == 0 {
		if def <= 0 || skipDefault || !maxTimeDefaulted[cmd] {
			return body, nil
		}
		v := def
		if limit > 0 && v > limit {
			v = limit
		}
		out := append([]byte{}, body[:len(body)-1]...)
		out = bsoncore.AppendInt64Element(out, "maxTimeMS", v)
		out = append(out, 0)
		n := len(out)
		out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
		return out, nil
	}
	n, ok := cur.AsInt64OK()
	if !ok {
		return nil, badValue("maxTimeMS must be a number")
	}
	if limit > 0 && (n == 0 || n > limit) {
		return setField(body, "maxTimeMS", func(*value) (value, bool, error) {
			return value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, limit)}, true, nil
		})
	}
	return body, nil
}

// IndexNames returns "<db>.<coll>#<name>" for every index a createIndexes
// command (as sent by the client) would create.
func IndexNames(db string, body bsoncore.Document) []string {
	coll, _ := body.Index(0).Value().StringValueOK()
	arr, ok := body.Lookup("indexes").ArrayOK()
	if !ok {
		return nil
	}
	vals, _ := arr.Values()
	var out []string
	for _, v := range vals {
		spec, ok := v.DocumentOK()
		if !ok {
			continue
		}
		out = append(out, db+"."+coll+"#"+indexName(spec))
	}
	return out
}

// DroppedIndex returns the identifier of the index a dropIndexes command
// names, or "" if it cannot be determined.
func DroppedIndex(db string, body bsoncore.Document) string {
	coll, _ := body.Index(0).Value().StringValueOK()
	idx := body.Lookup("index")
	switch idx.Type {
	case bsoncore.TypeString:
		return db + "." + coll + "#" + idx.StringValue()
	case bsoncore.TypeEmbeddedDocument:
		return db + "." + coll + "#" + keyName(idx.Document())
	}
	return ""
}

func indexName(spec bsoncore.Document) string {
	if n, ok := spec.Lookup("name").StringValueOK(); ok && n != "" {
		return n
	}
	if k, ok := spec.Lookup("key").DocumentOK(); ok {
		return keyName(k)
	}
	return "?"
}

// keyName builds MongoDB's default index name, e.g. {a:1,b:-1} -> "a_1_b_-1".
func keyName(key bsoncore.Document) string {
	els, _ := key.Elements()
	parts := make([]string, 0, len(els)*2)
	for _, e := range els {
		parts = append(parts, e.Key())
		v := e.Value()
		if s, ok := v.StringValueOK(); ok {
			parts = append(parts, s)
		} else if f, ok := v.AsFloat64OK(); ok {
			parts = append(parts, strconv.FormatFloat(f, 'f', -1, 64))
		} else if n, ok := v.AsInt64OK(); ok {
			parts = append(parts, fmt.Sprint(n))
		} else {
			parts = append(parts, "?")
		}
	}
	return strings.Join(parts, "_")
}
