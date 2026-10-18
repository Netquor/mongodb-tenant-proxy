package rewrite

import (
	"bytes"
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// fuzzRewriters are the configurations every input is run through.
func fuzzRewriters() []*Rewriter {
	return []*Rewriter{
		New(Config{}),
		New(Config{AllowJS: true, ChangeStreams: true}),
		New(Config{Databases: []string{"app"}, ChangeStreams: true}),
	}
}

func fuzzTenants() []*Tenant {
	a, _ := NewTenant("string", "T1")
	b, _ := NewTenant("objectId", "0123456789abcdef01234567")
	c, _ := NewTenant("int", "42")
	return []*Tenant{a, b, c}
}

// runRewrite exercises Rewrite and RewriteView on one input and checks every
// property. It returns an error describing the first violated property.
func runRewrite(r *Rewriter, ten *Tenant, db string, body bsoncore.Document, seqs []wire.Seq) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("PANIC: %v", p)
		}
	}()
	bodyCopy := append([]byte(nil), body...)
	seqCopy := make([][]byte, 0)
	for _, s := range seqs {
		for _, d := range s.Docs {
			seqCopy = append(seqCopy, append([]byte(nil), d...))
		}
	}
	g := &guard{r: r, t: ten}
	cmd := CommandName(body)
	if a, ok := aliases[cmd]; ok {
		cmd = a
	}
	res, rerr := r.Rewrite(ten, db, body, seqs)
	if rerr == nil {
		if cerr := g.check(cmd, res, seqs); cerr != nil {
			return fmt.Errorf("Rewrite(%s): %w\n in:  %s\n out: %s", cmd, cerr, bson.Raw(body), bson.Raw(res.Body))
		}
	}
	// View path: only reads, and only with a physical name the proxy chose.
	vres, verr := r.RewriteView(ten, db, body, seqs, "__mtp_v.abc.view")
	if verr == nil {
		vg := &guard{r: r, t: ten, view: true}
		if cerr := vg.check(cmd, vres, seqs); cerr != nil {
			return fmt.Errorf("RewriteView(%s): %w\n in:  %s\n out: %s", cmd, cerr, bson.Raw(body), bson.Raw(vres.Body))
		}
	}
	if !bytes.Equal(bodyCopy, body) {
		return fmt.Errorf("Rewrite mutated its input body")
	}
	i := 0
	for _, s := range seqs {
		for _, d := range s.Docs {
			if !bytes.Equal(seqCopy[i], d) {
				return fmt.Errorf("Rewrite mutated an input sequence document")
			}
			i++
		}
	}
	return nil
}

func runAll(t *testing.T, db string, body bsoncore.Document, seqs []wire.Seq) {
	t.Helper()
	for _, r := range fuzzRewriters() {
		for _, ten := range fuzzTenants() {
			if err := runRewrite(r, ten, db, body, seqs); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func fuzzSeeds() [][]byte {
	cmds := []bson.D{
		{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"a": 1}}},
		{{Key: "count", Value: "c"}, {Key: "query", Value: bson.M{"a": 1}}},
		{{Key: "distinct", Value: "c"}, {Key: "key", Value: "a"}},
		{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{
			bson.M{"$match": bson.M{"a": 1}},
			bson.M{"$lookup": bson.M{"from": "d", "localField": "a", "foreignField": "b", "as": "x"}},
			bson.M{"$facet": bson.M{"f": bson.A{bson.M{"$unionWith": "e"}}}},
			bson.M{"$merge": bson.M{"into": "o", "on": "k", "whenMatched": bson.A{bson.M{"$set": bson.M{"z": 1}}}}},
		}}},
		{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$graphLookup": bson.M{"from": "c", "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g"}}, bson.M{"$out": "x"}}}},
		{{Key: "aggregate", Value: 1}, {Key: "pipeline", Value: bson.A{bson.M{"$changeStream": bson.M{}}}}},
		{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"a": 1}, bson.M{"tenantId": "T1"}}}},
		{{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{
			bson.M{"q": bson.M{"a": 1}, "u": bson.M{"$set": bson.M{"b": 1}}, "upsert": true},
			bson.M{"q": bson.M{}, "u": bson.A{bson.M{"$set": bson.M{"b": 2}}}},
			bson.M{"q": bson.M{}, "u": bson.M{"b": 3}},
		}}},
		{{Key: "delete", Value: "c"}, {Key: "deletes", Value: bson.A{bson.M{"q": bson.M{"a": 1}, "limit": 0}}}},
		{{Key: "findAndModify", Value: "c"}, {Key: "query", Value: bson.M{"a": 1}}, {Key: "update", Value: bson.M{"$inc": bson.M{"n": 1}}}, {Key: "upsert", Value: true}},
		{{Key: "explain", Value: bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{}}}}, {Key: "verbosity", Value: "queryPlanner"}},
		{{Key: "createIndexes", Value: "c"}, {Key: "indexes", Value: bson.A{bson.M{"key": bson.M{"a": 1}, "name": "a_1"}, bson.M{"key": bson.M{"t": 1}, "name": "ttl", "expireAfterSeconds": 10}}}},
		{{Key: "dropIndexes", Value: "c"}, {Key: "index", Value: bson.M{"a": 1}}},
		{{Key: "listIndexes", Value: "c"}},
		{{Key: "listCollections", Value: 1}, {Key: "filter", Value: bson.M{"name": "c"}}},
		{{Key: "create", Value: "c"}, {Key: "capped", Value: true}, {Key: "size", Value: 100}},
		{{Key: "drop", Value: "c"}},
		{{Key: "mapReduce", Value: "c"}, {Key: "map", Value: bson.Symbol("function(){}")}, {Key: "out", Value: bson.M{"inline": 1}}},
	}
	var out [][]byte
	for _, c := range cmds {
		c = append(c, bson.E{Key: "$db", Value: "app"})
		b, err := bson.Marshal(c)
		if err != nil {
			panic(err)
		}
		out = append(out, b)
	}
	return out
}

// FuzzRewriteRaw feeds arbitrary bytes as the command document (and, split at
// the first 0xff, as an OP_MSG document sequence payload).
func FuzzRewriteRaw(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s, []byte(nil))
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, body, seq []byte) {
		var seqs []wire.Seq
		if len(seq) > 0 {
			var docs []bsoncore.Document
			rest := seq
			for len(rest) > 0 {
				d, r, ok := bsoncore.ReadDocument(rest)
				if !ok {
					break
				}
				docs = append(docs, d)
				rest = r
			}
			for _, id := range []string{"documents", "updates", "deletes"} {
				seqs = append(seqs, wire.Seq{ID: id, Docs: docs})
				break
			}
			if len(seq)%3 == 0 {
				seqs[0].ID = "updates"
			} else if len(seq)%3 == 1 {
				seqs[0].ID = "deletes"
			}
		}
		runAll(t, "app", bsoncore.Document(body), seqs)
	})
}

// ---- structure-aware generator ---------------------------------------------

type gen struct {
	b []byte
	i int
}

func (g *gen) u8() int {
	if g.i >= len(g.b) {
		g.i++
		return 0
	}
	v := g.b[g.i]
	g.i++
	return int(v)
}
func (g *gen) n(k int) int { return g.u8() % k }
func (g *gen) done() bool  { return g.i > len(g.b)+64 }

var interestingStrings = []string{
	"tenantId", "T1", "T2", "t1", "0123456789abcdef01234567", "42", "$tenantId", "$$ROOT", "$$REMOVE", "a", "b", "c",
	"_id", "x.y", "tenantId.x", "$[]", "$[x]", "a.$", "system.users", "__mtp_views", "__mtp_out", "admin", "app",
	"", "*", "_id_", "mtp_tenantId_a", "$out", "simple", "en", "inline", "insert", "replace", "merge", "fail",
}

var interestingKeys = []string{
	"tenantId", "$and", "$or", "$nor", "$not", "$expr", "$where", "$function", "$accumulator", "$in", "$eq", "$ne",
	"$set", "$unset", "$rename", "$setOnInsert", "$inc", "$push", "$pull", "$addToSet", "$currentDate", "$min",
	"$match", "$lookup", "$graphLookup", "$unionWith", "$facet", "$merge", "$out", "$project", "$group", "$sort",
	"$geoNear", "$changeStream", "$collStats", "$indexStats", "$documents", "$listSessions", "$search", "$replaceRoot",
	"$replaceWith", "$addFields", "$limit", "$skip", "$unwind", "$bucket", "$redact", "$sample", "$count",
	"from", "as", "localField", "foreignField", "let", "pipeline", "coll", "db", "into", "on", "whenMatched",
	"whenNotMatched", "q", "u", "limit", "multi", "upsert", "collation", "hint", "arrayFilters", "c", "query",
	"filter", "key", "name", "expireAfterSeconds", "unique", "partialFilterExpression", "restrictSearchWithMatch",
	"startWith", "connectFromField", "connectToField", "locale", "strength", "alternate", "documents", "updates",
	"deletes", "update", "remove", "new", "fields", "sort", "projection", "indexes", "index", "explain", "$db",
	"fullDocument", "fullDocumentBeforeChange", "allChangesForCluster", "viewOn", "capped", "validator", "timeseries",
	"clusteredIndex", "collMod", "a", "b", "x", "_id", "$comment", "$text", "$search", "$near", "$jsonSchema",
}

var interestingCmds = []string{
	"find", "count", "distinct", "aggregate", "insert", "update", "delete", "findAndModify", "findandmodify",
	"createIndexes", "dropIndexes", "listIndexes", "listCollections", "create", "drop", "mapReduce", "explain",
	"listDatabases", "ping", "dropDatabase", "collMod", "getMore", "bulkWrite",
}

var stageNames = []string{
	"$match", "$lookup", "$graphLookup", "$unionWith", "$facet", "$merge", "$out", "$project", "$group", "$sort",
	"$geoNear", "$changeStream", "$collStats", "$documents", "$set", "$unset", "$replaceRoot", "$limit", "$redact",
	"$addFields", "$bucket", "$setWindowFields", "$densify", "$count", "$unwind", "$sample", "$skip",
}

func (g *gen) str() string {
	if g.n(5) == 0 {
		return string([]byte{byte('a' + g.n(26))})
	}
	return interestingStrings[g.n(len(interestingStrings))]
}
func (g *gen) key() string {
	if g.n(6) == 0 {
		return g.str()
	}
	return interestingKeys[g.n(len(interestingKeys))]
}

func (g *gen) scalar(key string) []byte {
	switch g.n(14) {
	case 0:
		return bsoncore.AppendInt32Element(nil, key, int32(g.n(5)))
	case 1:
		return bsoncore.AppendInt64Element(nil, key, int64(g.n(5)))
	case 2:
		return bsoncore.AppendDoubleElement(nil, key, float64(g.n(3)))
	case 3:
		return bsoncore.AppendBooleanElement(nil, key, g.n(2) == 0)
	case 4:
		return bsoncore.AppendNullElement(nil, key)
	case 5:
		return bsoncore.AppendObjectIDElement(nil, key, [12]byte{1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103})
	case 6:
		return bsoncore.AppendRegexElement(nil, key, "^T1", "i")
	case 7:
		return bsoncore.AppendDateTimeElement(nil, key, int64(g.n(100)))
	case 8:
		return bsoncore.AppendBinaryElement(nil, key, 0, []byte{1, 2})
	case 9:
		return bsoncore.AppendJavaScriptElement(nil, key, "function(){}")
	case 10:
		return bsoncore.AppendDecimal128Element(nil, key, 0, 0)
	default:
		return bsoncore.AppendStringElement(nil, key, g.str())
	}
}

// value appends a random value. depth bounds recursion.
func (g *gen) value(key string, depth int) []byte {
	if depth <= 0 || g.done() {
		return g.scalar(key)
	}
	switch g.n(10) {
	case 0, 1, 2:
		return bsoncore.AppendDocumentElement(nil, key, g.document(depth-1))
	case 3:
		return bsoncore.AppendArrayElement(nil, key, g.array(depth-1))
	case 4:
		return bsoncore.AppendDocumentElement(nil, key, g.pipelineStageDoc(depth-1))
	case 5:
		return bsoncore.AppendArrayElement(nil, key, g.pipeline(depth-1))
	default:
		return g.scalar(key)
	}
}

func (g *gen) document(depth int) bsoncore.Document {
	var els [][]byte
	for k := g.n(5); k > 0 && !g.done(); k-- {
		els = append(els, g.value(g.key(), depth))
	}
	return bsoncore.BuildDocument(nil, els...)
}

func (g *gen) array(depth int) bsoncore.Array {
	var vs []bsoncore.Value
	for k := g.n(4); k > 0 && !g.done(); k-- {
		e := g.value("", depth)
		vs = append(vs, bsoncore.Element(e).Value())
	}
	return bsoncore.BuildArray(nil, vs...)
}

func (g *gen) filter(depth int) bsoncore.Document {
	var els [][]byte
	for k := g.n(4); k > 0 && !g.done(); k-- {
		switch g.n(6) {
		case 0:
			els = append(els, bsoncore.AppendArrayElement(nil, interestingKeys[g.n(4)+1], g.docArray(depth-1)))
		case 1:
			els = append(els, bsoncore.AppendDocumentElement(nil, "tenantId", g.document(depth-1)))
		case 2:
			els = append(els, g.scalar("tenantId"))
		default:
			els = append(els, g.value(g.key(), depth))
		}
	}
	return bsoncore.BuildDocument(nil, els...)
}

func (g *gen) docArray(depth int) bsoncore.Array {
	var vs []bsoncore.Value
	for k := g.n(3); k > 0 && !g.done(); k-- {
		vs = append(vs, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: g.filter(depth)})
	}
	return bsoncore.BuildArray(nil, vs...)
}

func (g *gen) stageSpec(name string, depth int) []byte {
	if depth <= 0 {
		return g.value(name, 0)
	}
	switch name {
	case "$match":
		return bsoncore.AppendDocumentElement(nil, name, g.filter(depth-1))
	case "$lookup":
		var els [][]byte
		for k := g.n(6); k > 0; k-- {
			switch g.n(7) {
			case 0:
				els = append(els, bsoncore.AppendStringElement(nil, "from", g.str()))
			case 1:
				els = append(els, bsoncore.AppendDocumentElement(nil, "from", g.document(1)))
			case 2:
				els = append(els, bsoncore.AppendArrayElement(nil, "pipeline", g.pipeline(depth-1)))
			case 3:
				els = append(els, bsoncore.AppendDocumentElement(nil, "let", g.document(2)))
			case 4:
				els = append(els, bsoncore.AppendStringElement(nil, "as", "x"))
			default:
				els = append(els, g.value(g.key(), depth-1))
			}
		}
		return bsoncore.AppendDocumentElement(nil, name, bsoncore.BuildDocument(nil, els...))
	case "$unionWith":
		if g.n(3) == 0 {
			return bsoncore.AppendStringElement(nil, name, g.str())
		}
		els := [][]byte{}
		for k := g.n(4); k > 0; k-- {
			switch g.n(3) {
			case 0:
				els = append(els, bsoncore.AppendStringElement(nil, "coll", g.str()))
			case 1:
				els = append(els, bsoncore.AppendArrayElement(nil, "pipeline", g.pipeline(depth-1)))
			default:
				els = append(els, g.value(g.key(), depth-1))
			}
		}
		return bsoncore.AppendDocumentElement(nil, name, bsoncore.BuildDocument(nil, els...))
	case "$facet":
		var els [][]byte
		for k := g.n(3); k > 0; k-- {
			els = append(els, bsoncore.AppendArrayElement(nil, g.str(), g.pipeline(depth-1)))
		}
		return bsoncore.AppendDocumentElement(nil, name, bsoncore.BuildDocument(nil, els...))
	case "$graphLookup":
		var els [][]byte
		for k := g.n(5); k > 0; k-- {
			switch g.n(4) {
			case 0:
				els = append(els, bsoncore.AppendStringElement(nil, "from", g.str()))
			case 1:
				els = append(els, bsoncore.AppendDocumentElement(nil, "restrictSearchWithMatch", g.filter(depth-1)))
			default:
				els = append(els, g.value(g.key(), depth-1))
			}
		}
		return bsoncore.AppendDocumentElement(nil, name, bsoncore.BuildDocument(nil, els...))
	case "$merge", "$out":
		if g.n(3) == 0 {
			return bsoncore.AppendStringElement(nil, name, g.str())
		}
		var els [][]byte
		for k := g.n(5); k > 0; k-- {
			switch g.n(5) {
			case 0:
				els = append(els, bsoncore.AppendStringElement(nil, "into", g.str()))
			case 1:
				els = append(els, bsoncore.AppendDocumentElement(nil, "into", g.document(1)))
			case 2:
				els = append(els, bsoncore.AppendArrayElement(nil, "whenMatched", g.pipeline(depth-1)))
			default:
				els = append(els, g.value(g.key(), depth-1))
			}
		}
		return bsoncore.AppendDocumentElement(nil, name, bsoncore.BuildDocument(nil, els...))
	case "$geoNear":
		return bsoncore.AppendDocumentElement(nil, name, bsoncore.BuildDocument(nil,
			bsoncore.AppendDocumentElement(nil, "query", g.filter(depth-1)), g.value(g.key(), depth-1)))
	}
	return g.value(name, depth-1)
}

func (g *gen) pipelineStageDoc(depth int) bsoncore.Document {
	name := stageNames[g.n(len(stageNames))]
	els := [][]byte{g.stageSpec(name, depth)}
	if g.n(12) == 0 { // two-field stage
		els = append(els, g.value(g.key(), depth))
	}
	return bsoncore.BuildDocument(nil, els...)
}

func (g *gen) pipeline(depth int) bsoncore.Array {
	var vs []bsoncore.Value
	for k := g.n(5); k > 0 && !g.done(); k-- {
		vs = append(vs, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: g.pipelineStageDoc(depth)})
	}
	return bsoncore.BuildArray(nil, vs...)
}

func (g *gen) update(depth int) bsoncore.Value {
	switch g.n(4) {
	case 0:
		return bsoncore.Value{Type: bsoncore.TypeArray, Data: g.pipeline(depth)}
	case 1:
		return bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: g.document(depth)}
	}
	var els [][]byte
	for k := g.n(3) + 1; k > 0; k-- {
		ops := []string{"$set", "$unset", "$rename", "$setOnInsert", "$inc", "$push", "$min", "$currentDate"}
		var fields [][]byte
		for j := g.n(3) + 1; j > 0; j-- {
			path := []string{"a", "tenantId", "tenantId.x", "b.$[x].c", "a.$", "$[]", "tenantId."}[g.n(7)]
			if g.n(3) == 0 {
				fields = append(fields, bsoncore.AppendStringElement(nil, path, g.str()))
			} else {
				fields = append(fields, g.value(path, depth-1))
			}
		}
		els = append(els, bsoncore.AppendDocumentElement(nil, ops[g.n(len(ops))], bsoncore.BuildDocument(nil, fields...)))
	}
	return bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: bsoncore.BuildDocument(nil, els...)}
}

func (g *gen) stmts(depth int, update bool) bsoncore.Array {
	var vs []bsoncore.Value
	for k := g.n(3) + 1; k > 0; k-- {
		els := [][]byte{}
		if g.n(8) != 0 {
			els = append(els, bsoncore.AppendDocumentElement(nil, "q", g.filter(depth)))
		}
		if update {
			if g.n(8) != 0 {
				els = append(els, bsoncore.AppendValueElement(nil, "u", g.update(depth)))
			}
			if g.n(3) == 0 {
				els = append(els, bsoncore.AppendBooleanElement(nil, "upsert", true))
			}
			if g.n(4) == 0 {
				els = append(els, bsoncore.AppendArrayElement(nil, "arrayFilters", g.docArray(depth)))
			}
			if g.n(6) == 0 {
				els = append(els, bsoncore.AppendDocumentElement(nil, "c", g.document(2)))
			}
		}
		if g.n(5) == 0 {
			els = append(els, bsoncore.AppendDocumentElement(nil, "collation", g.document(1)))
		}
		if g.n(10) == 0 {
			els = append(els, g.value(g.key(), 2))
		}
		vs = append(vs, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: bsoncore.BuildDocument(nil, els...)})
	}
	return bsoncore.BuildArray(nil, vs...)
}

// command builds a hostile command document and (for write commands) a sequence.
func (g *gen) command() (bsoncore.Document, []wire.Seq) {
	name := interestingCmds[g.n(len(interestingCmds))]
	depth := 3 + g.n(3)
	var seqs []wire.Seq
	first := bsoncore.AppendStringElement(nil, name, g.collName())
	if g.n(15) == 0 {
		first = g.value(name, 1)
	}
	if name == "aggregate" && g.n(5) == 0 {
		first = bsoncore.AppendInt32Element(nil, name, 1)
	}
	els := [][]byte{first}
	add := func(e []byte) { els = append(els, e) }
	switch name {
	case "find":
		add(bsoncore.AppendDocumentElement(nil, "filter", g.filter(depth)))
		if g.n(4) == 0 {
			add(bsoncore.AppendDocumentElement(nil, "projection", g.document(2)))
		}
		if g.n(4) == 0 {
			add(bsoncore.AppendDocumentElement(nil, "let", g.document(2)))
		}
	case "count", "distinct", "findAndModify", "findandmodify", "mapReduce":
		add(bsoncore.AppendDocumentElement(nil, "query", g.filter(depth)))
		if name == "findAndModify" || name == "findandmodify" {
			if g.n(2) == 0 {
				add(bsoncore.AppendValueElement(nil, "update", g.update(depth)))
			} else {
				add(bsoncore.AppendBooleanElement(nil, "remove", true))
			}
			if g.n(3) == 0 {
				add(bsoncore.AppendBooleanElement(nil, "upsert", true))
			}
		}
		if name == "mapReduce" {
			add(bsoncore.AppendDocumentElement(nil, "out", g.document(1)))
		}
	case "aggregate":
		add(bsoncore.AppendArrayElement(nil, "pipeline", g.pipeline(depth)))
		if g.n(5) == 0 {
			add(bsoncore.AppendDocumentElement(nil, "let", g.document(2)))
		}
	case "insert":
		docs := g.docArray(2)
		useSeq := g.n(2) == 0
		if useSeq {
			vs, _ := docs.Values()
			s := wire.Seq{ID: "documents"}
			for _, v := range vs {
				s.Docs = append(s.Docs, v.Document())
			}
			seqs = append(seqs, s)
		} else {
			add(bsoncore.AppendArrayElement(nil, "documents", docs))
		}
	case "update", "delete":
		key := map[string]string{"update": "updates", "delete": "deletes"}[name]
		st := g.stmts(depth, name == "update")
		if g.n(2) == 0 {
			vs, _ := st.Values()
			s := wire.Seq{ID: key}
			for _, v := range vs {
				s.Docs = append(s.Docs, v.Document())
			}
			seqs = append(seqs, s)
		} else {
			add(bsoncore.AppendArrayElement(nil, key, st))
		}
	case "explain":
		inner, _ := g.command()
		els[0] = bsoncore.AppendDocumentElement(nil, "explain", inner)
	case "createIndexes", "dropIndexes", "listIndexes", "create", "listCollections", "drop":
		for k := g.n(5); k > 0; k-- {
			switch g.n(5) {
			case 0:
				add(bsoncore.AppendArrayElement(nil, "indexes", g.indexes(depth)))
			case 1:
				add(g.value("index", 2))
			default:
				add(g.value(g.key(), 2))
			}
		}
	}
	if g.n(3) != 0 {
		add(bsoncore.AppendStringElement(nil, "$db", []string{"app", "app", "admin", "x", "config", ""}[g.n(6)]))
	}
	for k := g.n(3); k > 0; k-- {
		add(g.value(g.key(), 2))
	}
	return bsoncore.BuildDocument(nil, els...), seqs
}

func (g *gen) collName() string {
	switch g.n(8) {
	case 0:
		return g.str()
	case 1:
		return "system.views"
	default:
		return []string{"c", "d", "e", "view"}[g.n(4)]
	}
}

func (g *gen) indexes(depth int) bsoncore.Array {
	var vs []bsoncore.Value
	for k := g.n(3) + 1; k > 0; k-- {
		var els [][]byte
		if g.n(8) != 0 {
			els = append(els, bsoncore.AppendDocumentElement(nil, "key", g.document(1)))
		}
		for j := g.n(4); j > 0; j-- {
			switch g.n(6) {
			case 0:
				els = append(els, bsoncore.AppendInt32Element(nil, "expireAfterSeconds", int32(g.n(100))))
			case 1:
				els = append(els, bsoncore.AppendBooleanElement(nil, "unique", g.n(2) == 0))
			case 2:
				els = append(els, bsoncore.AppendDocumentElement(nil, "partialFilterExpression", g.filter(2)))
			case 3:
				els = append(els, bsoncore.AppendDocumentElement(nil, "collation", g.document(1)))
			case 4:
				els = append(els, bsoncore.AppendStringElement(nil, "name", g.str()))
			default:
				els = append(els, g.value(g.key(), 2))
			}
		}
		vs = append(vs, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: bsoncore.BuildDocument(nil, els...)})
	}
	return bsoncore.BuildArray(nil, vs...)
}

// FuzzRewriteStructured drives the rewriter with generated hostile commands
// that are always valid BSON, so every input reaches the policy code.
func FuzzRewriteStructured(f *testing.F) {
	for i := 0; i < 64; i++ {
		b := make([]byte, 96)
		for j := range b {
			b[j] = byte(i*131 + j*17 + j*j)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		g := &gen{b: data}
		body, seqs := g.command()
		if err := body.Validate(); err != nil {
			t.Fatalf("generator produced invalid BSON: %v", err)
		}
		db := "app"
		if d, ok := body.Lookup("$db").StringValueOK(); ok {
			db = d
		}
		runAll(t, db, body, seqs)
	})
}

// FuzzPostProcessors checks the reply transformers never panic and keep
// well-formed replies well-formed.
func FuzzPostProcessors(f *testing.F) {
	for _, s := range [][]byte{
		mustMarshal(bson.M{"cursor": bson.M{"firstBatch": bson.A{bson.M{"key": bson.M{"tenantId": 1, "a": 1}, "name": "x"}}, "id": int64(0), "ns": "app.c"}, "ok": 1}),
		mustMarshal(bson.M{"databases": bson.A{bson.M{"name": "app", "sizeOnDisk": 1}, bson.M{"name": "admin"}}, "ok": 1}),
		mustMarshal(bson.M{"n": 1, "ok": 1, "$clusterTime": bson.M{}}),
	} {
		f.Add(s)
	}
	r := New(Config{})
	ten := fuzzTenants()[0]
	f.Fuzz(func(t *testing.T, resp []byte) {
		valid := bsoncore.Document(resp).Validate() == nil
		for name, fn := range map[string]func(bsoncore.Document) bsoncore.Document{
			"unprefixIndexes": func(d bsoncore.Document) bsoncore.Document { return r.unprefixIndexes(ten, d) },
			"filterDatabases": r.filterDatabases,
		} {
			out := func() (o bsoncore.Document) {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("%s panicked: %v", name, p)
					}
				}()
				return fn(bsoncore.Document(resp))
			}()
			if valid {
				if err := out.Validate(); err != nil {
					t.Fatalf("%s produced invalid BSON: %v", name, err)
				}
			}
		}
	})
}

func mustMarshal(v any) []byte {
	b, err := bson.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
