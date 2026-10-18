package rewrite

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

type (
	D = bson.D
	A = bson.A
	M = bson.M
)

func s1(k string, v any) bson.E { return bson.E{Key: k, Value: v} }

// rawElems builds a document from pre-encoded elements, which lets tests
// repeat keys (bson.D/bson.M helpers would not preserve duplicates reliably).
func rawElems(els ...[]byte) bsoncore.Document { return bsoncore.BuildDocument(nil, els...) }
func rawStr(k, v string) []byte                { return bsoncore.AppendStringElement(nil, k, v) }
func rawDoc(k string, d bsoncore.Document) []byte {
	return bsoncore.AppendDocumentElement(nil, k, d)
}
func rawArr(k string, vs ...bsoncore.Value) []byte {
	return bsoncore.AppendArrayElement(nil, k, bsoncore.BuildArray(nil, vs...))
}
func dv(d bsoncore.Document) bsoncore.Value {
	return bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: d}
}

// nested returns {key: {key: {... leaf}}} nested n levels deep without recursion.
func nested(key string, n int, leaf []byte) bsoncore.Document {
	inner := rawElems(leaf)
	for i := 0; i < n; i++ {
		inner = rawElems(rawDoc(key, inner))
	}
	return inner
}

// nestedArr returns [[[...]]] n levels deep.
func nestedArr(n int) bsoncore.Value {
	v := bsoncore.Value{Type: bsoncore.TypeArray, Data: bsoncore.BuildArray(nil)}
	for i := 0; i < n; i++ {
		v = bsoncore.Value{Type: bsoncore.TypeArray, Data: bsoncore.BuildArray(nil, v)}
	}
	return v
}

type advCase struct {
	name   string
	cmd    any // bson.D or bsoncore.Document
	seqs   []wire.Seq
	reject bool
	// errHas, when set, must appear in the rejection message.
	errHas string
}

func seqOf(id string, docs ...any) wire.Seq {
	s := wire.Seq{ID: id}
	for _, d := range docs {
		b, err := bson.Marshal(d)
		if err != nil {
			panic(err)
		}
		s.Docs = append(s.Docs, b)
	}
	return s
}

func withDB(d D) D { return append(d, s1("$db", "app")) }

func agg(stages ...any) D {
	return withDB(D{s1("aggregate", "c"), s1("pipeline", A(stages)), s1("cursor", M{})})
}

func upd(stmts ...any) D { return withDB(D{s1("update", "c"), s1("updates", A(stmts))}) }

func adversarialCases() []advCase {
	deepFilter := nested("$and", 150, rawStr("a", "b"))
	var cs []advCase
	add := func(name string, cmd any, reject bool, errHas ...string) {
		c := advCase{name: name, cmd: cmd, reject: reject}
		if len(errHas) > 0 {
			c.errHas = errHas[0]
		}
		cs = append(cs, c)
	}

	// ---- duplicate keys at every nesting level --------------------------------
	add("dup/command filter", rawElems(rawStr("find", "c"), rawDoc("filter", rawElems(rawStr("a", "1"))), rawDoc("filter", rawElems(rawStr("tenantId", "T2"))), rawStr("$db", "app")), true)
	add("dup/command $db", rawElems(rawStr("find", "c"), rawStr("$db", "app"), rawStr("$db", "admin")), true)
	add("dup/command name", rawElems(rawStr("find", "c"), rawStr("find", "system.users"), rawStr("$db", "app")), true)
	add("dup/update stmt u", rawElems(rawStr("update", "c"), rawArr("updates", dv(rawElems(rawDoc("q", rawElems()), rawDoc("u", rawElems(rawDoc("$set", rawElems(rawStr("a", "1"))))), rawDoc("u", rawElems(rawDoc("$set", rawElems(rawStr("tenantId", "T2")))))))), rawStr("$db", "app")), true)
	add("dup/update stmt q", rawElems(rawStr("update", "c"), rawArr("updates", dv(rawElems(rawDoc("q", rawElems()), rawDoc("q", rawElems(rawStr("tenantId", "T2"))), rawDoc("u", rawElems(rawDoc("$set", rawElems(rawStr("a", "1")))))))), rawStr("$db", "app")), true)
	add("dup/delete stmt q", rawElems(rawStr("delete", "c"), rawArr("deletes", dv(rawElems(rawDoc("q", rawElems()), rawDoc("q", rawElems(rawStr("tenantId", "T2")))))), rawStr("$db", "app")), true)
	add("dup/operator set tenant", rawElems(rawStr("update", "c"), rawArr("updates", dv(rawElems(rawDoc("q", rawElems()), rawDoc("u", rawElems(rawDoc("$set", rawElems(rawStr("a", "1"))), rawDoc("$set", rawElems(rawStr("tenantId", "T2")))))))), rawStr("$db", "app")), true)
	add("dup/replacement tenant ids", rawElems(rawStr("update", "c"), rawArr("updates", dv(rawElems(rawDoc("q", rawElems()), rawDoc("u", rawElems(rawStr("tenantId", "T1"), rawStr("tenantId", "T2")))))), rawStr("$db", "app")), true)
	add("dup/insert tenant ids", rawElems(rawStr("insert", "c"), rawArr("documents", dv(rawElems(rawStr("tenantId", "T1"), rawStr("tenantId", "T2")))), rawStr("$db", "app")), true)
	add("dup/pipeline", rawElems(rawStr("aggregate", "c"), rawArr("pipeline"), rawArr("pipeline", dv(rawElems(rawDoc("$out", rawElems())))), rawStr("$db", "app")), true)
	add("dup/lookup from", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$lookup": rawElems(rawStr("from", "a"), rawStr("from", "b"), rawStr("as", "x"))}})}), true)
	add("dup/lookup pipeline", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$lookup": rawElems(rawStr("from", "a"), rawArr("pipeline"), rawArr("pipeline"), rawStr("as", "x"))}})}), true)
	add("dup/unionWith coll", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$unionWith": rawElems(rawStr("coll", "a"), rawStr("coll", "b"))}})}), true)
	add("dup/merge into", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$merge": rawElems(rawStr("into", "a"), rawStr("into", "b"))}})}), true)
	add("dup/graphLookup restrict", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$graphLookup": rawElems(rawStr("from", "c"), rawDoc("restrictSearchWithMatch", rawElems()), rawDoc("restrictSearchWithMatch", rawElems(rawStr("tenantId", "T2"))))}})}), true)
	add("dup/geoNear query", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$geoNear": rawElems(rawDoc("query", rawElems()), rawDoc("query", rawElems()), rawStr("distanceField", "d"))}})}), true)
	add("dup/changeStream", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$changeStream": rawElems(rawStr("fullDocument", "default"), rawStr("fullDocument", "required"))}})}), true)
	add("dup/explain inner", rawElems(rawDoc("explain", rawElems(rawStr("find", "c"), rawStr("find", "d"))), rawStr("$db", "app")), true)
	add("dup/filter keys are fine (and-wrapped)", withDB(D{s1("find", "c"), s1("filter", rawElems(rawStr("tenantId", "T2"), rawStr("tenantId", "T1")))}), false)

	// ---- BSON type confusion ---------------------------------------------------
	for _, tc := range []struct {
		n string
		v any
	}{{"int", 1}, {"double", 1.5}, {"array", A{"c"}}, {"doc", M{"a": 1}}, {"null", nil}, {"bool", true}, {"objectid", bson.NewObjectID()}} {
		add("type/find collection "+tc.n, withDB(D{s1("find", tc.v)}), true)
		add("type/insert collection "+tc.n, withDB(D{s1("insert", tc.v), s1("documents", A{M{"a": 1}})}), true)
		add("type/update collection "+tc.n, withDB(D{s1("update", tc.v), s1("updates", A{M{"q": M{}, "u": M{"$set": M{"a": 1}}}})}), true)
		add("type/delete collection "+tc.n, withDB(D{s1("delete", tc.v), s1("deletes", A{M{"q": M{}, "limit": 0}})}), true)
		add("type/createIndexes collection "+tc.n, withDB(D{s1("createIndexes", tc.v), s1("indexes", A{M{"key": M{"a": 1}, "name": "a"}})}), true)
		add("type/drop collection "+tc.n, withDB(D{s1("drop", tc.v)}), true)
		add("type/listIndexes collection "+tc.n, withDB(D{s1("listIndexes", tc.v)}), true)
		if tc.n != "int" && tc.n != "double" { // aggregate: 1 is the db-level form
			add("type/aggregate collection "+tc.n, withDB(D{s1("aggregate", tc.v), s1("pipeline", A{})}), true)
		}
	}
	add("type/aggregate 1 without changeStream", withDB(D{s1("aggregate", 1), s1("pipeline", A{M{"$match": M{}}})}), true)
	add("type/aggregate 1 no pipeline (was a panic)", withDB(D{s1("aggregate", 1)}), true)
	add("type/aggregate 1 pipeline string (was a panic)", withDB(D{s1("aggregate", 1), s1("pipeline", "x")}), true)
	add("type/aggregate 1 pipeline doc (was a panic)", withDB(D{s1("aggregate", 1), s1("pipeline", M{"$changeStream": M{}})}), true)
	add("type/aggregate 1.0 db-level changeStream", withDB(D{s1("aggregate", 1.0), s1("pipeline", A{M{"$changeStream": M{}}})}), false)
	add("type/filter array", withDB(D{s1("find", "c"), s1("filter", A{M{"tenantId": "T2"}})}), true)
	add("type/filter string", withDB(D{s1("find", "c"), s1("filter", "x")}), true)
	add("type/filter null", withDB(D{s1("find", "c"), s1("filter", nil)}), true)
	add("type/query array", withDB(D{s1("count", "c"), s1("query", A{})}), true)
	add("type/pipeline doc", withDB(D{s1("aggregate", "c"), s1("pipeline", M{"0": M{"$out": "x"}})}), true)
	add("type/pipeline missing", withDB(D{s1("aggregate", "c")}), true)
	add("type/stage array", agg(A{"$match", M{}}), true)
	add("type/stage string", agg("$out"), true)
	add("type/stage empty", agg(M{}), true)
	add("type/stage two fields", agg(D{s1("$match", M{}), s1("$out", "x")}), true)
	add("type/match array", agg(M{"$match": A{}}), true)
	add("type/lookup array", agg(M{"$lookup": A{}}), true)
	add("type/lookup from int", agg(M{"$lookup": M{"from": 1, "as": "x", "pipeline": A{}}}), true)
	add("type/lookup from doc bad db", agg(M{"$lookup": M{"from": M{"db": 1, "coll": "x"}, "as": "x"}}), true)
	add("type/lookup from doc bad coll", agg(M{"$lookup": M{"from": M{"db": "app", "coll": A{}}, "as": "x"}}), true)
	add("type/lookup pipeline doc", agg(M{"$lookup": M{"from": "x", "as": "x", "pipeline": M{"$out": "x"}}}), true)
	add("type/unionWith int", agg(M{"$unionWith": 1}), true)
	add("type/unionWith coll array", agg(M{"$unionWith": M{"coll": A{"x"}}}), true)
	add("type/unionWith pipeline doc", agg(M{"$unionWith": M{"coll": "x", "pipeline": M{}}}), true)
	add("type/facet array", agg(M{"$facet": A{}}), true)
	add("type/facet branch doc", agg(M{"$facet": M{"a": M{"$match": M{}}}}), true)
	add("type/graphLookup restrict string", agg(M{"$graphLookup": M{"from": "c", "restrictSearchWithMatch": "x"}}), true)
	add("type/geoNear string", agg(M{"$geoNear": "x"}), true)
	add("type/documents as doc", withDB(D{s1("insert", "c"), s1("documents", M{"0": M{"tenantId": "T2"}})}), true)
	add("type/documents as string", withDB(D{s1("insert", "c"), s1("documents", "x")}), true)
	add("type/updates as doc", withDB(D{s1("update", "c"), s1("updates", M{"0": M{"q": M{"tenantId": "T2"}, "u": M{"$set": M{"tenantId": "T2"}}}})}), true)
	add("type/deletes as string", withDB(D{s1("delete", "c"), s1("deletes", "x")}), true)
	add("type/documents elements not docs", withDB(D{s1("insert", "c"), s1("documents", A{1, "x"})}), true)
	add("type/update stmt string", upd("x"), true)
	add("type/update q array", upd(M{"q": A{}, "u": M{"$set": M{"a": 1}}}), true)
	add("type/update u string", upd(M{"q": M{}, "u": "x"}), true)
	add("type/update u int", upd(M{"q": M{}, "u": 1}), true)
	add("type/update u missing", upd(M{"q": M{}}), true)
	add("type/update op value not doc", upd(M{"q": M{}, "u": M{"$set": 1}}), true)
	add("type/update pipeline stage string", upd(M{"q": M{}, "u": A{"$set"}}), true)
	add("type/findAndModify update int", withDB(D{s1("findAndModify", "c"), s1("query", M{}), s1("update", 1)}), true)
	add("type/findAndModify update string", withDB(D{s1("findAndModify", "c"), s1("query", M{}), s1("update", "x")}), true)
	add("type/findAndModify query array", withDB(D{s1("findAndModify", "c"), s1("query", A{}), s1("remove", true)}), true)
	add("type/createIndexes indexes doc", withDB(D{s1("createIndexes", "c"), s1("indexes", M{"key": M{"a": 1}})}), true)
	add("type/createIndexes key string", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": "a", "name": "a"}})}), true)
	add("type/createIndexes key array", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": A{"a"}, "name": "a"}})}), true)
	add("type/createIndexes name int", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"a": 1}, "name": 5}})}), true)
	add("type/createIndexes pfe string", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"a": 1}, "expireAfterSeconds": 5, "partialFilterExpression": "x"}})}), true)
	add("type/dropIndexes int", withDB(D{s1("dropIndexes", "c"), s1("index", 1)}), true)
	add("type/explain string", withDB(D{s1("explain", "find")}), true)
	add("type/explain array", withDB(D{s1("explain", A{M{"find": "c"}})}), true)
	add("type/listCollections filter string", withDB(D{s1("listCollections", 1), s1("filter", "x")}), true)
	add("type/merge into int", agg(M{"$merge": M{"into": 1}}), true)
	add("type/merge on int", agg(M{"$merge": M{"into": "x", "on": 1}}), true)
	add("type/merge on array of ints", agg(M{"$merge": M{"into": "x", "on": A{1}}}), true)
	add("type/merge whenMatched int", agg(M{"$merge": M{"into": "x", "whenMatched": 1}}), true)
	add("type/out int", agg(M{"$out": 1}), true)
	add("type/out coll int", agg(M{"$out": M{"coll": 1}}), true)
	add("type/changeStream string", withDB(D{s1("aggregate", "c"), s1("pipeline", A{M{"$changeStream": "x"}})}), true)

	// ---- depth / size limits -----------------------------------------------------
	add("limits/filter 150 deep", rawElems(rawStr("find", "c"), rawDoc("filter", deepFilter), rawStr("$db", "app")), true, "nesting")
	add("limits/filter 90 deep ok", rawElems(rawStr("find", "c"), rawDoc("filter", nested("$and", 90, rawStr("a", "b"))), rawStr("$db", "app")), false)
	add("limits/array 100000 deep", rawElems(rawStr("find", "c"), bsoncore.AppendValueElement(nil, "filter", nestedArr(100000)), rawStr("$db", "app")), true)
	add("limits/doc 1e5 deep", rawElems(rawStr("find", "c"), rawDoc("filter", nested("$not", 100000, rawStr("a", "b"))), rawStr("$db", "app")), true)
	add("limits/facet 80 deep", func() any {
		stage := dv(rawElems(rawDoc("$match", rawElems())))
		for i := 0; i < 80; i++ {
			stage = dv(rawElems(rawDoc("$facet", rawElems(bsoncore.AppendArrayElement(nil, "f", bsoncore.BuildArray(nil, stage))))))
		}
		return rawElems(rawStr("aggregate", "c"), rawArr("pipeline", stage), rawStr("$db", "app"))
	}(), true, "nesting")
	add("limits/unionWith 60 deep", func() any {
		stage := dv(rawElems(rawDoc("$match", rawElems())))
		for i := 0; i < 60; i++ {
			stage = dv(rawElems(rawDoc("$unionWith", rawElems(rawStr("coll", "x"), rawArr("pipeline", stage)))))
		}
		return rawElems(rawStr("aggregate", "c"), rawArr("pipeline", stage), rawStr("$db", "app"))
	}(), true, "nesting")
	add("limits/lookup 60 deep", func() any {
		stage := dv(rawElems(rawDoc("$match", rawElems())))
		for i := 0; i < 60; i++ {
			stage = dv(rawElems(rawDoc("$lookup", rawElems(rawStr("from", "x"), rawStr("as", "y"), rawArr("pipeline", stage)))))
		}
		return rawElems(rawStr("aggregate", "c"), rawArr("pipeline", stage), rawStr("$db", "app"))
	}(), true, "nesting")
	add("limits/1001 stages", func() any {
		var vs []bsoncore.Value
		for i := 0; i < 1001; i++ {
			vs = append(vs, dv(rawElems(bsoncore.AppendInt32Element(nil, "$limit", 5))))
		}
		return rawElems(rawStr("aggregate", "c"), rawArr("pipeline", vs...), rawStr("$db", "app"))
	}(), true, "1000 stages")
	add("limits/1000 stages ok", func() any {
		var vs []bsoncore.Value
		for i := 0; i < 1000; i++ {
			vs = append(vs, dv(rawElems(bsoncore.AppendInt32Element(nil, "$limit", 5))))
		}
		return rawElems(rawStr("aggregate", "c"), rawArr("pipeline", vs...), rawStr("$db", "app"))
	}(), false)
	add("limits/update pipeline 1001 stages", func() any {
		var vs []bsoncore.Value
		for i := 0; i < 1001; i++ {
			vs = append(vs, dv(rawElems(rawDoc("$set", rawElems(bsoncore.AppendInt32Element(nil, "a", 1))))))
		}
		return rawElems(rawStr("update", "c"), rawArr("updates", dv(rawElems(rawDoc("q", rawElems()), rawArr("u", vs...)))), rawStr("$db", "app"))
	}(), true)
	add("limits/code with scope", rawElems(rawStr("find", "c"), bsoncore.AppendCodeWithScopeElement(nil, "filter", "1", rawElems()), rawStr("$db", "app")), true)

	// ---- malformed BSON (must be rejected, not panic) ----------------------------
	badString := func() bsoncore.Document {
		// {"find": "c", "filter": {"a": <string with length 0>}}
		inner := []byte{0, 0, 0, 0, 0x02, 'a', 0, 0, 0, 0, 0, 0}
		inner[0] = byte(len(inner))
		d := []byte{0, 0, 0, 0}
		d = bsoncore.AppendStringElement(d, "find", "c")
		d = append(d, 0x03, 'f', 'i', 'l', 't', 'e', 'r', 0)
		d = append(d, inner...)
		d = append(d, 0)
		d[0] = byte(len(d))
		return d
	}()
	add("malformed/zero-length string", badString, true)
	add("malformed/truncated", rawElems(rawStr("find", "c"), rawStr("$db", "app"))[:20], true)
	add("malformed/bad terminator", func() any {
		d := append(bsoncore.Document{}, rawElems(rawStr("find", "c"), rawStr("$db", "app"))...)
		d[len(d)-1] = 1
		return d
	}(), true)
	add("malformed/length too long", func() any {
		d := append(bsoncore.Document{}, rawElems(rawStr("find", "c"), rawStr("$db", "app"))...)
		d[0] += 3
		return d
	}(), true)
	add("malformed/trailing bytes", func() any {
		return append(append(bsoncore.Document{}, rawElems(rawStr("find", "c"), rawStr("$db", "app"))...), 0, 0, 0)
	}(), true)
	add("malformed/empty", bsoncore.Document{}, true)
	add("malformed/empty doc", rawElems(), true)

	// ---- $lookup / $graphLookup / $unionWith / $facet ---------------------------
	add("lookup/from db+coll same db", agg(M{"$lookup": M{"from": M{"db": "app", "coll": "d"}, "localField": "a", "foreignField": "b", "as": "x"}}), false)
	add("lookup/from admin", agg(M{"$lookup": M{"from": M{"db": "admin", "coll": "system.users"}, "as": "x", "pipeline": A{}}}), true)
	add("lookup/from local oplog", agg(M{"$lookup": M{"from": M{"db": "local", "coll": "oplog.rs"}, "as": "x", "pipeline": A{}}}), true)
	add("lookup/from config", agg(M{"$lookup": M{"from": M{"db": "config", "coll": "shards"}, "as": "x", "pipeline": A{}}}), true)
	add("lookup/from db case ADMIN", agg(M{"$lookup": M{"from": M{"db": "ADMIN", "coll": "x"}, "as": "x", "pipeline": A{}}}), true)
	add("lookup/from db with dot", agg(M{"$lookup": M{"from": M{"db": "app.x", "coll": "x"}, "as": "x", "pipeline": A{}}}), true)
	add("lookup/from db with NUL", agg(M{"$lookup": M{"from": M{"db": "admin\x00", "coll": "x"}, "as": "x", "pipeline": A{}}}), true)
	add("lookup/from system.views", agg(M{"$lookup": M{"from": "system.views", "as": "x", "pipeline": A{}}}), true)
	add("lookup/from __mtp_views", agg(M{"$lookup": M{"from": "__mtp_views", "as": "x", "pipeline": A{}}}), true)
	add("lookup/from has $", agg(M{"$lookup": M{"from": "a$b", "as": "x", "pipeline": A{}}}), true)
	add("lookup/from NUL", agg(M{"$lookup": M{"from": "a\x00b", "as": "x", "pipeline": A{}}}), true)
	add("lookup/from empty", agg(M{"$lookup": M{"from": "", "as": "x", "pipeline": A{}}}), true)
	add("lookup/no from, documents", agg(M{"$lookup": M{"as": "x", "pipeline": A{M{"$documents": A{M{"a": 1}}}}}}), true)
	add("lookup/localField only", agg(M{"$lookup": M{"from": "d", "localField": "a", "foreignField": "b", "as": "x"}}), false)
	add("lookup/pipeline with $out", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$out": "y"}}}}), true)
	add("lookup/pipeline with $merge", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$merge": "y"}}}}), true)
	add("lookup/nested lookup", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$lookup": M{"from": "e", "as": "y", "localField": "a", "foreignField": "b"}}}}}), false)
	add("lookup/let with $function", agg(M{"$lookup": M{"from": "d", "as": "x", "let": M{"v": M{"$function": M{"body": "function(){return 1}", "args": A{}, "lang": "js"}}}, "pipeline": A{}}}), true)
	add("lookup/let ok", agg(M{"$lookup": M{"from": "d", "as": "x", "let": M{"v": "$a"}, "pipeline": A{M{"$match": M{"$expr": M{"$eq": A{"$b", "$$v"}}}}}}}), false)
	add("lookup/match tenant override attempt", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$match": M{"tenantId": "T2"}}}}}), false)
	add("lookup/match $or tenant", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$match": M{"$or": A{M{"tenantId": "T2"}, M{"a": 1}}}}}}}), false)
	add("lookup/from view-ish name", agg(M{"$lookup": M{"from": "system.buckets.x", "as": "x", "pipeline": A{}}}), true)
	add("graphLookup/basic", agg(M{"$graphLookup": M{"from": "c", "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g"}}), false)
	add("graphLookup/no from", agg(M{"$graphLookup": M{"startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g"}}), true)
	add("graphLookup/from admin", agg(M{"$graphLookup": M{"from": M{"db": "admin", "coll": "x"}, "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g"}}), true)
	add("graphLookup/restrict tenant override", agg(M{"$graphLookup": M{"from": "c", "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g", "restrictSearchWithMatch": M{"tenantId": "T2"}}}), false)
	add("graphLookup/startWith $function", agg(M{"$graphLookup": M{"from": "c", "startWith": M{"$function": M{"body": "x", "args": A{}, "lang": "js"}}, "connectFromField": "a", "connectToField": "b", "as": "g"}}), true)
	add("graphLookup/from __mtp_", agg(M{"$graphLookup": M{"from": "__mtp_views", "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g"}}), true)
	add("unionWith/string", agg(M{"$unionWith": "d"}), false)
	add("unionWith/doc no pipeline", agg(M{"$unionWith": M{"coll": "d"}}), false)
	add("unionWith/documents", agg(M{"$unionWith": M{"pipeline": A{M{"$documents": A{M{"a": 1}}}}}}), true)
	add("unionWith/__mtp_", agg(M{"$unionWith": "__mtp_views"}), true)
	add("unionWith/system", agg(M{"$unionWith": M{"coll": "system.profile"}}), true)
	add("unionWith/nested $out", agg(M{"$unionWith": M{"coll": "d", "pipeline": A{M{"$out": "x"}}}}), true)
	add("unionWith/inner stage unscoped match first", agg(M{"$unionWith": M{"coll": "d", "pipeline": A{M{"$sort": M{"a": 1}}}}}), false)
	add("unionWith/nested in facet", agg(M{"$facet": M{"f": A{M{"$unionWith": "d"}}}}), false)
	add("unionWith/in facet to __mtp_", agg(M{"$facet": M{"f": A{M{"$unionWith": "__mtp_views"}}}}), true)
	add("unionWith/in facet in lookup", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$facet": M{"f": A{M{"$unionWith": M{"coll": "e", "pipeline": A{M{"$lookup": M{"from": "g", "as": "z", "localField": "a", "foreignField": "b"}}}}}}}}}}}), false)
	add("facet/first stage", agg(M{"$facet": M{"a": A{M{"$match": M{}}}}}), false)
	add("facet/$out inside", agg(M{"$facet": M{"a": A{M{"$out": "x"}}}}), true)
	add("facet/$merge inside", agg(M{"$facet": M{"a": A{M{"$merge": "x"}}}}), true)
	add("facet/changeStream inside", agg(M{"$facet": M{"a": A{M{"$changeStream": M{}}}}}), true)
	add("facet/lookup inside", agg(M{"$facet": M{"a": A{M{"$lookup": M{"from": "d", "as": "x", "localField": "a", "foreignField": "b"}}}}}), false)
	add("facet/graphLookup inside", agg(M{"$facet": M{"a": A{M{"$graphLookup": M{"from": "c", "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g"}}}}}), false)
	add("facet/collStats inside", agg(M{"$facet": M{"a": A{M{"$collStats": M{}}}}}), true)
	add("facet/$accumulator in $group", agg(M{"$facet": M{"a": A{M{"$group": M{"_id": nil, "x": M{"$accumulator": M{"init": "x", "accumulate": "x", "accumulateArgs": A{}, "merge": "x", "lang": "js"}}}}}}}), true)
	add("facet/duplicate branch names", agg(M{"$facet": rawElems(rawArr("a"), rawArr("a"))}), false)
	add("stage/$collStats", agg(M{"$collStats": M{"storageStats": M{}}}), false) // tenant-scoped stats (admin-cmds)
	add("stage/$indexStats", agg(M{"$indexStats": M{}}), true)
	add("stage/$currentOp", agg(M{"$currentOp": M{}}), true)
	add("stage/$listSessions", agg(M{"$listSessions": M{"allUsers": true}}), true)
	add("stage/$listLocalSessions", agg(M{"$listLocalSessions": M{"allUsers": true}}), true)
	add("stage/$planCacheStats", agg(M{"$planCacheStats": M{}}), true)
	add("stage/$documents", agg(M{"$documents": A{M{"a": 1}}}), true)
	add("stage/$search", agg(M{"$search": M{"text": M{"query": "x", "path": "a"}}}), false) // tenant filter injected
	add("stage/$vectorSearch", agg(M{"$vectorSearch": M{}}), false)                         // tenant filter injected
	add("stage/$unknown", agg(M{"$nope": M{}}), true)
	add("stage/$out not last", agg(M{"$out": "x"}, M{"$limit": 1}), true)
	add("stage/$merge not last", agg(M{"$merge": "x"}, M{"$limit": 1}), true)
	add("stage/$out then $out", agg(M{"$out": "x"}, M{"$out": "y"}), true)
	add("stage/$merge last ok", agg(M{"$match": M{"a": 1}}, M{"$merge": "x"}), false)
	add("stage/$out last ok", agg(M{"$match": M{"a": 1}}, M{"$out": "x"}), false)
	add("stage/$out db admin", agg(M{"$out": M{"db": "admin", "coll": "x"}}), true)
	add("stage/$out db config", agg(M{"$out": M{"db": "config", "coll": "x"}}), true)
	add("stage/$out system", agg(M{"$out": "system.views"}), true)
	add("stage/$out __mtp_", agg(M{"$out": "__mtp_views"}), true)
	add("stage/$out timeseries", agg(M{"$out": M{"db": "app", "coll": "x", "timeseries": M{"timeField": "t"}}}), true)
	add("stage/$merge into __mtp_", agg(M{"$merge": M{"into": "__mtp_views"}}), true)
	add("stage/$merge into admin", agg(M{"$merge": M{"into": M{"db": "admin", "coll": "x"}}}), true)
	add("stage/$merge into other db", agg(M{"$merge": M{"into": M{"db": "other", "coll": "x"}}}), false)
	add("stage/$merge on tenantId then _id", agg(M{"$merge": M{"into": "x", "on": A{"tenantId", "_id"}}}), false)
	add("stage/$merge on empty (unique index on tenantId alone)", agg(M{"$merge": M{"into": "x", "on": A{}}}), true)
	add("stage/$merge on only tenantId", agg(M{"$merge": M{"into": "x", "on": "tenantId"}}), true)
	add("stage/$merge on [tenantId, tenantId]", agg(M{"$merge": M{"into": "x", "on": A{"tenantId", "tenantId"}}}), true)
	add("stage/$merge on empty field name", agg(M{"$merge": M{"into": "x", "on": ""}}), true)
	add("stage/$merge on $-field", agg(M{"$merge": M{"into": "x", "on": "$a"}}), true)
	add("stage/$merge on custom", agg(M{"$merge": M{"into": "x", "on": A{"a", "b"}}}), false)
	add("stage/$merge unknown option", agg(M{"$merge": M{"into": "x", "evil": 1}}), true)
	add("stage/$merge whenMatched pipeline", agg(M{"$merge": M{"into": "x", "whenMatched": A{M{"$set": M{"tenantId": "T2"}}}}}), false)
	add("stage/$merge whenMatched pipeline $out", agg(M{"$merge": M{"into": "x", "whenMatched": A{M{"$out": "x"}}}}), true)
	add("stage/$merge whenMatched pipeline $lookup", agg(M{"$merge": M{"into": "x", "whenMatched": A{M{"$lookup": M{"from": "d", "as": "z", "pipeline": A{}}}}}}), true)
	add("stage/$merge let $function", agg(M{"$merge": M{"into": "x", "let": M{"a": M{"$function": M{"body": "x", "args": A{}, "lang": "js"}}}}}), true)
	add("stage/$set tenantId then $merge", agg(M{"$set": M{"tenantId": "T2"}}, M{"$merge": "x"}), false)
	add("stage/$replaceRoot tenant then $out", agg(M{"$replaceRoot": M{"newRoot": M{"tenantId": "T2"}}}, M{"$out": "x"}), false)
	add("stage/$unset tenant then $merge", agg(M{"$unset": "tenantId"}, M{"$merge": "x"}), false)
	add("stage/geoNear first", agg(M{"$geoNear": M{"near": M{"type": "Point", "coordinates": A{0, 0}}, "distanceField": "d", "query": M{"tenantId": "T2"}}}), false)
	add("stage/geoNear second", agg(M{"$match": M{}}, M{"$geoNear": M{"near": M{"type": "Point", "coordinates": A{0, 0}}, "distanceField": "d"}}), false)
	add("stage/$text match first", agg(M{"$match": M{"$text": M{"$search": "x"}}}), false)
	add("stage/match $expr with root", agg(M{"$match": M{"$expr": M{"$eq": A{"$tenantId", "T2"}}}}), false)
	add("stage/$redact", agg(M{"$redact": "$$KEEP"}), false)
	add("stage/$sample", agg(M{"$sample": M{"size": 3}}), false)
	add("stage/$setWindowFields", agg(M{"$setWindowFields": M{"sortBy": M{"a": 1}, "output": M{"s": M{"$sum": "$a"}}}}), false)
	add("stage/$densify", agg(M{"$densify": M{"field": "a", "range": M{"step": 1, "bounds": "full"}}}), false)
	add("stage/$unwind", agg(M{"$unwind": "$a"}), false)

	// ---- $expr / $let / JS in unexpected places --------------------------------
	fn := M{"$function": M{"body": "function(){return true}", "args": A{}, "lang": "js"}}
	acc := M{"$accumulator": M{"init": "function(){}", "accumulate": "function(){}", "accumulateArgs": A{}, "merge": "function(){}", "lang": "js"}}
	add("js/where find", withDB(D{s1("find", "c"), s1("filter", M{"$where": "1"})}), true)
	add("js/where in $or", withDB(D{s1("find", "c"), s1("filter", M{"$or": A{M{"a": 1}, M{"$where": "1"}}})}), true)
	add("js/where in $nor", withDB(D{s1("find", "c"), s1("filter", M{"$nor": A{M{"$where": "1"}}})}), true)
	add("js/where under $not", withDB(D{s1("find", "c"), s1("filter", M{"a": M{"$not": M{"$where": "1"}}})}), true)
	add("js/where in $elemMatch", withDB(D{s1("find", "c"), s1("filter", M{"a": M{"$elemMatch": M{"$where": "1"}}})}), true)
	add("js/$expr $let $function", withDB(D{s1("find", "c"), s1("filter", M{"$expr": M{"$let": M{"vars": M{"x": fn}, "in": "$$x"}}})}), true)
	add("js/$expr $reduce $function", withDB(D{s1("find", "c"), s1("filter", M{"$expr": M{"$reduce": M{"input": A{1}, "initialValue": 0, "in": fn}}})}), true)
	add("js/$expr $map $function", withDB(D{s1("find", "c"), s1("filter", M{"$expr": M{"$map": M{"input": A{1}, "in": fn}}})}), true)
	add("js/count $where", withDB(D{s1("count", "c"), s1("query", M{"$where": "1"})}), true)
	add("js/distinct $where", withDB(D{s1("distinct", "c"), s1("key", "a"), s1("query", M{"$where": "1"})}), true)
	add("js/find let", withDB(D{s1("find", "c"), s1("let", M{"x": fn})}), true)
	add("js/find projection", withDB(D{s1("find", "c"), s1("projection", M{"x": fn})}), true)
	add("js/find sort/hint doc", withDB(D{s1("find", "c"), s1("hint", M{"$where": 1})}), true)
	add("js/find collation key", withDB(D{s1("find", "c"), s1("collation", M{"locale": "en", "$where": 1})}), true)
	add("js/aggregate let", withDB(D{s1("aggregate", "c"), s1("pipeline", A{}), s1("let", M{"x": fn})}), true)
	add("js/aggregate $group accumulator", agg(M{"$group": M{"_id": nil, "x": acc}}), true)
	add("js/aggregate $addFields function", agg(M{"$addFields": M{"x": fn}}), true)
	add("js/aggregate $bucket accumulator", agg(M{"$bucket": M{"groupBy": "$a", "boundaries": A{0, 10}, "output": M{"x": acc}}}), true)
	add("js/aggregate $setWindowFields", agg(M{"$setWindowFields": M{"output": M{"x": acc}}}), true)
	add("js/aggregate $match $expr", agg(M{"$match": M{"$expr": fn}}), true)
	add("js/aggregate $lookup pipeline", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$match": M{"$where": "1"}}}}}), true)
	add("js/aggregate $unionWith pipeline", agg(M{"$unionWith": M{"coll": "d", "pipeline": A{M{"$addFields": M{"x": fn}}}}}), true)
	add("js/aggregate $facet", agg(M{"$facet": M{"a": A{M{"$addFields": M{"x": fn}}}}}), true)
	add("js/aggregate $graphLookup restrict", agg(M{"$graphLookup": M{"from": "c", "startWith": "$a", "connectFromField": "a", "connectToField": "b", "as": "g", "restrictSearchWithMatch": M{"$where": "1"}}}), true)
	add("js/aggregate geoNear query", agg(M{"$geoNear": M{"near": A{0, 0}, "distanceField": "d", "query": M{"$where": "1"}}}), true)
	add("js/update q", upd(M{"q": M{"$where": "1"}, "u": M{"$set": M{"a": 1}}}), true)
	add("js/update c", upd(M{"q": M{}, "u": A{M{"$set": M{"x": "$$v"}}}, "c": M{"v": fn}}), true)
	add("js/update pipeline $set", upd(M{"q": M{}, "u": A{M{"$set": M{"x": fn}}}}), true)
	add("js/update let", withDB(D{s1("update", "c"), s1("updates", A{M{"q": M{}, "u": M{"$set": M{"a": 1}}}}), s1("let", M{"x": fn})}), true)
	add("js/update arrayFilters", upd(M{"q": M{}, "u": M{"$set": M{"a.$[x]": 1}}, "arrayFilters": A{M{"x.$where": 1}}}), false)
	add("js/update hint", upd(M{"q": M{}, "u": M{"$set": M{"a": 1}}, "hint": M{"$where": 1}}), true)
	add("js/delete q", withDB(D{s1("delete", "c"), s1("deletes", A{M{"q": M{"$where": "1"}, "limit": 0}})}), true)
	add("js/delete let", withDB(D{s1("delete", "c"), s1("deletes", A{M{"q": M{}, "limit": 0}}), s1("let", M{"x": fn})}), true)
	add("js/findAndModify query", withDB(D{s1("findAndModify", "c"), s1("query", M{"$where": 1}), s1("remove", true)}), true)
	add("js/findAndModify fields", withDB(D{s1("findAndModify", "c"), s1("query", M{}), s1("remove", true), s1("fields", M{"x": fn})}), true)
	add("js/findAndModify pipeline update", withDB(D{s1("findAndModify", "c"), s1("query", M{}), s1("update", A{M{"$set": M{"x": fn}}})}), true)
	add("js/findAndModify let", withDB(D{s1("findAndModify", "c"), s1("query", M{}), s1("remove", true), s1("let", M{"x": fn})}), true)
	add("js/createIndexes partialFilterExpression", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"a": 1}, "name": "a", "partialFilterExpression": M{"$where": 1}}})}), true)
	add("js/createIndexes ttl pfe", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"a": 1}, "name": "a", "expireAfterSeconds": 5, "partialFilterExpression": M{"$expr": fn}}})}), true)
	add("js/createIndexes other spec field", withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"a": 1}, "name": "a", "storageEngine": M{"$function": 1}}})}), true)
	add("js/explain find", withDB(D{s1("explain", D{s1("find", "c"), s1("filter", M{"$where": 1})})}), true)
	add("js/explain nested let", withDB(D{s1("explain", D{s1("aggregate", "c"), s1("pipeline", A{}), s1("let", M{"x": fn})})}), true)
	add("js/listCollections filter", withDB(D{s1("listCollections", 1), s1("filter", M{"$where": 1})}), true)
	add("js/top-level junk key", withDB(D{s1("find", "c"), s1("$function", 1)}), true)
	add("js/listDatabases filter", withDB(D{s1("listDatabases", 1), s1("filter", M{"$where": 1})}), true)
	add("js/insert data keys are data", withDB(D{s1("insert", "c"), s1("documents", A{M{"a": M{"$where": "just data"}}})}), false)
	add("js/mapReduce denied", withDB(D{s1("mapReduce", "c"), s1("map", bson.JavaScript("function(){}")), s1("reduce", bson.JavaScript("function(){}")), s1("out", M{"inline": 1})}), true)

	// ---- tenant-field updates ---------------------------------------------------
	for _, op := range []string{"$set", "$setOnInsert", "$unset", "$inc", "$min", "$max", "$mul", "$currentDate", "$push", "$addToSet", "$pull", "$pop", "$pullAll", "$bit", "$rename"} {
		add("update/"+op+" tenantId", upd(M{"q": M{}, "u": M{op: M{"tenantId": "T2"}}}), true)
		add("update/"+op+" tenantId dotted", upd(M{"q": M{}, "u": M{op: M{"tenantId.x": "T2"}}}), true)
		add("update/"+op+" tenantId positional", upd(M{"q": M{}, "u": M{op: M{"tenantId.$": "T2"}}}), true)
		add("update/"+op+" tenantId index", upd(M{"q": M{}, "u": M{op: M{"tenantId.0": "T2"}}}), true)
		add("update/"+op+" tenantId $[]", upd(M{"q": M{}, "u": M{op: M{"tenantId.$[]": "T2"}}}), true)
		add("update/"+op+" tenantId arrayFilter", upd(M{"q": M{}, "u": M{op: M{"tenantId.$[x]": "T2"}}, "arrayFilters": A{M{"x": "T1"}}}), true)
	}
	add("update/$rename onto tenantId", upd(M{"q": M{}, "u": M{"$rename": M{"a": "tenantId"}}}), true)
	add("update/$rename onto tenantId.x", upd(M{"q": M{}, "u": M{"$rename": M{"a": "tenantId.x"}}}), true)
	add("update/$rename from tenantId", upd(M{"q": M{}, "u": M{"$rename": M{"tenantId": "a"}}}), true)
	add("update/$rename other fields ok", upd(M{"q": M{}, "u": M{"$rename": M{"a": "b"}}}), false)
	add("update/$setOnInsert with upsert", upd(M{"q": M{"a": 1}, "u": M{"$setOnInsert": M{"tenantId": "T2"}}, "upsert": true}), true)
	add("update/upsert other fields", upd(M{"q": M{"a": 1}, "u": M{"$setOnInsert": M{"b": 1}}, "upsert": true}), false)
	add("update/upsert replacement", upd(M{"q": M{"a": 1}, "u": M{"a": 1}, "upsert": true}), false)
	add("update/upsert q sets other tenant", upd(M{"q": M{"tenantId": "T2"}, "u": M{"$set": M{"a": 1}}, "upsert": true}), false)
	add("update/replacement other tenant", upd(M{"q": M{}, "u": M{"tenantId": "T2"}}), true)
	add("update/replacement int tenant", upd(M{"q": M{}, "u": M{"tenantId": 1}}), true)
	add("update/replacement null tenant", upd(M{"q": M{}, "u": M{"tenantId": nil}}), true)
	add("update/replacement array tenant", upd(M{"q": M{}, "u": M{"tenantId": A{"T1"}}}), true)
	add("update/replacement doc tenant", upd(M{"q": M{}, "u": M{"tenantId": M{"$eq": "T1"}}}), true)
	add("update/replacement same tenant", upd(M{"q": M{}, "u": M{"tenantId": "T1", "a": 1}}), false)
	add("update/replacement empty", upd(M{"q": M{}, "u": M{}}), false)
	add("update/replacement with operator key later", upd(M{"q": M{}, "u": D{s1("a", 1), s1("$set", M{"b": 1})}}), true)
	add("update/operator then plain key", upd(M{"q": M{}, "u": D{s1("$set", M{"b": 1}), s1("tenantId", "T2")}}), true)
	add("update/pipeline set tenant", upd(M{"q": M{}, "u": A{M{"$set": M{"tenantId": "T2"}}}}), false)
	add("update/pipeline unset tenant", upd(M{"q": M{}, "u": A{M{"$unset": "tenantId"}}}), false)
	add("update/pipeline replaceRoot", upd(M{"q": M{}, "u": A{M{"$replaceRoot": M{"newRoot": M{"tenantId": "T2"}}}}}), false)
	add("update/pipeline replaceWith", upd(M{"q": M{}, "u": A{M{"$replaceWith": M{"tenantId": "T2"}}}}), false)
	add("update/pipeline project", upd(M{"q": M{}, "u": A{M{"$project": M{"tenantId": 0}}}}), false)
	add("update/pipeline empty", upd(M{"q": M{}, "u": A{}}), false)
	for _, st := range []string{"$match", "$lookup", "$out", "$merge", "$group", "$unionWith", "$facet", "$graphLookup", "$limit", "$sort", "$unwind", "$count", "$sample", "$redact", "$documents", "$changeStream"} {
		add("update/pipeline smuggles "+st, upd(M{"q": M{}, "u": A{M{st: M{}}}}), true)
	}
	add("update/pipeline two-field stage", upd(M{"q": M{}, "u": A{D{s1("$set", M{"a": 1}), s1("$out", "x")}}}), true)
	add("update/q missing", upd(M{"u": M{"$set": M{"a": 1}}}), false)
	add("update/q override attempt", upd(M{"q": M{"$or": A{M{"tenantId": "T2"}, M{"a": 1}}}, "u": M{"$set": M{"a": 1}}}), false)
	add("update/multi", upd(M{"q": M{}, "u": M{"$set": M{"a": 1}}, "multi": true}), false)
	add("update/arrayFilters", upd(M{"q": M{}, "u": M{"$set": M{"a.$[x].b": 1}}, "arrayFilters": A{M{"x.c": 1}}}), false)
	add("update/statement extra keys", upd(M{"q": M{}, "u": M{"$set": M{"a": 1}}, "hint": M{"a": 1}, "collation": M{"locale": "simple"}}), false)
	add("update/stmts via seq", withDB(D{s1("update", "c")}), false)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("updates", M{"q": M{}, "u": M{"$set": M{"a": 1}}})}
	add("update/stmts via seq set tenant", withDB(D{s1("update", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("updates", M{"q": M{}, "u": M{"$set": M{"tenantId": "T2"}}})}
	add("update/stmts in both body and seq", upd(M{"q": M{}, "u": M{"$set": M{"a": 1}}}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("updates", M{"q": M{"tenantId": "T2"}, "u": M{"$set": M{"tenantId": "T2"}}})}
	add("update/unexpected seq id", withDB(D{s1("update", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"q": M{}, "u": M{"$set": M{"a": 1}}})}
	add("delete/q override attempt", withDB(D{s1("delete", "c"), s1("deletes", A{M{"q": M{"$or": A{M{"tenantId": "T2"}, M{"a": 1}}}, "limit": 0}})}), false)
	add("delete/no q", withDB(D{s1("delete", "c"), s1("deletes", A{M{"limit": 0}})}), false)
	add("delete/empty q", withDB(D{s1("delete", "c"), s1("deletes", A{M{"q": M{}, "limit": 0}})}), false)
	add("delete/in both body and seq", withDB(D{s1("delete", "c"), s1("deletes", A{M{"q": M{}, "limit": 0}})}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("deletes", M{"q": M{"tenantId": "T2"}, "limit": 0})}

	// ---- insert --------------------------------------------------------------
	ins := func(tenantVal any) D {
		return withDB(D{s1("insert", "c"), s1("documents", A{M{"a": 1, "tenantId": tenantVal}})})
	}
	add("insert/tenantId same string", ins("T1"), false)
	add("insert/tenantId other string", ins("T2"), true)
	add("insert/tenantId case variant", ins("t1"), true)
	add("insert/tenantId trailing space", ins("T1 "), true)
	add("insert/tenantId int", ins(1), true)
	add("insert/tenantId int64", ins(int64(1)), true)
	add("insert/tenantId double", ins(1.0), true)
	add("insert/tenantId null", ins(nil), true)
	add("insert/tenantId bool", ins(true), true)
	add("insert/tenantId array containing tenant", ins(A{"T1"}), true)
	add("insert/tenantId array of two", ins(A{"T1", "T2"}), true)
	add("insert/tenantId doc", ins(M{"$eq": "T1"}), true)
	add("insert/tenantId objectId", ins(bson.NewObjectID()), true)
	add("insert/tenantId binary", ins(bson.Binary{Data: []byte("T1")}), true)
	add("insert/tenantId symbol", ins(bson.Symbol("T1")), true)
	add("insert/tenantId regex", ins(bson.Regex{Pattern: "^T"}), true)
	add("insert/tenantId absent", withDB(D{s1("insert", "c"), s1("documents", A{M{"a": 1}})}), false)
	add("insert/nested tenantId is data", withDB(D{s1("insert", "c"), s1("documents", A{M{"a": M{"tenantId": "T2"}}})}), false)
	add("insert/dotted tenantId key is data", withDB(D{s1("insert", "c"), s1("documents", A{M{"tenantId.x": "T2"}})}), false)
	add("insert/second doc foreign", withDB(D{s1("insert", "c"), s1("documents", A{M{"a": 1}, M{"tenantId": "T2"}})}), true)
	add("insert/empty documents", withDB(D{s1("insert", "c"), s1("documents", A{})}), false)
	add("insert/seq foreign", withDB(D{s1("insert", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"a": 1}, M{"tenantId": "T2"})}
	add("insert/seq ok", withDB(D{s1("insert", "c")}), false)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"a": 1}, M{"tenantId": "T1"})}
	add("insert/two seqs second foreign", withDB(D{s1("insert", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"a": 1}), seqOf("documents", M{"tenantId": "T2"})}
	add("insert/body and seq", withDB(D{s1("insert", "c"), s1("documents", A{M{"a": 1}})}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"tenantId": "T2"})}
	add("insert/unknown seq id", withDB(D{s1("insert", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("updates", M{"a": 1})}
	add("insert/__mtp_ collection", withDB(D{s1("insert", "__mtp_views"), s1("documents", A{M{"a": 1}})}), true)
	add("insert/system collection", withDB(D{s1("insert", "system.js"), s1("documents", A{M{"a": 1}})}), true)

	// ---- findAndModify -------------------------------------------------------
	fm := func(extra ...bson.E) D { return withDB(append(D{s1("findAndModify", "c")}, extra...)) }
	add("fam/remove", fm(s1("query", M{"a": 1}), s1("remove", true)), false)
	add("fam/no query", fm(s1("remove", true)), false)
	add("fam/update op", fm(s1("query", M{}), s1("update", M{"$inc": M{"n": 1}})), false)
	add("fam/update op tenant", fm(s1("query", M{}), s1("update", M{"$set": M{"tenantId": "T2"}})), true)
	add("fam/update replacement", fm(s1("query", M{}), s1("update", M{"a": 1}), s1("upsert", true), s1("new", true)), false)
	add("fam/update replacement foreign", fm(s1("query", M{}), s1("update", M{"tenantId": "T2"})), true)
	add("fam/update pipeline", fm(s1("query", M{}), s1("update", A{M{"$set": M{"tenantId": "T2"}}})), false)
	add("fam/update pipeline $out", fm(s1("query", M{}), s1("update", A{M{"$out": "x"}})), true)
	add("fam/lowercase name", withDB(D{s1("findandmodify", "c"), s1("query", M{}), s1("remove", true)}), false)
	add("fam/upsert op", fm(s1("query", M{"a": 1}), s1("update", M{"$setOnInsert": M{"b": 1}}), s1("upsert", true)), false)
	add("fam/sort fields", fm(s1("query", M{}), s1("sort", M{"a": 1}), s1("fields", M{"a": 1}), s1("remove", true)), false)
	add("fam/arrayFilters", fm(s1("query", M{}), s1("update", M{"$set": M{"a.$[x]": 1}}), s1("arrayFilters", A{M{"x": 1}})), false)
	add("fam/with seq", fm(s1("query", M{}), s1("remove", true)), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"a": 1})}
	add("fam/query override attempt", fm(s1("query", M{"$or": A{M{"tenantId": "T2"}, M{}}}), s1("remove", true)), false)

	// ---- explain ---------------------------------------------------------------
	add("explain/find", withDB(D{s1("explain", D{s1("find", "c"), s1("filter", M{"a": 1})}), s1("verbosity", "queryPlanner")}), false)
	add("explain/aggregate with $out", withDB(D{s1("explain", D{s1("aggregate", "c"), s1("pipeline", A{M{"$out": "x"}})})}), false)
	add("explain/aggregate $lookup", withDB(D{s1("explain", D{s1("aggregate", "c"), s1("pipeline", A{M{"$lookup": M{"from": "d", "as": "x", "localField": "a", "foreignField": "b"}}})})}), false)
	add("explain/count", withDB(D{s1("explain", D{s1("count", "c")})}), false)
	add("explain/distinct", withDB(D{s1("explain", D{s1("distinct", "c"), s1("key", "a")})}), false)
	add("explain/update", withDB(D{s1("explain", D{s1("update", "c"), s1("updates", A{M{"q": M{}, "u": M{"$set": M{"a": 1}}}})})}), false)
	add("explain/update tenant", withDB(D{s1("explain", D{s1("update", "c"), s1("updates", A{M{"q": M{}, "u": M{"$set": M{"tenantId": "T2"}}}})})}), true)
	add("explain/delete", withDB(D{s1("explain", D{s1("delete", "c"), s1("deletes", A{M{"q": M{}, "limit": 0}})})}), false)
	add("explain/findAndModify", withDB(D{s1("explain", D{s1("findAndModify", "c"), s1("query", M{}), s1("remove", true)})}), false)
	add("explain/findandmodify lowercase", withDB(D{s1("explain", D{s1("findandmodify", "c"), s1("query", M{}), s1("remove", true)})}), false)
	add("explain/insert", withDB(D{s1("explain", D{s1("insert", "c"), s1("documents", A{})})}), true)
	add("explain/explain", withDB(D{s1("explain", D{s1("explain", D{s1("find", "c")})})}), true)
	add("explain/drop", withDB(D{s1("explain", D{s1("drop", "c")})}), true)
	add("explain/createIndexes", withDB(D{s1("explain", D{s1("createIndexes", "c"), s1("indexes", A{})})}), true)
	add("explain/mapReduce", withDB(D{s1("explain", D{s1("mapReduce", "c")})}), true)
	add("explain/empty", withDB(D{s1("explain", M{})}), true)
	add("explain/inner denied command", withDB(D{s1("explain", D{s1("dropDatabase", 1)})}), true)
	add("explain/inner collation weak", withDB(D{s1("explain", D{s1("find", "c"), s1("collation", M{"locale": "en", "strength": 1})})}), true)
	add("explain/inner bad coll", withDB(D{s1("explain", D{s1("find", "system.users")})}), true)
	add("explain/outer extra keys", withDB(D{s1("explain", D{s1("find", "c")}), s1("verbosity", "executionStats"), s1("comment", "x")}), false)
	add("explain/inner $db other", withDB(D{s1("explain", D{s1("find", "c"), s1("$db", "admin")})}), false)

	// ---- collation ---------------------------------------------------------------
	weak := []M{
		{"locale": "en", "strength": 1},
		{"locale": "en", "strength": 2},
		{"locale": "en", "strength": int64(2)},
		{"locale": "en", "strength": 1.0},
		{"locale": "en", "strength": "1"},
		{"locale": "en", "alternate": "shifted"},
		{"locale": "en", "alternate": 1},
		{"locale": "en", "numericOrdering": true},
		{"locale": "en", "strength": 1, "caseLevel": true},
	}
	for i, c := range weak {
		n := string(rune('a' + i))
		add("collation/weak find "+n, withDB(D{s1("find", "c"), s1("collation", c)}), true)
		add("collation/weak count "+n, withDB(D{s1("count", "c"), s1("collation", c)}), true)
		add("collation/weak distinct "+n, withDB(D{s1("distinct", "c"), s1("key", "a"), s1("collation", c)}), true)
		add("collation/weak aggregate "+n, withDB(D{s1("aggregate", "c"), s1("pipeline", A{}), s1("collation", c)}), true)
		add("collation/weak update stmt "+n, upd(M{"q": M{}, "u": M{"$set": M{"a": 1}}, "collation": c}), true)
		add("collation/weak delete stmt "+n, withDB(D{s1("delete", "c"), s1("deletes", A{M{"q": M{}, "limit": 0, "collation": c}})}), true)
		add("collation/weak findAndModify "+n, withDB(D{s1("findAndModify", "c"), s1("query", M{}), s1("remove", true), s1("collation", c)}), true)
		add("collation/weak index "+n, withDB(D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"a": 1}, "name": "ci", "collation": c}})}), true)
		add("collation/weak mapReduce "+n, withDB(D{s1("mapReduce", "c"), s1("collation", c), s1("out", M{"inline": 1})}), true)
	}
	add("collation/weak update stmt via seq", withDB(D{s1("update", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("updates", M{"q": M{}, "u": M{"$set": M{"a": 1}}, "collation": M{"locale": "en", "strength": 1}})}
	add("collation/weak delete stmt via seq", withDB(D{s1("delete", "c")}), true)
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("deletes", M{"q": M{}, "limit": 0, "collation": M{"locale": "en", "strength": 2}})}
	add("collation/not a doc", withDB(D{s1("find", "c"), s1("collation", "en")}), true)
	for i, c := range []M{{"locale": "en"}, {"locale": "en", "strength": 3}, {"locale": "fr", "strength": 4}, {"locale": "simple"}, {"locale": "simple", "strength": 1}, {"locale": "en", "alternate": "non-ignorable"}, {"locale": "en", "numericOrdering": false}, {"locale": "en", "strength": 3, "caseLevel": true}} {
		add("collation/ok find "+string(rune('a'+i)), withDB(D{s1("find", "c"), s1("collation", c)}), false)
	}
	add("collation/ok aggregate", withDB(D{s1("aggregate", "c"), s1("pipeline", A{}), s1("collation", M{"locale": "en", "strength": 3})}), false)

	// ---- create ------------------------------------------------------------------
	add("create/plain", withDB(D{s1("create", "c")}), false)
	add("create/with comment", withDB(D{s1("create", "c"), s1("comment", "x")}), false)
	for _, o := range []bson.E{
		s1("capped", true), s1("size", 1), s1("max", 1), s1("validator", M{"a": M{"$exists": true}}),
		s1("validationLevel", "strict"), s1("validationAction", "error"), s1("collation", M{"locale": "en", "strength": 1}),
		s1("expireAfterSeconds", 1), s1("clusteredIndex", M{"key": M{"_id": 1}, "unique": true}),
		s1("storageEngine", M{"wiredTiger": M{}}), s1("indexOptionDefaults", M{}), s1("autoIndexId", false),
		s1("changeStreamPreAndPostImages", M{"enabled": false}), s1("timeseries", M{"timeField": "t"}),
		s1("viewOn", "x"), s1("pipeline", A{}), s1("clone", true), s1("temp", true), s1("flags", 2),
		s1("encryptedFields", M{}), s1("recordPreImages", true),
	} {
		add("create/"+o.Key, withDB(D{s1("create", "c"), o}), true)
	}
	add("create/system", withDB(D{s1("create", "system.js")}), true)

	// ---- indexes -----------------------------------------------------------------
	ci := func(specs ...any) D { return withDB(D{s1("createIndexes", "c"), s1("indexes", A(specs))}) }
	add("index/plain", ci(M{"key": M{"a": 1}, "name": "a_1"}), false)
	add("index/no name", ci(M{"key": M{"a": 1}}), false)
	add("index/tenantId first", ci(M{"key": D{s1("tenantId", 1), s1("a", 1)}, "name": "t"}), false)
	add("index/tenantId only", ci(M{"key": M{"tenantId": 1}, "name": "t"}), false)
	add("index/tenantId later", ci(M{"key": D{s1("a", 1), s1("tenantId", 1)}, "name": "t"}), true)
	add("index/tenantId twice", ci(M{"key": rawElems(bsoncore.AppendInt32Element(nil, "tenantId", 1), bsoncore.AppendInt32Element(nil, "tenantId", -1)), "name": "t"}), false)
	add("index/tenantId dotted", ci(M{"key": M{"tenantId.x": 1}, "name": "t"}), false)
	add("index/_id only", ci(M{"key": M{"_id": 1}, "name": "x"}), false)
	add("index/empty key", ci(M{"key": M{}, "name": "x"}), true)
	add("index/no key", ci(M{"name": "x"}), true)
	add("index/text", ci(M{"key": M{"a": "text"}, "name": "tx"}), false)
	add("index/2dsphere", ci(M{"key": M{"loc": "2dsphere"}, "name": "g"}), false)
	add("index/wildcard", ci(M{"key": M{"$**": 1}, "name": "w"}), false)
	add("index/hashed", ci(M{"key": M{"a": "hashed"}, "name": "h"}), false)
	add("index/unique", ci(M{"key": M{"a": 1}, "name": "u", "unique": true}), false)
	add("index/unique on tenantId alone (caps every tenant at one doc)", ci(M{"key": M{"tenantId": 1}, "name": "t", "unique": true}), true)
	add("index/unique on tenantId.x alone", ci(M{"key": M{"tenantId.x": 1}, "name": "t", "unique": true}), true)
	add("index/unique on tenantId numeric flag", ci(M{"key": M{"tenantId": 1}, "name": "t", "unique": 1}), true)
	add("index/unique tenantId + a", ci(M{"key": D{s1("tenantId", 1), s1("a", 1)}, "name": "t", "unique": true}), false)
	add("index/unique ttl", ci(M{"key": M{"a": 1}, "name": "u", "unique": true, "expireAfterSeconds": 1}), true)
	add("index/unique ttl numeric", ci(M{"key": M{"a": 1}, "name": "u", "unique": 1, "expireAfterSeconds": 1}), true)
	add("index/unique ttl string", ci(M{"key": M{"a": 1}, "name": "u", "unique": "yes", "expireAfterSeconds": 1}), true)
	add("index/ttl", ci(M{"key": M{"t": 1}, "name": "ttl", "expireAfterSeconds": 1}), false)
	add("index/ttl no name", ci(M{"key": M{"t": 1}, "expireAfterSeconds": 1}), false)
	add("index/ttl with pfe", ci(M{"key": M{"t": 1}, "name": "ttl", "expireAfterSeconds": 1, "partialFilterExpression": M{"tenantId": "T2"}}), false)
	add("index/ttl with pfe $or", ci(M{"key": M{"t": 1}, "name": "ttl", "expireAfterSeconds": 1, "partialFilterExpression": M{"$or": A{M{"tenantId": "T2"}}}}), false)
	add("index/ttl on _id", ci(M{"key": M{"_id": 1}, "name": "ttl", "expireAfterSeconds": 0}), false)
	add("index/ttl expire as string", ci(M{"key": M{"t": 1}, "name": "ttl", "expireAfterSeconds": "1"}), false)
	add("index/ttl second spec", ci(M{"key": M{"a": 1}, "name": "a"}, M{"key": M{"t": 1}, "name": "ttl", "expireAfterSeconds": 1}), false)
	add("index/ttl key mtp_ default name", ci(M{"key": M{"mtp_tenantId_a": 1}, "expireAfterSeconds": 1}), false)
	add("index/ttl key with tag", ci(M{"key": M{"x__mtp_tdeadbeef": 1}, "expireAfterSeconds": 1}), true)
	add("index/key with tag", ci(M{"key": M{"x__mtp_tdeadbeef": 1}}), true)
	add("index/name mtp_", ci(M{"key": M{"a": 1}, "name": "mtp_tenantId_a"}), true)
	add("index/name with tag", ci(M{"key": M{"a": 1}, "name": "a__mtp_tdeadbeef0000"}), true)
	add("index/pfe js", ci(M{"key": M{"a": 1}, "name": "a", "partialFilterExpression": M{"$where": 1}}), true)
	add("drop/name", withDB(D{s1("dropIndexes", "c"), s1("index", "a_1")}), false)
	add("drop/key", withDB(D{s1("dropIndexes", "c"), s1("index", M{"a": 1})}), false)
	add("drop/star", withDB(D{s1("dropIndexes", "c"), s1("index", "*")}), true)
	add("drop/_id_", withDB(D{s1("dropIndexes", "c"), s1("index", "_id_")}), true)
	add("drop/array", withDB(D{s1("dropIndexes", "c"), s1("index", A{"a", "b"})}), true)
	add("drop/mtp_ managed", withDB(D{s1("dropIndexes", "c"), s1("index", "mtp_tenantId__id")}), true)
	add("drop/other tenant's private", withDB(D{s1("dropIndexes", "c"), s1("index", "ttl__mtp_tdeadbeef0000")}), true)
	add("drop/empty key", withDB(D{s1("dropIndexes", "c"), s1("index", M{})}), true)
	add("drop/missing index", withDB(D{s1("dropIndexes", "c")}), true)
	add("listIndexes/plain", withDB(D{s1("listIndexes", "c")}), false)
	add("listIndexes/batchSize 1", withDB(D{s1("listIndexes", "c"), s1("cursor", M{"batchSize": 1})}), false)

	// ---- listCollections / listDatabases ---------------------------------------
	add("listCollections/plain", withDB(D{s1("listCollections", 1)}), false)
	add("listCollections/filter", withDB(D{s1("listCollections", 1), s1("filter", M{"name": "c"})}), false)
	add("listCollections/filter regex internal", withDB(D{s1("listCollections", 1), s1("filter", M{"name": M{"$regex": "^__mtp_"}})}), false)
	add("listCollections/small batch", withDB(D{s1("listCollections", 1), s1("cursor", M{"batchSize": 1})}), false)
	add("listCollections/admin db", D{s1("listCollections", 1), s1("$db", "admin")}, true)
	add("listDatabases/plain", D{s1("listDatabases", 1), s1("$db", "admin")}, false)

	// ---- change streams -------------------------------------------------------
	add("cs/collection", agg(M{"$changeStream": M{}}), false)
	add("cs/cluster", agg(M{"$changeStream": M{"allChangesForCluster": true}}), true)
	add("cs/not first", agg(M{"$match": M{}}, M{"$changeStream": M{}}), true)
	add("cs/after cs", agg(M{"$changeStream": M{}}, M{"$changeStream": M{}}), true)
	add("cs/in lookup", agg(M{"$lookup": M{"from": "d", "as": "x", "pipeline": A{M{"$changeStream": M{}}}}}), true)
	add("cs/in unionWith", agg(M{"$unionWith": M{"coll": "d", "pipeline": A{M{"$changeStream": M{}}}}}), true)
	add("cs/in facet", agg(M{"$facet": M{"a": A{M{"$changeStream": M{}}}}}), true)
	add("cs/fullDocument updateLookup", agg(M{"$changeStream": M{"fullDocument": "updateLookup", "fullDocumentBeforeChange": "whenAvailable"}}), false)
	add("cs/client stages after", agg(M{"$changeStream": M{}}, M{"$match": M{"operationType": "insert"}}, M{"$project": M{"fullDocument.tenantId": 0}}), false)
	add("cs/client $replaceRoot after", agg(M{"$changeStream": M{}}, M{"$replaceRoot": M{"newRoot": M{"x": 1}}}), false)
	add("cs/showExpandedEvents", agg(M{"$changeStream": M{"showExpandedEvents": true}}), false)
	add("cs/db-level", withDB(D{s1("aggregate", 1), s1("pipeline", A{M{"$changeStream": M{}}}), s1("cursor", M{})}), false)
	add("cs/db-level cluster", withDB(D{s1("aggregate", 1), s1("pipeline", A{M{"$changeStream": M{"allChangesForCluster": true}}})}), true)
	add("cs/db-level not first", withDB(D{s1("aggregate", 1), s1("pipeline", A{M{"$match": M{}}, M{"$changeStream": M{}}})}), true)
	add("cs/db-level with $lookup after", withDB(D{s1("aggregate", 1), s1("pipeline", A{M{"$changeStream": M{}}, M{"$lookup": M{"from": "d", "as": "x", "localField": "a", "foreignField": "b"}}})}), false)
	add("cs/db-level with $out after", withDB(D{s1("aggregate", 1), s1("pipeline", A{M{"$changeStream": M{}}, M{"$out": "x"}})}), false)
	add("cs/resumeAfter junk", agg(M{"$changeStream": M{"resumeAfter": M{"_data": "00"}}}), false)

	// ---- databases / collection names ------------------------------------------
	for _, db := range []string{"admin", "local", "config", "ADMIN", "Admin", "LOCAL", "Config", "", "app.x", "a b", "a/b", "a\\b", "a\"b", "a$b", "a*b", "a<b", "a>b", "a:b", "a|b", "a?b", "a\x00b", "admin\x00", strings.Repeat("a", 64)} {
		add("db/"+strings.ReplaceAll(db, "\x00", "<NUL>"), D{s1("find", "c"), s1("$db", db)}, true)
	}
	add("db/no $db", D{s1("find", "c")}, true)
	add("db/$db int", D{s1("find", "c"), s1("$db", 1)}, true)
	add("db/ok", D{s1("find", "c"), s1("$db", "my-db_1")}, false)
	for _, c := range []string{"", "system.users", "system.views", "system.profile", "system.js", "system.buckets.x", "system.", "__mtp_views", "__mtp_v.abc.x", "__mtp_", "a$b", "$cmd", "a\x00b", "$"} {
		add("coll/"+strings.ReplaceAll(c, "\x00", "<NUL>"), withDB(D{s1("find", c)}), true)
	}
	add("coll/similar names are fine", withDB(D{s1("find", "systemx")}), false)
	add("coll/Mixed-case MTP is not reserved by server but is distinct", withDB(D{s1("find", "__MTP_views")}), false)
	add("coll/unicode", withDB(D{s1("find", "коллекция")}), false)
	add("coll/dots", withDB(D{s1("find", "a.b.c")}), false)

	// ---- commands ---------------------------------------------------------------
	for _, c := range []string{"dropAllUsersFromDatabase", "createUser", "grantRolesToUser", "shutdown", "fsync", "killOp", "renameCollection", "copydb", "eval", "$eval", "applyOps", "replSetGetStatus", "collMod", "compact", "reIndex", "validate", "collStats", "getParameter", "setParameter", "profile", "getLog", "listCommands", "authenticate", "saslStart", "hello", "bulkWrite", "getMore", "killCursors", "FIND", "Find", "insert ", "_id"} {
		add("cmd/"+strings.ReplaceAll(c, "\x00", "<NUL>"), withDB(D{s1(c, 1)}), true)
	}
	add("cmd/ping", withDB(D{s1("ping", 1)}), false)
	add("cmd/buildinfo alias", withDB(D{s1("buildinfo", 1)}), false)
	add("cmd/connectionStatus", withDB(D{s1("connectionStatus", 1), s1("showPrivileges", true)}), false)
	add("cmd/endSessions", withDB(D{s1("endSessions", A{})}), false)
	add("cmd/commitTransaction", withDB(D{s1("commitTransaction", 1)}), false)
	add("cmd/admin passthrough with seq", withDB(D{s1("ping", 1)}), true)
	cs[len(cs)-1].cmd = withDB(D{s1("endSessions", A{})})
	cs[len(cs)-1].seqs = []wire.Seq{seqOf("documents", M{"a": 1})}
	add("cmd/mapReduce to collection", withDB(D{s1("mapReduce", "c"), s1("out", "x")}), true) // JS disabled in this config; output to a collection is tenant-scoped when JS is on
	add("cmd/mapReduce without out", withDB(D{s1("mapReduce", "c")}), true)
	return cs
}

func TestAdversarialCorpus(t *testing.T) {
	for _, tc := range adversarialCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var body bsoncore.Document
			switch c := tc.cmd.(type) {
			case bsoncore.Document:
				body = c
			case D:
				b, err := bson.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				body = b
			default:
				t.Fatalf("bad case type %T", tc.cmd)
			}
			db, _ := body.Lookup("$db").StringValueOK() // like the proxy: "" when absent
			r := New(Config{ChangeStreams: true})
			ten := fuzzTenants()[0]
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("PANIC: %v", p)
				}
			}()
			res, err := r.Rewrite(ten, db, body, tc.seqs)
			if err != nil && strings.Contains(err.Error(), "internal error") {
				t.Fatalf("rewriter panicked: %v", err)
			}
			if tc.reject {
				if err == nil {
					t.Fatalf("expected rejection, got: %s", bson.Raw(res.Body))
				}
				if tc.errHas != "" && !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("error %q does not mention %q", err, tc.errHas)
				}
			} else if err != nil {
				t.Fatalf("expected acceptance, got: %v", err)
			}
			// Whatever the verdict, every configuration and tenant type must
			// satisfy the structural guard and never panic.
			if strings.HasPrefix(tc.name, "limits/") {
				return // huge inputs: one configuration is enough
			}
			for _, rw := range fuzzRewriters() {
				for _, tn := range fuzzTenants() {
					if err := runRewrite(rw, tn, db, body, tc.seqs); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

// AllowJS must still let JavaScript through (but nothing else changes).
func TestAdversarialAllowJS(t *testing.T) {
	r := New(Config{AllowJS: true})
	ten := fuzzTenants()[0]
	for name, cmd := range map[string]D{
		"where":       withDB(D{s1("find", "c"), s1("filter", M{"$where": "this.a == 1"})}),
		"let":         withDB(D{s1("find", "c"), s1("let", M{"x": M{"$function": M{"body": "x", "args": A{}, "lang": "js"}}})}),
		"accumulator": agg(M{"$group": M{"_id": nil, "x": M{"$accumulator": M{"init": "x", "accumulate": "x", "accumulateArgs": A{}, "merge": "x", "lang": "js"}}}}),
	} {
		b, _ := bson.Marshal(cmd)
		if _, err := r.Rewrite(ten, "app", b, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ---- reply post-processing ----------------------------------------------------

func TestListIndexesHidesOtherTenantsIndexes(t *testing.T) {
	r := New(Config{})
	t1 := fuzzTenants()[0]
	t2, _ := NewTenant("string", "T2")
	mine := indexTag(t1)
	theirs := indexTag(t2)
	if mine == theirs || !strings.HasPrefix(mine, indexTagMark) {
		t.Fatalf("bad tags %q %q", mine, theirs)
	}
	resp := mk(t, M{"cursor": M{"id": int64(0), "ns": "app.c", "firstBatch": A{
		M{"v": 2, "key": M{"_id": 1}, "name": "_id_"},
		M{"v": 2, "key": D{s1("tenantId", 1), s1("a", 1)}, "name": "tenantId_1_a_1"},
		M{"v": 2, "key": M{"t": 1}, "name": "ttl" + mine, "expireAfterSeconds": 5, "partialFilterExpression": M{"tenantId": "T1"}},
		M{"v": 2, "key": M{"t": 1}, "name": "ttl" + theirs, "expireAfterSeconds": 5, "partialFilterExpression": M{"tenantId": "T2"}},
		M{"v": 2, "key": M{"t": 1}, "name": "legacy_global_ttl", "expireAfterSeconds": 5},
		M{"v": 2, "key": D{s1("tenantId", 1), s1("b", 1)}, "name": "tenantId_1_b_1"},
	}}, "ok": 1})
	out := r.unprefixIndexes(t1, resp)
	if err := out.Validate(); err != nil {
		t.Fatal(err)
	}
	s := bson.Raw(out).String()
	for _, bad := range []string{theirs, "T2", "legacy_global_ttl"} {
		if strings.Contains(s, bad) {
			t.Errorf("listIndexes leaks %q: %s", bad, s)
		}
	}
	for _, good := range []string{"_id_", "ttl" + mine, `"key": {"a"`, `"key": {"b"`} {
		if !strings.Contains(s, good) {
			t.Errorf("listIndexes lost %q: %s", good, s)
		}
	}
}

func TestListIndexesForcesSingleBatch(t *testing.T) {
	r := New(Config{})
	res, err := rewriteCmd(t, r, D{s1("listIndexes", "c"), s1("cursor", M{"batchSize": 1}), s1("$db", "app")})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.Body.Lookup("cursor", "batchSize").AsInt64OK(); n < 64 {
		t.Fatalf("batchSize not widened: %s", json(res.Body))
	}
}

func TestListCollectionsFiltersServerSide(t *testing.T) {
	r := New(Config{})
	for _, f := range []any{nil, M{"name": "c"}, M{"type": "collection"}} {
		cmd := D{s1("listCollections", 1), s1("$db", "app"), s1("cursor", M{"batchSize": 1})}
		if f != nil {
			cmd = append(cmd, s1("filter", f))
		}
		res, err := rewriteCmd(t, r, cmd)
		if err != nil {
			t.Fatal(err)
		}
		s := json(res.Body)
		if !strings.Contains(s, "__mtp_") || !strings.Contains(s, "system") {
			t.Fatalf("listCollections filter does not hide internal collections: %s", s)
		}
		if f != nil && !strings.Contains(s, "$and") {
			t.Fatalf("client filter lost: %s", s)
		}
	}
}

func TestTTLIndexIsTenantPrivate(t *testing.T) {
	r := New(Config{})
	t1, _ := NewTenant("string", "T1")
	t2, _ := NewTenant("string", "T2")
	body := mk(t, D{s1("createIndexes", "c"), s1("indexes", A{M{"key": M{"createdAt": 1}, "name": "exp", "expireAfterSeconds": 60}}), s1("$db", "app")})
	a, err := r.Rewrite(t1, "app", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Rewrite(t2, "app", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	sa, sb := json(a.Body), json(b.Body)
	if !strings.Contains(sa, `"partialFilterExpression": {"tenantId": "T1"}`) || !strings.Contains(sb, `"partialFilterExpression": {"tenantId": "T2"}`) {
		t.Fatalf("TTL index not confined:\n%s\n%s", sa, sb)
	}
	if sa == sb || !strings.Contains(sa, "exp"+indexTag(t1)) || !strings.Contains(sb, "exp"+indexTag(t2)) {
		t.Fatalf("TTL index names must differ per tenant:\n%s\n%s", sa, sb)
	}
	// A tenant may drop its own private index by name, not another's.
	if _, err := r.Rewrite(t1, "app", mk(t, D{s1("dropIndexes", "c"), s1("index", "exp"+indexTag(t1)), s1("$db", "app")}), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rewrite(t1, "app", mk(t, D{s1("dropIndexes", "c"), s1("index", "exp"+indexTag(t2)), s1("$db", "app")}), nil); err == nil {
		t.Fatal("dropping another tenant's private index must fail")
	}
}

// A hostile tenant id must not be usable to escape the guard either: the
// guard proves containment for every tenant id type.
func TestGuardRejectsBrokenOutput(t *testing.T) {
	r := New(Config{})
	ten := fuzzTenants()[0]
	g := &guard{r: r, t: ten}
	bad := map[string]D{
		"unguarded find":      {s1("find", "c"), s1("filter", M{"a": 1})},
		"or-guard":            {s1("find", "c"), s1("filter", M{"$or": A{M{"tenantId": "T1"}, M{"a": 1}}})},
		"lookup w/o pipe":     {s1("aggregate", "c"), s1("pipeline", A{M{"$match": M{"tenantId": "T1"}}, M{"$lookup": M{"from": "d", "as": "x", "localField": "a", "foreignField": "b"}}})},
		"out survives":        {s1("aggregate", "c"), s1("pipeline", A{M{"$match": M{"tenantId": "T1"}}, M{"$out": "x"}})},
		"first stage sort":    {s1("aggregate", "c"), s1("pipeline", A{M{"$sort": M{"a": 1}}})},
		"facet branch lookup": {s1("aggregate", "c"), s1("pipeline", A{M{"$match": M{"tenantId": "T1"}}, M{"$facet": M{"f": A{M{"$lookup": M{"from": "d", "as": "x"}}}}}})},
		"update sets tenant":  {s1("update", "c"), s1("updates", A{M{"q": M{"tenantId": "T1"}, "u": M{"$set": M{"tenantId": "T2"}}}})},
	}
	for name, cmd := range bad {
		b := mk(t, cmd)
		if err := g.body(CommandName(b), b, nil); err == nil {
			t.Errorf("guard accepted broken output: %s", name)
		}
	}
}

// A bug in a command rewriter must surface as an error for that one request,
// not as a process-wide panic.
func TestRewriterPanicBecomesError(t *testing.T) {
	r := New(Config{})
	r.cmds["boom"] = func(*Rewriter, *request) (*Result, error) { panic("boom") }
	ten := fuzzTenants()[0]
	res, err := r.Rewrite(ten, "app", mk(t, D{s1("boom", 1)}), nil)
	if err == nil || res != nil || !strings.Contains(err.Error(), "internal error") {
		t.Fatalf("panic not contained: %v %v", res, err)
	}
	if _, err := r.ScopeViewPipeline(ten, bsoncore.BuildArray(nil), true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ScopeViewPipeline(ten, bsoncore.Array{1, 2, 3}, true); err == nil {
		t.Fatal("malformed view pipeline accepted")
	}
}
