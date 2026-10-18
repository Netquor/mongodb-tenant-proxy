package rewrite

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// nj renders a document as relaxed JSON with all spaces removed so
// expectations do not depend on formatting.
func nj(d interface{ String() string }) string { return strings.ReplaceAll(d.String(), " ", "") }

func nsRewriter() *Rewriter  { return New(Config{IDPolicy: PolicyNamespace, AllowJS: true}) }
func genRewriter() *Rewriter { return New(Config{IDPolicy: PolicyRequireGenerated, AllowJS: true}) }

func cmd(name, coll string, kv ...any) bson.D {
	d := bson.D{{Key: name, Value: coll}}
	for i := 0; i < len(kv); i += 2 {
		d = append(d, bson.E{Key: kv[i].(string), Value: kv[i+1]})
	}
	return append(d, bson.E{Key: "$db", Value: "app"})
}

func TestNamespaceFilterRewrite(t *testing.T) {
	r := nsRewriter()
	cases := []struct {
		name   string
		filter any
		want   []string
	}{
		{"equality", bson.M{"_id": 5}, []string{`"_id": {"t": "T1", "id": {"$numberInt":"5"}}`}},
		{"in", bson.M{"_id": bson.M{"$in": bson.A{1, 2}}}, []string{`"$in": [{"t": "T1", "id": {"$numberInt":"1"}}`}},
		{"range", bson.M{"_id": bson.M{"$gt": 3}}, []string{`"$gt": {"t": "T1"`}},
		{"nested or", bson.M{"$or": bson.A{bson.M{"_id": "x"}, bson.M{"a": 1}}}, []string{`"_id": {"t": "T1", "id": "x"}`, `"a"`}},
		{"dotted", bson.M{"_id.a": 1}, []string{`"_id.id.a"`}},
		{"other fields untouched", bson.M{"a": bson.M{"$elemMatch": bson.M{"_id": 1}}}, []string{`"$elemMatch": {"_id": {"$numberInt":"1"}}`}},
	}
	for _, c := range cases {
		res, err := rewriteCmd(t, r, cmd("find", "c", "filter", c.filter))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := nj(res.Body)
		for _, w := range c.want {
			if !has(got, w) {
				t.Errorf("%s: %s missing from %s", c.name, w, got)
			}
		}
	}
}

func TestNamespaceRejections(t *testing.T) {
	r := nsRewriter()
	bad := map[string]bson.D{
		"regex on _id":       cmd("find", "c", "filter", bson.M{"_id": bson.M{"$regex": "^a"}}),
		"regex literal":      cmd("find", "c", "filter", bson.M{"_id": bson.Regex{Pattern: "a"}}),
		"$type on _id":       cmd("find", "c", "filter", bson.M{"_id": bson.M{"$type": "string"}}),
		"$expr on _id":       cmd("find", "c", "filter", bson.M{"$expr": bson.M{"$eq": bson.A{"$_id", 1}}}),
		"$expr ROOT":         cmd("find", "c", "filter", bson.M{"$expr": bson.M{"$eq": bson.A{"$$ROOT", 1}}}),
		"$where":             cmd("find", "c", "filter", bson.M{"$where": "this._id == 1"}),
		"min":                cmd("find", "c", "min", bson.M{"_id": 1}),
		"lookup":             cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$lookup": bson.M{"from": "d", "localField": "a", "foreignField": "b", "as": "x"}}}, "cursor", bson.M{}),
		"merge":              cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$merge": "d"}}, "cursor", bson.M{}),
		"facet":              cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$facet": bson.M{"a": bson.A{}}}}, "cursor", bson.M{}),
		"push ROOT":          cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$group": bson.M{"_id": nil, "all": bson.M{"$push": "$$ROOT"}}}}, "cursor", bson.M{}),
		"group by _id":       cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$group": bson.M{"_id": "$_id"}}}, "cursor", bson.M{}),
		"project from _id":   cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$project": bson.M{"x": "$_id"}}}, "cursor", bson.M{}),
		"mapReduce":          cmd("mapReduce", "c", "map", "f", "reduce", "g", "out", bson.M{"inline": 1}),
		"set _id":            cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"$set": bson.M{"_id": 5}}}}),
		"setOnInsert _id":    cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"$setOnInsert": bson.M{"_id": 5}}, "upsert": true}}),
		"pipeline upsert":    cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.A{bson.M{"$set": bson.M{"b": 1}}}, "upsert": true}}),
		"replacement upsert": cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"b": 1}, "upsert": true}}),
		"array _id insert":   cmd("insert", "c", "documents", bson.A{bson.M{"_id": bson.A{1}}}),
		"change stream":      cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$changeStream": bson.M{}}}, "cursor", bson.M{}),
	}
	for name, c := range bad {
		if _, err := rewriteCmd(t, r, c); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestNamespaceInsertAndUpsert(t *testing.T) {
	r := nsRewriter()
	res, err := rewriteCmd(t, r, cmd("insert", "c", "documents", bson.A{bson.M{"_id": 7, "a": 1}, bson.M{"a": 2}}))
	if err != nil {
		t.Fatal(err)
	}
	got := nj(res.Body)
	if !has(got, `"_id": {"t": "T1", "id": {"$numberInt":"7"}}`) {
		t.Fatalf("explicit _id not wrapped: %s", got)
	}
	if countOf(got, `"_id": {"t": "T1", "id": {"$oid"`) != 1 {
		t.Fatalf("generated _id missing: %s", got)
	}

	// Operator upsert without an _id equality gets a wrapped $setOnInsert _id.
	res, err = rewriteCmd(t, r, cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"$set": bson.M{"b": 1}}, "upsert": true}}))
	if err != nil {
		t.Fatal(err)
	}
	if !has(nj(res.Body), `"$setOnInsert": {"_id": {"t": "T1", "id": {"$oid"`) {
		t.Fatalf("no $setOnInsert _id: %s", nj(res.Body))
	}
	// With an _id equality the server derives the wrapped _id from the filter.
	res, err = rewriteCmd(t, r, cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"_id": 3}, "u": bson.M{"$set": bson.M{"b": 1}}, "upsert": true}}))
	if err != nil {
		t.Fatal(err)
	}
	if has(nj(res.Body), "$setOnInsert") {
		t.Fatalf("unexpected $setOnInsert: %s", nj(res.Body))
	}
}

func TestNamespaceAggregateUnwrapState(t *testing.T) {
	r := nsRewriter()
	res, err := rewriteCmd(t, r, cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$match": bson.M{"_id": 1}}, bson.M{"$sort": bson.M{"_id": 1}}}, "cursor", bson.M{}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IDCursor {
		t.Fatal("plain pipeline should unwrap _id")
	}
	if !has(nj(res.Body), `"_id": {"t": "T1", "id": {"$numberInt":"1"}}`) {
		t.Fatalf("$match not rewritten: %s", nj(res.Body))
	}
	// After $group, _id is the group key and a later $match must not be rewritten.
	res, err = rewriteCmd(t, r, cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$group": bson.M{"_id": "$a"}}, bson.M{"$match": bson.M{"_id": 1}}}, "cursor", bson.M{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.IDCursor || has(nj(res.Body), `"t": "T1", "id"`) {
		t.Fatalf("post-$group handling wrong: %s", nj(res.Body))
	}
}

func TestUnwrapReply(t *testing.T) {
	r := nsRewriter()
	ten, _ := NewTenant("string", "T1")
	w := bson.D{{Key: "t", Value: "T1"}, {Key: "id", Value: 9}}
	resp := mk(t, bson.D{
		{Key: "cursor", Value: bson.D{{Key: "firstBatch", Value: bson.A{
			bson.D{{Key: "_id", Value: w}, {Key: "a", Value: 1}},
			bson.D{{Key: "_id", Value: bson.D{{Key: "t", Value: "OTHER"}, {Key: "id", Value: 1}}}}, // not ours: untouched
		}}, {Key: "id", Value: int64(0)}}},
		{Key: "ok", Value: 1},
	})
	got := nj(r.IDPost(ten)(resp))
	if !has(got, `"_id": {"$numberInt":"9"}`) || !has(got, `"OTHER"`) {
		t.Fatalf("unwrap wrong: %s", got)
	}
}

func TestRequireGenerated(t *testing.T) {
	r := genRewriter()
	oid := bson.NewObjectID()
	uuid := bson.Binary{Subtype: 4, Data: make([]byte, 16)}
	ok := []bson.D{
		cmd("insert", "c", "documents", bson.A{bson.M{"_id": oid}, bson.M{"_id": uuid}, bson.M{"a": 1}}),
		cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"_id": oid}, "u": bson.M{"$set": bson.M{"a": 1}}, "upsert": true}}),
		cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"$set": bson.M{"a": 1}}, "upsert": true}}),
		cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"_id": 5}, "u": bson.M{"$set": bson.M{"a": 1}}}}), // not an upsert
		cmd("findAndModify", "c", "query", bson.M{"_id": oid}, "update", bson.M{"$set": bson.M{"a": 1}}, "upsert", true),
	}
	for i, c := range ok {
		if _, err := rewriteCmd(t, r, c); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string]bson.D{
		"int insert":      cmd("insert", "c", "documents", bson.A{bson.M{"_id": 1}}),
		"string insert":   cmd("insert", "c", "documents", bson.A{bson.M{"_id": "alice"}}),
		"legacy uuid":     cmd("insert", "c", "documents", bson.A{bson.M{"_id": bson.Binary{Subtype: 3, Data: make([]byte, 16)}}}),
		"doc id":          cmd("insert", "c", "documents", bson.A{bson.M{"_id": bson.M{"a": 1}}}),
		"int upsert":      cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"_id": 5}, "u": bson.M{"$set": bson.M{"a": 1}}, "upsert": true}}),
		"$in upsert":      cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"_id": bson.M{"$in": bson.A{oid}}}, "u": bson.M{"$set": bson.M{"a": 1}}, "upsert": true}}),
		"and upsert":      cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"$and": bson.A{bson.M{"_id": "x"}}}, "u": bson.M{"$set": bson.M{"a": 1}}, "upsert": true}}),
		"dotted upsert":   cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"_id.a": 1}, "u": bson.M{"$set": bson.M{"a": 1}}, "upsert": true}}),
		"setOnInsert":     cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"$setOnInsert": bson.M{"_id": "x"}}, "upsert": true}}),
		"replacement":     cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.M{"_id": "x"}, "upsert": true}}),
		"pipeline upsert": cmd("update", "c", "updates", bson.A{bson.M{"q": bson.M{"a": 1}, "u": bson.A{bson.M{"$set": bson.M{"_id": "x"}}}, "upsert": true}}),
		"fam upsert":      cmd("findAndModify", "c", "query", bson.M{"_id": "x"}, "update", bson.M{"$set": bson.M{"a": 1}}, "upsert", true),
	}
	for name, c := range bad {
		if _, err := rewriteCmd(t, r, c); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestScrubDupKey(t *testing.T) {
	resp := mk(t, bson.D{
		{Key: "n", Value: 0},
		{Key: "writeErrors", Value: bson.A{bson.D{
			{Key: "index", Value: 0}, {Key: "code", Value: 11000},
			{Key: "errmsg", Value: "E11000 duplicate key error collection: app.items index: _id_ dup key: { _id: 1 }"},
			{Key: "keyPattern", Value: bson.M{"_id": 1}}, {Key: "keyValue", Value: bson.M{"_id": 1}},
		}, bson.D{
			{Key: "index", Value: 1}, {Key: "code", Value: 11000},
			{Key: "errmsg", Value: "E11000 duplicate key error collection: app.items index: email_1 dup key"},
		}}},
		{Key: "ok", Value: 1},
	})
	got := nj(scrubDupKey(resp))
	if has(got, "_id_") || has(got, "keyValue") || has(got, "dup key: { _id") {
		t.Fatalf("_id duplicate not scrubbed: %s", got)
	}
	if !has(got, "email_1") {
		t.Fatalf("unrelated duplicate must be kept: %s", got)
	}
}

func TestMergeIDCheckUnderRequireGenerated(t *testing.T) {
	r := genRewriter()
	res, err := rewriteCmd(t, r, cmd("aggregate", "c", "pipeline", bson.A{bson.M{"$merge": "d"}}, "cursor", bson.M{}))
	if err != nil {
		t.Fatal(err)
	}
	if !has(nj(res.Body), "__mtp_idcheck") {
		t.Fatalf("no _id check stage: %s", nj(res.Body))
	}
}

func TestMaxTime(t *testing.T) {
	body := mk(t, bson.D{{Key: "find", Value: "c"}, {Key: "$db", Value: "app"}})
	b, err := ApplyMaxTime("find", body, 1000, 500, false)
	if err != nil || !has(nj(b), `"maxTimeMS": {"$numberLong":"500"}`) {
		t.Fatalf("default not applied: %s %v", nj(b), err)
	}
	b, _ = ApplyMaxTime("find", mk(t, bson.D{{Key: "find", Value: "c"}, {Key: "maxTimeMS", Value: 99999}}), 1000, 0, false)
	if !has(nj(b), `"maxTimeMS": {"$numberLong":"1000"}`) {
		t.Fatalf("cap not applied: %s", nj(b))
	}
	b, _ = ApplyMaxTime("find", mk(t, bson.D{{Key: "find", Value: "c"}, {Key: "maxTimeMS", Value: 0}}), 1000, 0, false)
	if !has(nj(b), `1000`) {
		t.Fatalf("maxTimeMS 0 (unlimited) must be capped: %s", nj(b))
	}
	b, _ = ApplyMaxTime("find", mk(t, bson.D{{Key: "find", Value: "c"}, {Key: "maxTimeMS", Value: 50}}), 1000, 500, false)
	if !has(nj(b), `50`) || has(nj(b), `1000`) {
		t.Fatalf("smaller client value must stay: %s", nj(b))
	}
	b, _ = ApplyMaxTime("getMore", mk(t, bson.D{{Key: "getMore", Value: int64(1)}}), 1000, 500, false)
	if has(nj(b), "maxTimeMS") {
		t.Fatalf("getMore must be untouched: %s", nj(b))
	}
}

func TestUsesJSAndIndexNames(t *testing.T) {
	if !UsesJS("find", mk(t, bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"$where": "1"}}})) {
		t.Fatal("$where not detected")
	}
	if UsesJS("find", mk(t, bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"a": 1}}})) {
		t.Fatal("false positive")
	}
	got := IndexNames("app", mk(t, bson.D{{Key: "createIndexes", Value: "c"}, {Key: "indexes", Value: bson.A{
		bson.M{"key": bson.D{{Key: "a", Value: 1}, {Key: "b", Value: -1}}},
		bson.M{"key": bson.M{"x": 1}, "name": "custom"},
	}}}))
	if len(got) != 2 || got[0] != "app.c#a_1_b_-1" || got[1] != "app.c#custom" {
		t.Fatalf("index names: %v", got)
	}
}

func countOf(got, want string) int { return strings.Count(got, strings.ReplaceAll(want, " ", "")) }
