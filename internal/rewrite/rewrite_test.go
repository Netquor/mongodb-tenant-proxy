package rewrite

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

func mk(t testing.TB, v any) bsoncore.Document {
	t.Helper()
	b, err := bson.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rewriteCmd(t testing.TB, r *Rewriter, cmd bson.D, seqs ...wire.Seq) (*Result, error) {
	t.Helper()
	ten, _ := NewTenant("string", "T1")
	db := "app"
	for _, e := range cmd {
		if e.Key == "$db" {
			db = e.Value.(string)
		}
	}
	return r.Rewrite(ten, db, mk(t, cmd), seqs)
}

func json(d bsoncore.Document) string { return bson.Raw(d).String() }

func TestFindFilterIsAnded(t *testing.T) {
	r := New(Config{})
	res, err := rewriteCmd(t, r, bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"a": 1}}, {Key: "$db", Value: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	got := json(res.Body)
	if !strings.Contains(got, `"$and"`) || !strings.Contains(got, `"tenantId": "T1"`) || !strings.Contains(got, `"a": {"$numberInt":"1"}`) {
		t.Fatalf("unexpected rewrite: %s", got)
	}
	// Command name must stay first.
	if CommandName(res.Body) != "find" {
		t.Fatal("command name moved")
	}
}

func TestMissingFilterGetsTenant(t *testing.T) {
	r := New(Config{})
	res, err := rewriteCmd(t, r, bson.D{{Key: "find", Value: "c"}, {Key: "$db", Value: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(json(res.Body), `"filter": {"tenantId": "T1"}`) {
		t.Fatalf("filter not injected: %s", json(res.Body))
	}
}

func TestRejections(t *testing.T) {
	r := New(Config{})
	cases := map[string]bson.D{
		"unknown command":    {{Key: "dropDatabase", Value: 1}, {Key: "$db", Value: "app"}},
		"admin db":           {{Key: "find", Value: "c"}, {Key: "$db", Value: "admin"}},
		"system collection":  {{Key: "find", Value: "system.users"}, {Key: "$db", Value: "app"}},
		"$where":             {{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"$where": "1"}}, {Key: "$db", Value: "app"}},
		"nested $function":   {{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"$expr": bson.M{"$function": bson.M{}}}}, {Key: "$db", Value: "app"}},
		"merge not last":     {{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$merge": "x"}, bson.M{"$limit": 1}}}, {Key: "$db", Value: "app"}},
		"lookup w/o from":    {{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$lookup": bson.M{"as": "x", "pipeline": bson.A{bson.M{"$documents": bson.A{}}}}}}}, {Key: "$db", Value: "app"}},
		"lookup other db":    {{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$lookup": bson.M{"from": bson.M{"db": "admin", "coll": "system.users"}, "as": "x", "pipeline": bson.A{}}}}}, {Key: "$db", Value: "app"}},
		"two-field stage":    {{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.D{{Key: "$match", Value: bson.M{}}, {Key: "$out", Value: "x"}}}}, {Key: "$db", Value: "app"}},
		"duplicate filter":   {{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{}}, {Key: "filter", Value: bson.M{"tenantId": "T2"}}, {Key: "$db", Value: "app"}},
		"foreign tenant doc": {{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"tenantId": "T2"}}}, {Key: "$db", Value: "app"}},
		"set tenant":         {{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{bson.M{"q": bson.M{}, "u": bson.M{"$set": bson.M{"tenantId": "T2"}}}}}, {Key: "$db", Value: "app"}},
		"set tenant sub":     {{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{bson.M{"q": bson.M{}, "u": bson.M{"$set": bson.M{"tenantId.x": 1}}}}}, {Key: "$db", Value: "app"}},
		"rename to tenant":   {{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{bson.M{"q": bson.M{}, "u": bson.M{"$rename": bson.M{"a": "tenantId"}}}}}, {Key: "$db", Value: "app"}},
		"operator in repl":   {{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{bson.D{{Key: "q", Value: bson.M{}}, {Key: "u", Value: bson.D{{Key: "a", Value: 1}, {Key: "$set", Value: bson.M{"b": 1}}}}}}}, {Key: "$db", Value: "app"}},
		"bad update stage":   {{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{bson.M{"q": bson.M{}, "u": bson.A{bson.M{"$match": bson.M{}}}}}}, {Key: "$db", Value: "app"}},
		"reserved name":      {{Key: "find", Value: "__mtp_views"}, {Key: "$db", Value: "app"}},
		"drop all indexes":   {{Key: "dropIndexes", Value: "c"}, {Key: "index", Value: "*"}, {Key: "$db", Value: "app"}},
		"explain insert":     {{Key: "explain", Value: bson.D{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{}}}}, {Key: "$db", Value: "app"}},
		"unexpected seq":     {{Key: "find", Value: "c"}, {Key: "$db", Value: "app"}},
	}
	for name, cmd := range cases {
		var seqs []wire.Seq
		if name == "unexpected seq" {
			seqs = []wire.Seq{{ID: "documents", Docs: []bsoncore.Document{mk(t, bson.M{"a": 1})}}}
		}
		if _, err := rewriteCmd(t, r, cmd, seqs...); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestDenyCommandsAndJS(t *testing.T) {
	r := New(Config{DenyCommands: []string{"distinct"}})
	if _, err := rewriteCmd(t, r, bson.D{{Key: "distinct", Value: "c"}, {Key: "key", Value: "a"}, {Key: "$db", Value: "app"}}); err == nil {
		t.Fatal("denied command accepted")
	}
	r = New(Config{AllowJS: true})
	if _, err := rewriteCmd(t, r, bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"$where": "1"}}, {Key: "$db", Value: "app"}}); err != nil {
		t.Fatalf("AllowJS should permit $where: %v", err)
	}
}

func TestDatabaseAllowList(t *testing.T) {
	r := New(Config{Databases: []string{"app"}})
	ten, _ := NewTenant("string", "T1")
	if _, err := r.Rewrite(ten, "other", mk(t, bson.D{{Key: "find", Value: "c"}}), nil); err == nil {
		t.Fatal("database outside allow-list accepted")
	}
	if _, err := r.Rewrite(ten, "app", mk(t, bson.D{{Key: "find", Value: "c"}}), nil); err != nil {
		t.Fatal(err)
	}
}

func TestInsertSequence(t *testing.T) {
	r := New(Config{})
	seq := wire.Seq{ID: "documents", Docs: []bsoncore.Document{mk(t, bson.M{"a": 1}), mk(t, bson.M{"b": 2, "tenantId": "T1"})}}
	res, err := rewriteCmd(t, r, bson.D{{Key: "insert", Value: "c"}, {Key: "$db", Value: "app"}}, seq)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Seqs[0].Docs {
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
		if s, _ := d.Lookup("tenantId").StringValueOK(); s != "T1" {
			t.Fatalf("doc not stamped: %s", json(d))
		}
	}
	// Input must not have been mutated.
	if seq.Docs[0].Lookup("tenantId").Type != 0 {
		t.Fatal("rewriter mutated its input")
	}
}

func TestPipelineUpdateReassertsTenant(t *testing.T) {
	r := New(Config{})
	res, err := rewriteCmd(t, r, bson.D{{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{
		bson.M{"q": bson.M{}, "u": bson.A{bson.M{"$set": bson.M{"tenantId": "evil"}}}},
	}}, {Key: "$db", Value: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	got := json(res.Body)
	if !strings.Contains(got, `{"$set": {"tenantId": "evil"}},{"$set": {"tenantId": "T1"}}]`) {
		t.Fatalf("final stage must restore the tenant: %s", got)
	}
}

func TestMatchWithTextStaysFirst(t *testing.T) {
	r := New(Config{})
	res, err := rewriteCmd(t, r, bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{
		bson.M{"$match": bson.M{"$text": bson.M{"$search": "x"}}}, bson.M{"$limit": 5},
	}}, {Key: "$db", Value: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := res.Body.Lookup("pipeline").Array().Values()
	if len(p) != 2 { // wrapped, not prepended
		t.Fatalf("expected 2 stages, got %d", len(p))
	}
}

func TestDropBecomesDelete(t *testing.T) {
	r := New(Config{})
	res, err := rewriteCmd(t, r, bson.D{{Key: "drop", Value: "c"}, {Key: "$db", Value: "app"}})
	if err != nil {
		t.Fatal(err)
	}
	if CommandName(res.Body) != "delete" || res.Post == nil {
		t.Fatalf("drop not converted: %s", json(res.Body))
	}
	out := res.Post(mk(t, bson.M{"n": 3, "ok": 1}))
	if ns, _ := out.Lookup("ns").StringValueOK(); ns != "app.c" {
		t.Fatalf("unexpected drop reply %s", json(out))
	}
}

func BenchmarkRewriteFind(b *testing.B) {
	r := New(Config{})
	ten, _ := NewTenant("string", "T1")
	cmd := mk(b, bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"a": 1, "b": bson.M{"$in": bson.A{1, 2, 3}}}}, {Key: "$db", Value: "app"}})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := r.Rewrite(ten, "app", cmd, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRewriteInsert1000(b *testing.B) {
	r := New(Config{})
	ten, _ := NewTenant("string", "T1")
	docs := make([]bsoncore.Document, 1000)
	for i := range docs {
		docs[i] = mk(b, bson.M{"i": i, "name": "some document", "tags": bson.A{"a", "b"}})
	}
	cmd := mk(b, bson.D{{Key: "insert", Value: "c"}, {Key: "$db", Value: "app"}})
	seqs := []wire.Seq{{ID: "documents", Docs: docs}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := r.Rewrite(ten, "app", cmd, seqs); err != nil {
			b.Fatal(err)
		}
	}
}
