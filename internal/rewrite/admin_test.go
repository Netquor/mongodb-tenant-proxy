package rewrite

import (
	"fmt"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

func seqOfT(t testing.TB, id string, docs ...any) wire.Seq {
	s := wire.Seq{ID: id}
	for _, d := range docs {
		s.Docs = append(s.Docs, mk(t, d))
	}
	return s
}

func mustRewrite(t *testing.T, r *Rewriter, cmd bson.D, seqs ...wire.Seq) *Result {
	t.Helper()
	res, err := rewriteCmd(t, r, cmd, seqs...)
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	return res
}

func mustDeny(t *testing.T, r *Rewriter, name string, cmd bson.D, seqs ...wire.Seq) error {
	t.Helper()
	_, err := rewriteCmd(t, r, cmd, seqs...)
	if err == nil {
		t.Fatalf("%s: expected rejection", name)
	}
	return err
}

// ---- bulkWrite ----------------------------------------------------------------

func bulkCmd(extra ...bson.E) bson.D {
	return append(bson.D{{Key: "bulkWrite", Value: 1}, {Key: "ordered", Value: true}, {Key: "$db", Value: "admin"}}, extra...)
}

func TestBulkWriteSequences(t *testing.T) {
	r := New(Config{})
	res := mustRewrite(t, r, bulkCmd(),
		seqOfT(t, "ops",
			bson.D{{Key: "insert", Value: 0}, {Key: "document", Value: bson.M{"a": 1}}},
			bson.D{{Key: "update", Value: 1}, {Key: "filter", Value: bson.M{"a": 1}}, {Key: "updateMods", Value: bson.M{"$set": bson.M{"b": 2}}}, {Key: "multi", Value: true}},
			bson.D{{Key: "update", Value: 0}, {Key: "filter", Value: bson.M{}}, {Key: "updateMods", Value: bson.A{bson.M{"$set": bson.M{"c": 1}}}}},
			bson.D{{Key: "update", Value: 0}, {Key: "filter", Value: bson.M{"z": 1}}, {Key: "updateMods", Value: bson.M{"replaced": true}}, {Key: "upsert", Value: true}},
			bson.D{{Key: "delete", Value: 1}, {Key: "filter", Value: bson.M{"a": bson.M{"$gt": 1}}}, {Key: "multi", Value: true}}),
		seqOfT(t, "nsInfo", bson.M{"ns": "app.c1"}, bson.M{"ns": "other.c2"}))
	if CommandName(res.Body) != "bulkWrite" {
		t.Fatal("command name moved")
	}
	if len(res.Namespaces) != 2 || res.Namespaces[1] != "other.c2" {
		t.Fatalf("namespaces = %v", res.Namespaces)
	}
	var ops, ns []string
	for _, s := range res.Seqs {
		for _, d := range s.Docs {
			if s.ID == "ops" {
				ops = append(ops, json(d))
			} else {
				ns = append(ns, json(d))
			}
		}
	}
	if len(ops) != 5 || len(ns) != 2 {
		t.Fatalf("sequences lost: %d ops, %d ns", len(ops), len(ns))
	}
	if !has(ops[0], `"tenantId": "T1"`) {
		t.Fatalf("insert not stamped: %s", ops[0])
	}
	for _, i := range []int{1, 3, 4} {
		if !has(ops[i], `"$and"`) || !has(ops[i], `"tenantId": "T1"`) {
			t.Fatalf("op %d filter not scoped: %s", i, ops[i])
		}
	}
	if !has(ops[2], `"filter": {"tenantId": "T1"}`) || !has(ops[2], `"$set": {"tenantId": "T1"}`) {
		t.Fatalf("pipeline update does not re-assert the tenant: %s", ops[2])
	}
	if !has(ops[3], `"replaced": true`) || cnt(ops[3], `"tenantId": "T1"`) < 2 {
		t.Fatalf("replacement/upsert not stamped: %s", ops[3])
	}
}

func TestBulkWriteArrays(t *testing.T) {
	r := New(Config{})
	res := mustRewrite(t, r, bulkCmd(
		bson.E{Key: "ops", Value: bson.A{bson.D{{Key: "insert", Value: 0}, {Key: "document", Value: bson.M{"a": 1}}}, bson.D{{Key: "delete", Value: 0}, {Key: "filter", Value: bson.M{}}}}},
		bson.E{Key: "nsInfo", Value: bson.A{bson.M{"ns": "app.c"}}}))
	s := json(res.Body)
	if !has(s, `"tenantId": "T1"`) || cnt(s, "tenantId") < 2 {
		t.Fatalf("array form not rewritten: %s", s)
	}
	if len(res.Seqs) != 0 {
		t.Fatal("array form must not grow sequences")
	}
}

func TestBulkWriteRejections(t *testing.T) {
	r := New(Config{})
	ns := func(n string) wire.Seq { return seqOfT(t, "nsInfo", bson.M{"ns": n}) }
	ins := seqOfT(t, "ops", bson.D{{Key: "insert", Value: 0}, {Key: "document", Value: bson.M{"a": 1}}})
	for name, n := range map[string]string{
		"admin": "admin.x", "local": "local.x", "config": "config.x", "system": "app.system.users",
		"reserved": "app.__mtp_views", "no dot": "app", "dollar": "app.a$b", "empty coll": "app.",
	} {
		mustDeny(t, r, name, bulkCmd(), ins, ns(n))
	}
	rd := New(Config{Databases: []string{"only"}})
	mustDeny(t, rd, "db allow-list", bulkCmd(), ins, ns("app.c"))
	mustRewrite(t, rd, bulkCmd(), ins, ns("only.c"))

	good := ns("app.c")
	for name, op := range map[string]bson.D{
		"forged tenant":    {{Key: "insert", Value: 0}, {Key: "document", Value: bson.M{"tenantId": "T2"}}},
		"bad index":        {{Key: "insert", Value: 3}, {Key: "document", Value: bson.M{}}},
		"negative index":   {{Key: "insert", Value: -1}, {Key: "document", Value: bson.M{}}},
		"unknown op":       {{Key: "merge", Value: 0}, {Key: "document", Value: bson.M{}}},
		"unknown field":    {{Key: "insert", Value: 0}, {Key: "document", Value: bson.M{}}, {Key: "x", Value: 1}},
		"set tenant":       {{Key: "update", Value: 0}, {Key: "filter", Value: bson.M{}}, {Key: "updateMods", Value: bson.M{"$set": bson.M{"tenantId": "T2"}}}},
		"rename to tenant": {{Key: "update", Value: 0}, {Key: "filter", Value: bson.M{}}, {Key: "updateMods", Value: bson.M{"$rename": bson.M{"a": "tenantId"}}}},
		"bad stage":        {{Key: "update", Value: 0}, {Key: "filter", Value: bson.M{}}, {Key: "updateMods", Value: bson.A{bson.M{"$lookup": bson.M{"from": "x"}}}}},
		"js filter":        {{Key: "delete", Value: 0}, {Key: "filter", Value: bson.M{"$where": "1"}}},
	} {
		mustDeny(t, r, name, bulkCmd(), seqOfT(t, "ops", op), good)
	}
	mustDeny(t, r, "tenant in nsInfo extra", bulkCmd(), ins, seqOfT(t, "nsInfo", bson.M{"ns": "app.c", "x": 1}))
	mustDeny(t, r, "missing nsInfo", bulkCmd(), ins)
	mustDeny(t, r, "missing ops", bulkCmd(), good)
	mustDeny(t, r, "both forms", bulkCmd(bson.E{Key: "ops", Value: bson.A{}}), ins, good)
	mustDeny(t, r, "encryption", bulkCmd(bson.E{Key: "encryptionInformation", Value: bson.M{}}), ins, good)
	if d := New(Config{DenyCommands: []string{"bulkWrite"}}); true {
		mustDeny(t, d, "denyCommands", bulkCmd(), ins, good)
	}
}

// ---- Atlas Search ---------------------------------------------------------------

func aggregateOf(t *testing.T, pipeline ...bson.M) string {
	t.Helper()
	p := bson.A{}
	for _, s := range pipeline {
		p = append(p, s)
	}
	res := mustRewrite(t, New(Config{}), bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: p}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "app"}})
	return json(res.Body)
}

func TestSearchIsScoped(t *testing.T) {
	got := aggregateOf(t, bson.M{"$search": bson.D{{Key: "index", Value: "default"}, {Key: "text", Value: bson.M{"query": "x", "path": "title"}}, {Key: "highlight", Value: bson.M{"path": "title"}}}})
	for _, want := range []string{
		`"$search": {"index": "default", "compound": {"filter": [{"equals": {"path": "tenantId", "value": "T1"}}], "must": [{"text":`,
		`"highlight"`,
		`{"$match": {"tenantId": "T1"}}`,
	} {
		if !has(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	// $search must stay the first stage: no $match is prepended.
	if strings.Index(got, `"$search"`) > strings.Index(got, `"$match"`) {
		t.Fatalf("$search is not first: %s", got)
	}
}

func TestSearchCompoundIsWrapped(t *testing.T) {
	got := aggregateOf(t, bson.M{"$search": bson.M{"compound": bson.M{"should": bson.A{bson.M{"text": bson.M{"query": "a", "path": "p"}}}}}})
	// A client "should"/"mustNot" cannot widen the result: the whole compound sits under must.
	if !has(got, `"must": [{"compound": {"should"`) || !has(got, `"equals"`) {
		t.Fatalf("compound not nested under must: %s", got)
	}
}

func TestSearchMetaAndStoredSource(t *testing.T) {
	got := aggregateOf(t, bson.M{"$searchMeta": bson.M{"facet": bson.M{
		"operator": bson.M{"text": bson.M{"query": "x", "path": "t"}},
		"facets":   bson.M{"g": bson.M{"type": "string", "path": "genre"}}}}})
	if !has(got, `"equals"`) || !has(got, `"facets"`) || has(got, `{"$match"`) {
		t.Fatalf("$searchMeta facet: %s", got)
	}
	got = aggregateOf(t, bson.M{"$searchMeta": bson.M{"facet": bson.M{"facets": bson.M{}}}})
	if !has(got, `"operator": {"compound": {"filter"`) {
		t.Fatalf("facet without operator not scoped: %s", got)
	}
	got = aggregateOf(t, bson.M{"$search": bson.M{"text": bson.M{"query": "x", "path": "t"}, "returnStoredSource": true}})
	if has(got, `{"$match"`) {
		t.Fatalf("stored-source search must not be post-filtered on the (unstored) tenant field: %s", got)
	}
	got = aggregateOf(t, bson.M{"$search": bson.M{"knnBeta": bson.M{"vector": bson.A{1, 2}, "path": "v", "k": 3, "filter": bson.M{"text": bson.M{"query": "x", "path": "t"}}}}})
	if !has(got, `"knnBeta"`) || cnt(got, `"equals"`) != 1 || !has(got, `"filter": {"compound"`) {
		t.Fatalf("knnBeta filter: %s", got)
	}
}

func TestVectorSearchFilter(t *testing.T) {
	got := aggregateOf(t, bson.M{"$vectorSearch": bson.M{"index": "v", "path": "e", "queryVector": bson.A{1, 2}, "numCandidates": 10, "limit": 3}})
	if !has(got, `"filter": {"tenantId": {"$eq": "T1"}}`) {
		t.Fatalf("missing filter: %s", got)
	}
	got = aggregateOf(t, bson.M{"$vectorSearch": bson.M{"index": "v", "path": "e", "queryVector": bson.A{1}, "numCandidates": 10, "limit": 3,
		"filter": bson.M{"$or": bson.A{bson.M{"tenantId": "T2"}, bson.M{"x": 1}}}}})
	if !has(got, `"filter": {"$and": [{"tenantId": {"$eq": "T1"}}, {"$or"`) {
		t.Fatalf("client filter not ANDed: %s", got)
	}
}

func TestSearchRejections(t *testing.T) {
	r := New(Config{})
	pipe := func(stages ...bson.M) bson.D {
		p := bson.A{}
		for _, s := range stages {
			p = append(p, s)
		}
		return bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: p}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "app"}}
	}
	txt := bson.M{"text": bson.M{"query": "x", "path": "t"}}
	mustDeny(t, r, "not first", pipe(bson.M{"$match": bson.M{}}, bson.M{"$search": txt}))
	mustDeny(t, r, "in facet", pipe(bson.M{"$facet": bson.M{"f": bson.A{bson.M{"$search": txt}}}}))
	mustDeny(t, r, "no operator", pipe(bson.M{"$search": bson.M{"index": "x"}}))
	mustDeny(t, r, "two operators", pipe(bson.M{"$search": bson.M{"text": bson.M{}, "phrase": bson.M{}}}))
	mustDeny(t, r, "vector filter type", pipe(bson.M{"$vectorSearch": bson.M{"filter": 1}}))
	// Inside $lookup/$unionWith pipelines a search is the first stage of its own pipeline.
	got := aggregateOf(t, bson.M{"$lookup": bson.M{"from": "o", "as": "x", "pipeline": bson.A{bson.M{"$search": txt}}}})
	if cnt(got, `"equals"`) != 1 {
		t.Fatalf("$lookup search not scoped: %s", got)
	}
}

// ---- admin commands --------------------------------------------------------------

func TestCollModRules(t *testing.T) {
	r := New(Config{})
	base := func(extra ...bson.E) bson.D {
		return append(bson.D{{Key: "collMod", Value: "c"}, {Key: "$db", Value: "app"}}, extra...)
	}
	res := mustRewrite(t, r, base(bson.E{Key: "validator", Value: bson.M{"a": bson.M{"$exists": true}}}, bson.E{Key: "maxTimeMS", Value: 5}))
	if res.Run == nil {
		t.Fatal("collMod validator must be run by the proxy")
	}
	for name, e := range map[string]bson.E{
		"index":   {Key: "index", Value: bson.M{"name": "x", "expireAfterSeconds": 1}},
		"expire":  {Key: "expireAfterSeconds", Value: 1},
		"level":   {Key: "validationLevel", Value: "off"},
		"action":  {Key: "validationAction", Value: "warn"},
		"capped":  {Key: "cappedSize", Value: 1},
		"unknown": {Key: "whatever", Value: 1},
	} {
		err := mustDeny(t, r, name, base(e))
		if !has(err.Error(), e.Key) {
			t.Fatalf("%s: the denial should name the option: %v", name, err)
		}
	}
	mustRewrite(t, r, base(bson.E{Key: "validationLevel", Value: "strict"}))
	mustDeny(t, r, "in transaction", base(bson.E{Key: "txnNumber", Value: 1}, bson.E{Key: "validator", Value: bson.M{}}))
	mustDeny(t, r, "validate", bson.D{{Key: "validate", Value: "c"}, {Key: "$db", Value: "app"}})
}

func TestAdminCommandArguments(t *testing.T) {
	r := New(Config{})
	mustRewrite(t, r, bson.D{{Key: "dropDatabase", Value: 1}, {Key: "$db", Value: "app"}})
	mustDeny(t, r, "dropDatabase on admin", bson.D{{Key: "dropDatabase", Value: 1}, {Key: "$db", Value: "admin"}})
	mustRewrite(t, r, bson.D{{Key: "renameCollection", Value: "app.a"}, {Key: "to", Value: "app.b"}, {Key: "$db", Value: "admin"}})
	for name, c := range map[string]bson.D{
		"same":           {{Key: "renameCollection", Value: "app.a"}, {Key: "to", Value: "app.a"}},
		"no to":          {{Key: "renameCollection", Value: "app.a"}},
		"bad ns":         {{Key: "renameCollection", Value: "a"}, {Key: "to", Value: "app.b"}},
		"admin source":   {{Key: "renameCollection", Value: "admin.a"}, {Key: "to", Value: "app.b"}},
		"system target":  {{Key: "renameCollection", Value: "app.a"}, {Key: "to", Value: "app.system.x"}},
		"bad dropTarget": {{Key: "renameCollection", Value: "app.a"}, {Key: "to", Value: "app.b"}, {Key: "dropTarget", Value: "yes"}},
	} {
		mustDeny(t, r, name, append(c, bson.E{Key: "$db", Value: "admin"}))
	}
	mustRewrite(t, r, bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: 77}, {Key: "$db", Value: "admin"}})
	mustDeny(t, r, "killOp string", bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: "x"}, {Key: "$db", Value: "admin"}})
	mustRewrite(t, r, bson.D{{Key: "currentOp", Value: 1}, {Key: "active", Value: true}, {Key: "$db", Value: "admin"}})
	mustDeny(t, r, "currentOp js", bson.D{{Key: "currentOp", Value: 1}, {Key: "$where", Value: "1"}, {Key: "$db", Value: "admin"}})
	mustRewrite(t, r, bson.D{{Key: "aggregate", Value: 1}, {Key: "pipeline", Value: bson.A{bson.M{"$currentOp": bson.M{"allUsers": true}}}}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "admin"}})
	mustDeny(t, r, "non-currentOp admin aggregate", bson.D{{Key: "aggregate", Value: 1}, {Key: "pipeline", Value: bson.A{bson.M{"$listLocalSessions": bson.M{}}}}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "admin"}})
	mustDeny(t, r, "unknown $currentOp option", bson.D{{Key: "aggregate", Value: 1}, {Key: "pipeline", Value: bson.A{bson.M{"$currentOp": bson.M{"x": 1}}}}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "admin"}})
	mustDeny(t, r, "$collStats latency", bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$collStats": bson.M{"queryExecStats": bson.M{}}}}}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "app"}})
	mustDeny(t, r, "$indexStats", bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$indexStats": bson.M{}}}}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "app"}})
}

// ---- mapReduce -------------------------------------------------------------------

func TestMapReduceOutRewrite(t *testing.T) {
	r := New(Config{AllowJS: true})
	mr := func(out any) bson.D {
		return bson.D{{Key: "mapReduce", Value: "c"}, {Key: "map", Value: bson.JavaScript("function(){}")},
			{Key: "reduce", Value: bson.JavaScript("function(){}")}, {Key: "out", Value: out}, {Key: "$db", Value: "app"}}
	}
	if res := mustRewrite(t, r, mr(bson.M{"inline": 1})); res.Run != nil || !has(json(res.Body), `"tenantId": "T1"`) {
		t.Fatal("inline mapReduce must stay a scoped pass-through")
	}
	for _, out := range []any{"o", bson.M{"replace": "o"}, bson.M{"merge": "o", "nonAtomic": true}, bson.M{"reduce": "o", "db": "other"}} {
		if res := mustRewrite(t, r, mr(out)); res.Run == nil {
			t.Fatalf("out %v must be run by the proxy", out)
		}
	}
	for name, out := range map[string]any{
		"admin": bson.M{"replace": "o", "db": "admin"}, "system": "system.x", "reserved": bson.M{"merge": "__mtp_x"},
		"two modes": bson.M{"replace": "a", "merge": "b"}, "unknown": bson.M{"replace": "a", "bogus": 1}, "no mode": bson.M{"db": "x"},
		"int": 5,
	} {
		mustDeny(t, r, name, mr(out))
	}
	mustDeny(t, New(Config{}), "js disabled", mr("o"))
}

// ---- fake upstream: install / dropDatabase / killOp ----------------------------------

type call struct {
	db  string
	cmd bson.Raw
}

type fakeUp struct {
	calls   []call
	txn     bool
	failTxn bool
	reply   func(db string, cmd bson.Raw) bson.D
	clients []string
	views   []string
}

func (f *fakeUp) Run(db string, cmd bsoncore.Document) (bsoncore.Document, error) {
	f.calls = append(f.calls, call{db, bson.Raw(cmd)})
	name := CommandName(cmd)
	if f.failTxn && (name == "commitTransaction" || cmd.Lookup("startTransaction").Type != 0) {
		return mk2(bson.D{{Key: "ok", Value: 0}, {Key: "code", Value: 20}, {Key: "errmsg", Value: "no txn"}}), nil
	}
	if f.reply != nil {
		if d := f.reply(db, bson.Raw(cmd)); d != nil {
			return mk2(d), nil
		}
	}
	return mk2(bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}, {Key: "firstBatch", Value: bson.A{}}}}}), nil
}
func (f *fakeUp) Txn() bool                            { return f.txn }
func (f *fakeUp) TenantViews(string) ([]string, error) { return f.views, nil }
func (f *fakeUp) DropTenantViews(db string) error {
	f.calls = append(f.calls, call{db, mk2D(bson.D{{Key: "dropTenantViews", Value: 1}})})
	return nil
}
func (f *fakeUp) OwnClients() []string { return f.clients }

func mk2(d bson.D) bsoncore.Document { b, _ := bson.Marshal(d); return b }
func mk2D(d bson.D) bson.Raw         { b, _ := bson.Marshal(d); return b }

func (f *fakeUp) names() string {
	var out []string
	for _, c := range f.calls {
		n := CommandName(bsoncore.Document(c.cmd))
		if n == "aggregate" && has(c.cmd.String(), "$merge") {
			n = "aggregate($merge)"
		}
		out = append(out, n)
	}
	return strings.Join(out, ",")
}

func TestInstallFallsBackToMarker(t *testing.T) {
	r := New(Config{})
	ten, _ := NewTenant("string", "T1")
	for name, f := range map[string]*fakeUp{
		"no transactions":     {txn: false},
		"transaction refused": {txn: true, failTxn: true},
	} {
		if err := r.install(bound{f, ten}, "app", "stage", "app", "dst", modeReplace, ""); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := f.names()
		if !strings.HasSuffix(got, "aggregate($merge),delete,update") {
			t.Fatalf("%s: marker path not used: %s", name, got)
		}
		if !has(got, "createIndexes") {
			t.Fatalf("%s: unique index missing: %s", name, got)
		}
	}
	// Failing transaction is aborted before falling back.
	f := &fakeUp{txn: true, reply: func(db string, c bson.Raw) bson.D {
		if CommandName(bsoncore.Document(c)) == "insert" {
			return bson.D{{Key: "ok", Value: 1}, {Key: "writeErrors", Value: bson.A{bson.D{{Key: "code", Value: 112}, {Key: "errmsg", Value: "wc"}}}}}
		}
		if CommandName(bsoncore.Document(c)) == "find" {
			return bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)},
				{Key: "firstBatch", Value: bson.A{bson.D{{Key: "_id", Value: 1}}}}}}}
		}
		return nil
	}}
	if err := r.install(bound{f, ten}, "app", "stage", "app", "dst", modeReplace, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.names(); !has(got, "abortTransaction") || !strings.HasSuffix(got, "aggregate($merge),delete,update") {
		t.Fatalf("aborted-txn fallback: %s", got)
	}
}

func TestInstallTransactionShape(t *testing.T) {
	r := New(Config{})
	ten, _ := NewTenant("string", "T1")
	f := &fakeUp{txn: true, reply: func(db string, c bson.Raw) bson.D {
		if CommandName(bsoncore.Document(c)) == "find" {
			return bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)},
				{Key: "firstBatch", Value: bson.A{bson.D{{Key: "_id", Value: 1}}, bson.D{{Key: "_id", Value: 2}, {Key: "tenantId", Value: "T1"}}}}}}}
		}
		return nil
	}}
	if err := r.install(bound{f, ten}, "app", "stage", "app", "dst", modeReplace, ""); err != nil {
		t.Fatal(err)
	}
	if got := f.names(); !has(got, "delete,find,insert,commitTransaction") {
		t.Fatalf("transaction order: %s", got)
	}
	var del, ins, commit call
	for _, c := range f.calls {
		switch CommandName(bsoncore.Document(c.cmd)) {
		case "delete":
			del = c
		case "insert":
			ins = c
		case "commitTransaction":
			commit = c
		}
	}
	if del.cmd.Lookup("startTransaction").Boolean() != true || ins.cmd.Lookup("startTransaction").Type != 0 {
		t.Fatal("only the first command may start the transaction")
	}
	if commit.db != "admin" || commit.cmd.Lookup("autocommit").Boolean() {
		t.Fatalf("bad commit: %s", commit.cmd)
	}
	if s := ins.cmd.String(); cnt(s, `"tenantId": "T1"`) != 2 {
		t.Fatalf("staged documents must be stamped with the tenant: %s", s)
	}
	// A staged document carrying another tenant is refused and nothing is committed.
	bad := &fakeUp{txn: true, reply: func(db string, c bson.Raw) bson.D {
		if CommandName(bsoncore.Document(c)) == "find" {
			return bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)},
				{Key: "firstBatch", Value: bson.A{bson.D{{Key: "_id", Value: 1}, {Key: "tenantId", Value: "T2"}}}}}}}
		}
		return nil
	}}
	_ = r.install(bound{bad, ten}, "app", "stage", "app", "dst", modeReplace, "") // falls back, marker path re-stamps
	if has(bad.names(), "commitTransaction") {
		t.Fatalf("committed a transaction holding a foreign document: %s", bad.names())
	}
}

func TestDropDatabaseRun(t *testing.T) {
	r := New(Config{})
	ten, _ := NewTenant("string", "T1")
	f := &fakeUp{reply: func(db string, c bson.Raw) bson.D {
		if CommandName(bsoncore.Document(c)) == "listCollections" {
			return bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}, {Key: "firstBatch", Value: bson.A{
				bson.D{{Key: "name", Value: "a"}}, bson.D{{Key: "name", Value: "b"}}, bson.D{{Key: "name", Value: "__mtp_views"}}, bson.D{{Key: "name", Value: "system.x"}}}}}}}
		}
		return nil
	}}
	res := mustRewrite(t, r, bson.D{{Key: "dropDatabase", Value: 1}, {Key: "$db", Value: "app"}})
	resp, err := res.Run(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.names(); got != "listCollections,delete,delete,dropTenantViews,find" {
		t.Fatalf("dropDatabase steps: %s", got)
	}
	for _, c := range f.calls {
		if CommandName(bsoncore.Document(c.cmd)) == "delete" && !has(c.cmd.String(), `"q": {"tenantId": "T1"}`) {
			t.Fatalf("delete is not tenant-scoped: %s", c.cmd)
		}
	}
	if s := bson.Raw(resp).String(); !has(s, `"dropped": "app"`) {
		t.Fatalf("reply = %s", s)
	}
	_ = ten
}

func TestKillOpOnlyOwnOps(t *testing.T) {
	r := New(Config{})
	res := mustRewrite(t, r, bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: 55}, {Key: "$db", Value: "admin"}})
	// Foreign op: the $currentOp lookup is restricted to own connections and finds nothing.
	f := &fakeUp{clients: []string{"127.0.0.1:1111"}}
	resp, err := res.Run(f)
	if err != nil {
		t.Fatal(err)
	}
	if has(f.names(), "killOp") {
		t.Fatalf("killed an op that is not the tenant's: %s", f.names())
	}
	if !has(f.calls[0].cmd.String(), `"client": {"$in": ["127.0.0.1:1111"]}`) {
		t.Fatalf("lookup not restricted to own connections: %s", f.calls[0].cmd)
	}
	if !has(bson.Raw(resp).String(), `"ok": {"$numberInt":"1"}`) {
		t.Fatalf("killOp of unknown op must look like success: %s", bson.Raw(resp))
	}
	// Own op is killed.
	f = &fakeUp{clients: []string{"c"}, reply: func(db string, c bson.Raw) bson.D {
		if CommandName(bsoncore.Document(c)) == "aggregate" {
			return bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}, {Key: "firstBatch", Value: bson.A{bson.D{{Key: "opid", Value: 55}}}}}}}
		}
		return nil
	}}
	if _, err := res.Run(f); err != nil || !has(f.names(), "killOp") {
		t.Fatalf("own op not killed: %v %s", err, f.names())
	}
	// No connections => nothing to look up.
	f = &fakeUp{}
	if _, err := res.Run(f); err != nil || len(f.calls) != 0 {
		t.Fatalf("no clients: %v %d calls", err, len(f.calls))
	}
	_ = fmt.Sprint
}

func TestAtomicOutRewrite(t *testing.T) {
	ten, _ := NewTenant("string", "T1")
	cmd := bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$match": bson.M{}}, bson.M{"$out": "dst"}}}, {Key: "cursor", Value: bson.M{}}, {Key: "$db", Value: "app"}}
	// Without transactions: the in-pipeline marker approach.
	res, err := New(Config{}).Rewrite(ten, "app", mk(t, cmd), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := json(res.Body); !has(s, "$merge") || has(s, `"$out"`) {
		t.Fatalf("expected the marker approach: %s", s)
	}
	// With transactions: stage in a private collection, swap afterwards.
	res, err = New(Config{AtomicOut: func() bool { return true }}).Rewrite(ten, "app", mk(t, cmd), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := json(res.Body)
	if !has(s, `"$out": {"db": "app", "coll": "__mtp_out_`) || has(s, "$merge") || !has(s, `"$set": {"tenantId": "T1"}`) {
		t.Fatalf("expected a staged $out: %s", s)
	}
	if len(res.After) != 1 || res.After[0].Func == nil {
		t.Fatal("swap step missing")
	}
	f := &fakeUp{txn: true}
	if err := res.After[0].Func(f); err != nil {
		t.Fatal(err)
	}
	if got := f.names(); !strings.HasSuffix(got, "commitTransaction,drop") {
		t.Fatalf("swap/cleanup steps: %s", got)
	}
}

func squash(s string) string { return strings.NewReplacer(" ", "", "\n", "").Replace(s) }

func has(s, sub string) bool { return strings.Contains(squash(s), squash(sub)) }
func cnt(s, sub string) int  { return strings.Count(squash(s), squash(sub)) }
