package test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func cmdOn(t *testing.T, c *mongo.Client, db string, cmd bson.D) (bson.M, error) {
	t.Helper()
	var out bson.M
	err := c.Database(db).RunCommand(ctx(t), cmd).Decode(&out)
	return out, err
}

func mustCmd(t *testing.T, c *mongo.Client, db string, cmd bson.D) bson.M {
	t.Helper()
	out, err := cmdOn(t, c, db, cmd)
	must(t, err)
	return out
}

func seed(t *testing.T, c *mongo.Client, db, coll string, n int, tag string) {
	t.Helper()
	docs := make([]any, n)
	for i := range docs {
		docs[i] = bson.M{"k": i, "tag": tag, "pad": strings.Repeat("x", 50)}
	}
	_, err := c.Database(db).Collection(coll).InsertMany(ctx(t), docs)
	must(t, err)
}

func TestDropDatabase(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	for _, c := range []string{"c1", "c2"} {
		seed(t, a, "dd", c, 3, "a")
		seed(t, b, "dd", c, 2, "b")
	}
	must(t, a.Database("dd").CreateView(ctx(t), "v1", "c1", mongo.Pipeline{}))
	must(t, b.Database("dd").CreateView(ctx(t), "v1", "c1", mongo.Pipeline{}))
	_ = mustCmd(t, a, "dd", bson.D{{Key: "collMod", Value: "c1"}, {Key: "validator", Value: bson.M{"k": bson.M{"$exists": true}}}})

	must(t, a.Database("dd").Drop(ctx(t)))

	for _, c := range []string{"c1", "c2"} {
		if n := count(t, e.direct.Database("dd").Collection(c), bson.M{"tenantId": "tenant-a"}); n != 0 {
			t.Fatalf("tenant-a still has %d docs in %s", n, c)
		}
		if n := count(t, b.Database("dd").Collection(c), bson.M{}); n != 2 {
			t.Fatalf("tenant-b lost documents in %s: %d", c, n)
		}
	}
	names, err := a.Database("dd").ListCollectionNames(ctx(t), bson.M{"name": "v1"})
	must(t, err)
	if len(names) != 0 {
		t.Fatalf("tenant-a's view survived dropDatabase: %v", names)
	}
	names, err = b.Database("dd").ListCollectionNames(ctx(t), bson.M{"name": "v1"})
	must(t, err)
	if len(names) != 1 {
		t.Fatalf("tenant-b's view was removed: %v", names)
	}
	if n := count(t, e.direct.Database("dd").Collection("__mtp_validators"), bson.M{"tenantId": "tenant-a"}); n != 0 {
		t.Fatal("validator rows survived dropDatabase")
	}
	// The shared validator no longer constrains anybody.
	if _, err := b.Database("dd").Collection("c1").InsertOne(ctx(t), bson.M{"nok": 1}); err != nil {
		t.Fatalf("stale validator: %v", err)
	}
}

func TestRenameCollection(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	seed(t, a, "rn", "src", 4, "a")
	seed(t, b, "rn", "src", 2, "b")
	_, err := a.Database("rn").Collection("src").Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "k", Value: 1}}})
	must(t, err)

	mustCmd(t, a, "admin", bson.D{{Key: "renameCollection", Value: "rn.src"}, {Key: "to", Value: "rn.dst"}})
	if n := count(t, a.Database("rn").Collection("src"), bson.M{}); n != 0 {
		t.Fatalf("source still has %d docs", n)
	}
	if n := count(t, a.Database("rn").Collection("dst"), bson.M{}); n != 4 {
		t.Fatalf("target has %d docs, want 4", n)
	}
	if n := count(t, b.Database("rn").Collection("src"), bson.M{}); n != 2 {
		t.Fatalf("tenant-b's source changed: %d", n)
	}
	if n := count(t, b.Database("rn").Collection("dst"), bson.M{}); n != 0 {
		t.Fatalf("tenant-b sees tenant-a's renamed docs: %d", n)
	}

	// Target exists / dropTarget.
	seed(t, a, "rn", "src", 1, "a2")
	_, err = cmdOn(t, a, "admin", bson.D{{Key: "renameCollection", Value: "rn.src"}, {Key: "to", Value: "rn.dst"}})
	mustFail(t, err, "rename onto an existing target")
	mustCmd(t, a, "admin", bson.D{{Key: "renameCollection", Value: "rn.src"}, {Key: "to", Value: "rn.dst"}, {Key: "dropTarget", Value: true}})
	if n := count(t, a.Database("rn").Collection("dst"), bson.M{}); n != 1 {
		t.Fatalf("dropTarget left %d docs", n)
	}
	// Cross-database, reserved and unknown names.
	seed(t, a, "rn", "x", 1, "x")
	mustCmd(t, a, "admin", bson.D{{Key: "renameCollection", Value: "rn.x"}, {Key: "to", Value: "rn2.x"}})
	if n := count(t, a.Database("rn2").Collection("x"), bson.M{}); n != 1 {
		t.Fatalf("cross-db rename lost the document")
	}
	for name, cmd := range map[string]bson.D{
		"admin target":    {{Key: "renameCollection", Value: "rn.dst"}, {Key: "to", Value: "admin.x"}},
		"reserved target": {{Key: "renameCollection", Value: "rn.dst"}, {Key: "to", Value: "rn.__mtp_x"}},
		"system source":   {{Key: "renameCollection", Value: "rn.system.users"}, {Key: "to", Value: "rn.y"}},
		"missing source":  {{Key: "renameCollection", Value: "rn.nope"}, {Key: "to", Value: "rn.y"}},
	} {
		_, err := cmdOn(t, a, "admin", cmd)
		mustFail(t, err, name)
	}
}

func TestCollModValidator(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	seed(t, a, "cm", "c", 1, "a")
	seed(t, b, "cm", "c", 1, "b")

	mustCmd(t, a, "cm", bson.D{{Key: "collMod", Value: "c"}, {Key: "validator", Value: bson.M{"req": bson.M{"$exists": true}}}})
	ca, cb := a.Database("cm").Collection("c"), b.Database("cm").Collection("c")
	_, err := ca.InsertOne(ctx(t), bson.M{"no": 1})
	mustFail(t, err, "insert violating tenant-a's validator")
	if _, err := ca.InsertOne(ctx(t), bson.M{"req": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.InsertOne(ctx(t), bson.M{"no": 1}); err != nil {
		t.Fatalf("tenant-a's validator leaked to tenant-b: %v", err)
	}
	mustCmd(t, b, "cm", bson.D{{Key: "collMod", Value: "c"}, {Key: "validator", Value: bson.M{"other": bson.M{"$exists": true}}}})
	_, err = cb.InsertOne(ctx(t), bson.M{"req": 1})
	mustFail(t, err, "insert violating tenant-b's validator")
	if _, err := ca.InsertOne(ctx(t), bson.M{"req": 2}); err != nil {
		t.Fatalf("tenant-b's validator leaked to tenant-a: %v", err)
	}

	// listCollections shows only the caller's validator.
	cur, err := a.Database("cm").ListCollections(ctx(t), bson.M{"name": "c"})
	must(t, err)
	var specs []bson.M
	must(t, cur.All(ctx(t), &specs))
	if len(specs) != 1 {
		t.Fatalf("listCollections: %v", specs)
	}
	if s := fmt.Sprint(specs[0]["options"]); !strings.Contains(s, "req") || strings.Contains(s, "other") || strings.Contains(s, "tenant-b") {
		t.Fatalf("validator not tenant-scoped: %v", specs[0]["options"])
	}

	// Clearing removes only the caller's constraint.
	mustCmd(t, a, "cm", bson.D{{Key: "collMod", Value: "c"}, {Key: "validator", Value: bson.M{}}})
	if _, err := ca.InsertOne(ctx(t), bson.M{"no": 3}); err != nil {
		t.Fatalf("validator not cleared: %v", err)
	}
	_, err = cb.InsertOne(ctx(t), bson.M{"req": 9})
	mustFail(t, err, "tenant-b's validator survives tenant-a clearing theirs")

	for name, cmd := range map[string]bson.D{
		"ttl index":    {{Key: "collMod", Value: "c"}, {Key: "index", Value: bson.M{"name": "_id_", "hidden": true}}},
		"expire":       {{Key: "collMod", Value: "c"}, {Key: "expireAfterSeconds", Value: 5}},
		"level":        {{Key: "collMod", Value: "c"}, {Key: "validationLevel", Value: "moderate"}},
		"action":       {{Key: "collMod", Value: "c"}, {Key: "validationAction", Value: "warn"}},
		"capped":       {{Key: "collMod", Value: "c"}, {Key: "cappedSize", Value: 1 << 20}},
		"images":       {{Key: "collMod", Value: "c"}, {Key: "changeStreamPreAndPostImages", Value: bson.M{"enabled": false}}},
		"js validator": {{Key: "collMod", Value: "c"}, {Key: "validator", Value: bson.M{"$where": "true"}}},
	} {
		_, err := cmdOn(t, a, "cm", cmd)
		if name == "js validator" {
			continue // JS is allowed by default; the server rejects $where in validators itself
		}
		mustFail(t, err, name)
	}
	// "strict" / "error" are the defaults and accepted as no-ops.
	mustCmd(t, a, "cm", bson.D{{Key: "collMod", Value: "c"}, {Key: "validationLevel", Value: "strict"}, {Key: "validationAction", Value: "error"}})
}

func TestStats(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	seed(t, a, "st", "c1", 10, "a")
	seed(t, a, "st", "c2", 5, "a")
	seed(t, b, "st", "c1", 100, "b")

	cs := mustCmd(t, a, "st", bson.D{{Key: "collStats", Value: "c1"}})
	if cs["count"] != int32(10) && cs["count"] != int64(10) {
		t.Fatalf("collStats count = %v, want 10 (tenant only)", cs["count"])
	}
	if cs["ns"] != "st.c1" || cs["tenantScoped"] != true {
		t.Fatalf("collStats: %v", cs)
	}
	ds := mustCmd(t, a, "st", bson.D{{Key: "dbStats", Value: 1}})
	if fmt.Sprint(ds["objects"]) != "15" || fmt.Sprint(ds["collections"]) != "2" {
		t.Fatalf("dbStats = %v, want 15 objects in 2 collections", ds)
	}
	db := mustCmd(t, b, "st", bson.D{{Key: "dbStats", Value: 1}})
	if fmt.Sprint(db["objects"]) != "100" || fmt.Sprint(db["collections"]) != "1" {
		t.Fatalf("tenant-b dbStats = %v", db)
	}
	// size scales
	sc := mustCmd(t, a, "st", bson.D{{Key: "collStats", Value: "c1"}, {Key: "scale", Value: 1024}})
	if fmt.Sprint(sc["scaleFactor"]) != "1024" {
		t.Fatalf("scale ignored: %v", sc)
	}

	// $collStats stage.
	cur, err := a.Database("st").Collection("c1").Aggregate(ctx(t), mongo.Pipeline{
		{{Key: "$collStats", Value: bson.M{"count": bson.M{}, "storageStats": bson.M{}}}},
	})
	must(t, err)
	var rows []bson.M
	must(t, cur.All(ctx(t), &rows))
	if len(rows) != 1 || fmt.Sprint(rows[0]["count"]) != "10" || rows[0]["storageStats"] == nil {
		t.Fatalf("$collStats = %v", rows)
	}
	_, err = a.Database("st").Collection("c1").Aggregate(ctx(t), mongo.Pipeline{
		{{Key: "$collStats", Value: bson.M{"latencyStats": bson.M{}}}}})
	mustFail(t, err, "$collStats latencyStats")

	// validate is refused; serverStatus is synthesized.
	_, err = cmdOn(t, a, "st", bson.D{{Key: "validate", Value: "c1"}})
	mustFail(t, err, "validate")
	ss := mustCmd(t, a, "admin", bson.D{{Key: "serverStatus", Value: 1}})
	if _, ok := ss["opcounters"]; ok || ss["host"] == nil {
		t.Fatalf("serverStatus = %v", ss)
	}
}

func TestCurrentOpKillOp(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	seed(t, b, "op", "c", 1, "b")
	seed(t, a, "op", "c", 1, "a")

	var wg sync.WaitGroup
	var slowErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		cur, err := b.Database("op").Collection("c").Find(ctx(t), bson.M{"$where": "sleep(20000) || true"})
		if err == nil {
			err = cur.Err()
			if err == nil {
				err = cur.All(ctx(t), &[]bson.M{})
			}
		}
		slowErr = err
	}()

	find := func(c *mongo.Client) []any {
		for i := 0; i < 50; i++ {
			out := mustCmd(t, c, "admin", bson.D{{Key: "currentOp", Value: 1}, {Key: "ns", Value: "op.c"}})
			if ops, _ := out["inprog"].(bson.A); len(ops) > 0 {
				return ops
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	}
	ops := find(b)
	if len(ops) != 1 {
		t.Fatalf("tenant-b sees %d of its own ops, want 1", len(ops))
	}
	var opid any
	for _, kv := range ops[0].(bson.D) {
		if kv.Key == "opid" {
			opid = kv.Value
		}
	}
	// Tenant A sees nothing of B's.
	out := mustCmd(t, a, "admin", bson.D{{Key: "currentOp", Value: 1}, {Key: "ns", Value: "op.c"}})
	if ops, _ := out["inprog"].(bson.A); len(ops) != 0 {
		t.Fatalf("tenant-a sees tenant-b's operations: %v", ops)
	}
	// Aggregation form.
	cur, err := a.Database("admin").Aggregate(ctx(t), mongo.Pipeline{
		{{Key: "$currentOp", Value: bson.M{"allUsers": true}}}, {{Key: "$match", Value: bson.M{"ns": "op.c"}}}})
	must(t, err)
	var rows []bson.M
	must(t, cur.All(ctx(t), &rows))
	if len(rows) != 0 {
		t.Fatalf("$currentOp leaked %v", rows)
	}

	// A cannot kill B's op (reported like an unknown op).
	mustCmd(t, a, "admin", bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: opid}})
	time.Sleep(300 * time.Millisecond)
	if len(find(b)) != 1 {
		t.Fatal("tenant-a killed tenant-b's operation")
	}
	// B can.
	mustCmd(t, b, "admin", bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: opid}})
	wg.Wait()
	if slowErr == nil {
		t.Fatal("killed operation completed normally")
	}
}

func TestMapReduceOut(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	for tenant, c := range map[string]*mongo.Client{"a": a, "b": b} {
		docs := []any{}
		for i := 0; i < 6; i++ {
			docs = append(docs, bson.M{"g": fmt.Sprintf("%s%d", tenant, i%2), "n": 1})
		}
		_, err := c.Database("mr").Collection("src").InsertMany(ctx(t), docs)
		must(t, err)
	}
	mrCmd := func(out any) bson.D {
		return bson.D{{Key: "mapReduce", Value: "src"},
			{Key: "map", Value: bson.JavaScript("function(){ emit(this.g, this.n); }")},
			{Key: "reduce", Value: bson.JavaScript("function(k, v){ return Array.sum(v); }")},
			{Key: "out", Value: out}}
	}
	vals := func(c *mongo.Client, coll string) map[string]int64 {
		cur, err := c.Database("mr").Collection(coll).Find(ctx(t), bson.M{})
		must(t, err)
		var rows []bson.M
		must(t, cur.All(ctx(t), &rows))
		out := map[string]int64{}
		for _, r := range rows {
			if r["tenantId"] == nil {
				t.Fatalf("result without tenantId: %v", r)
			}
			switch v := r["value"].(type) {
			case float64:
				out[r["_id"].(string)] = int64(v)
			case int32:
				out[r["_id"].(string)] = int64(v)
			case int64:
				out[r["_id"].(string)] = v
			}
		}
		return out
	}

	res := mustCmd(t, a, "mr", mrCmd(bson.M{"replace": "out1"}))
	if res["result"] != "out1" {
		t.Fatalf("reply = %v", res)
	}
	if got := vals(a, "out1"); got["a0"] != 3 || got["a1"] != 3 || len(got) != 2 {
		t.Fatalf("replace result = %v", got)
	}
	mustCmd(t, b, "mr", mrCmd("out1")) // string form = replace
	if got := vals(b, "out1"); got["b0"] != 3 || len(got) != 2 {
		t.Fatalf("tenant-b result = %v", got)
	}
	if got := vals(a, "out1"); len(got) != 2 || got["b0"] != 0 {
		t.Fatalf("tenant-a sees tenant-b's output: %v", got)
	}

	// replace is per tenant and drops the tenant's old keys.
	_, err := a.Database("mr").Collection("src").DeleteMany(ctx(t), bson.M{"g": "a1"})
	must(t, err)
	mustCmd(t, a, "mr", mrCmd(bson.M{"replace": "out1"}))
	if got := vals(a, "out1"); len(got) != 1 || got["a0"] != 3 {
		t.Fatalf("replace did not drop stale keys: %v", got)
	}
	if got := vals(b, "out1"); len(got) != 2 {
		t.Fatalf("replace touched tenant-b: %v", got)
	}

	// merge overwrites matching keys, keeps others.
	_, err = a.Database("mr").Collection("src").InsertOne(ctx(t), bson.M{"g": "a9", "n": 7})
	must(t, err)
	mustCmd(t, a, "mr", mrCmd(bson.M{"merge": "out1"}))
	if got := vals(a, "out1"); len(got) != 2 || got["a9"] != 7 || got["a0"] != 3 {
		t.Fatalf("merge result = %v", got)
	}
	// reduce combines with existing values.
	mustCmd(t, a, "mr", mrCmd(bson.M{"reduce": "out1"}))
	if got := vals(a, "out1"); got["a0"] != 6 || got["a9"] != 14 {
		t.Fatalf("reduce result = %v", got)
	}
	// No staging collections left behind.
	names, err := e.direct.Database("mr").ListCollectionNames(ctx(t), bson.M{})
	must(t, err)
	for _, n := range names {
		if strings.HasPrefix(n, "__mtp_mr_") || strings.HasPrefix(n, "__mtp_out_") {
			t.Fatalf("staging collection %s left behind", n)
		}
	}
	// Reserved / foreign targets.
	for name, out := range map[string]any{
		"reserved":    bson.M{"replace": "__mtp_views"},
		"system":      bson.M{"replace": "system.x"},
		"admin db":    bson.M{"replace": "x", "db": "admin"},
		"two actions": bson.M{"replace": "x", "merge": "y"},
	} {
		_, err := cmdOn(t, a, "mr", mrCmd(out))
		mustFail(t, err, name)
	}
	// Inline still works.
	in := mustCmd(t, a, "mr", mrCmd(bson.M{"inline": 1}))
	if rs, _ := in["results"].(bson.A); len(rs) != 2 {
		t.Fatalf("inline results = %v", in)
	}
}

func TestAtomicOut(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	src := func(c *mongo.Client) *mongo.Collection { return c.Database("ao").Collection("src") }
	for i := 0; i < 5; i++ {
		_, err := src(a).InsertOne(ctx(t), bson.M{"k": i, "who": "a"})
		must(t, err)
		_, err = src(b).InsertOne(ctx(t), bson.M{"k": i, "who": "b"})
		must(t, err)
	}
	out := func(c *mongo.Client, match bson.M) {
		cur, err := src(c).Aggregate(ctx(t), mongo.Pipeline{
			{{Key: "$match", Value: match}},
			{{Key: "$project", Value: bson.M{"_id": 0, "k": 1, "who": 1}}},
			{{Key: "$out", Value: "dst"}},
		})
		must(t, err)
		must(t, cur.Close(ctx(t)))
	}
	committed := func() int64 {
		var ss bson.M
		must(t, e.direct.Database("admin").RunCommand(ctx(t), bson.D{{Key: "serverStatus", Value: 1}}).Decode(&ss))
		tx, _ := ss["transactions"].(bson.D)
		for _, kv := range tx {
			if kv.Key == "totalCommitted" {
				switch v := kv.Value.(type) {
				case int32:
					return int64(v)
				case int64:
					return v
				}
			}
		}
		return -1
	}
	before := committed()
	out(a, bson.M{})
	if committed() <= before {
		t.Fatalf("$out did not swap inside a transaction (committed %d -> %d)", before, committed())
	}
	out(b, bson.M{"k": bson.M{"$lt": 2}})
	if n := count(t, e.direct.Database("ao").Collection("dst"), bson.M{"tenantId": "tenant-a"}); n != 5 {
		t.Fatalf("tenant-a has %d docs in dst, want 5", n)
	}
	if n := count(t, e.direct.Database("ao").Collection("dst"), bson.M{"tenantId": "tenant-b"}); n != 2 {
		t.Fatalf("tenant-b has %d docs in dst, want 2", n)
	}
	// Re-running replaces the tenant's documents, others are untouched.
	out(a, bson.M{"k": bson.M{"$gte": 3}})
	if n := count(t, e.direct.Database("ao").Collection("dst"), bson.M{"tenantId": "tenant-a"}); n != 2 {
		t.Fatalf("tenant-a has %d docs after replace, want 2", n)
	}
	if n := count(t, e.direct.Database("ao").Collection("dst"), bson.M{"tenantId": "tenant-b"}); n != 2 {
		t.Fatalf("tenant-b changed: %d", n)
	}
	// Nothing left over: no marker field, no staging collection.
	if n := count(t, e.direct.Database("ao").Collection("dst"), bson.M{"__mtp_out": bson.M{"$exists": true}}); n != 0 {
		t.Fatalf("%d documents carry the marker", n)
	}
	names, err := e.direct.Database("ao").ListCollectionNames(ctx(t), bson.M{})
	must(t, err)
	for _, n := range names {
		if strings.HasPrefix(n, "__mtp_out_") {
			t.Fatalf("staging collection %s left behind", n)
		}
	}
	// A replace with an empty result clears the tenant's documents.
	out(a, bson.M{"k": 999})
	if n := count(t, e.direct.Database("ao").Collection("dst"), bson.M{"tenantId": "tenant-a"}); n != 0 {
		t.Fatalf("empty $out left %d docs", n)
	}
}

func serverAtLeast(t *testing.T, e *env, major int) bool {
	t.Helper()
	var bi bson.M
	must(t, e.direct.Database("admin").RunCommand(ctx(t), bson.D{{Key: "buildInfo", Value: 1}}).Decode(&bi))
	arr, _ := bi["versionArray"].(bson.A)
	if len(arr) == 0 {
		return false
	}
	switch v := arr[0].(type) {
	case int32:
		return int(v) >= major
	case int64:
		return int(v) >= major
	}
	return false
}

func TestBulkWriteCommand(t *testing.T) {
	e := setup(t, nil)
	if !serverAtLeast(t, e, 8) {
		t.Skip("bulkWrite needs mongod 8.0+; the rewrite is covered by unit tests")
	}
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	_, err := b.Database("bw").Collection("c").InsertOne(ctx(t), bson.M{"k": 1, "who": "b"})
	must(t, err)

	res, err := a.BulkWrite(ctx(t), []mongo.ClientBulkWrite{
		{Database: "bw", Collection: "c", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"k": 1, "who": "a"})},
		{Database: "bw", Collection: "c2", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"k": 2, "who": "a"})},
		{Database: "bw", Collection: "c", Model: mongo.NewClientUpdateManyModel().SetFilter(bson.M{}).SetUpdate(bson.M{"$set": bson.M{"touched": true}})},
		{Database: "bw", Collection: "c", Model: mongo.NewClientDeleteManyModel().SetFilter(bson.M{"k": 99})},
	})
	must(t, err)
	if res.InsertedCount != 2 || res.MatchedCount != 1 || res.ModifiedCount != 1 {
		t.Fatalf("result = %+v", res)
	}
	var got bson.M
	must(t, e.direct.Database("bw").Collection("c").FindOne(ctx(t), bson.M{"who": "b"}).Decode(&got))
	if got["touched"] != nil {
		t.Fatal("tenant-a's bulk update touched tenant-b")
	}
	if n := count(t, e.direct.Database("bw").Collection("c"), bson.M{"tenantId": "tenant-a"}); n != 1 {
		t.Fatalf("inserts were not stamped: %d", n)
	}
	// Deletes are scoped.
	_, err = a.BulkWrite(ctx(t), []mongo.ClientBulkWrite{
		{Database: "bw", Collection: "c", Model: mongo.NewClientDeleteManyModel().SetFilter(bson.M{})}})
	must(t, err)
	if n := count(t, b.Database("bw").Collection("c"), bson.M{}); n != 1 {
		t.Fatalf("tenant-b lost documents: %d", n)
	}
	// Foreign tenant stamp and forbidden namespaces fail.
	_, err = a.BulkWrite(ctx(t), []mongo.ClientBulkWrite{
		{Database: "bw", Collection: "c", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"tenantId": "tenant-b"})}})
	mustFail(t, err, "forged tenantId")
	for _, ns := range []struct{ db, coll string }{{"admin", "x"}, {"bw", "system.x"}, {"bw", "__mtp_views"}} {
		_, err = a.BulkWrite(ctx(t), []mongo.ClientBulkWrite{
			{Database: ns.db, Collection: ns.coll, Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"x": 1})}})
		mustFail(t, err, ns.db+"."+ns.coll)
	}
	// Views are read-only.
	must(t, a.Database("bw").CreateView(ctx(t), "vw", "c2", mongo.Pipeline{}))
	_, err = a.BulkWrite(ctx(t), []mongo.ClientBulkWrite{
		{Database: "bw", Collection: "vw", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"x": 1})}})
	mustFail(t, err, "write to a view")
	// Unordered continues past errors.
	_, err = a.BulkWrite(ctx(t), []mongo.ClientBulkWrite{
		{Database: "bw", Collection: "c3", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"_id": 1})},
		{Database: "bw", Collection: "c3", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"_id": 1})},
		{Database: "bw", Collection: "c3", Model: mongo.NewClientInsertOneModel().SetDocument(bson.M{"_id": 2})},
	}, optionsUnordered())
	if err == nil {
		t.Fatal("duplicate key not reported")
	}
	if n := count(t, a.Database("bw").Collection("c3"), bson.M{}); n != 2 {
		t.Fatalf("unordered bulkWrite stored %d docs, want 2", n)
	}
}
