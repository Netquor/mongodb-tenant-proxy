package test

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func docsOf(t *testing.T, c *mongo.Collection, filter any) []bson.M {
	t.Helper()
	cur, err := c.Find(ctx(t), filter)
	must(t, err)
	var out []bson.M
	must(t, cur.All(ctx(t), &out))
	return normAll(out)
}

func TestMergeAndOut(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	sa, sb := a.Database("o").Collection("src"), b.Database("o").Collection("src")
	_, err := sa.InsertMany(ctx(t), []any{bson.M{"k": 1, "v": "a1"}, bson.M{"k": 2, "v": "a2"}})
	must(t, err)
	_, err = sb.InsertMany(ctx(t), []any{bson.M{"k": 1, "v": "b1"}, bson.M{"k": 3, "v": "b3"}})
	must(t, err)

	merge := func(c *mongo.Client, on any) {
		cur, err := c.Database("o").Collection("src").Aggregate(ctx(t), mongo.Pipeline{
			{{Key: "$project", Value: bson.M{"_id": 0}}},
			{{Key: "$merge", Value: bson.M{"into": "merged", "on": on, "whenMatched": "replace", "whenNotMatched": "insert"}}},
		})
		must(t, err)
		must(t, cur.Close(ctx(t)))
	}

	t.Run("merge stays inside the tenant", func(t *testing.T) {
		merge(a, "k")
		merge(b, "k") // same k values for both tenants must not collide
		for tenant, want := range map[string]int64{"tenant-a": 2, "tenant-b": 2} {
			if n := count(t, e.direct.Database("o").Collection("merged"), bson.M{"tenantId": tenant}); n != want {
				t.Fatalf("%s has %d merged docs, want %d", tenant, n, want)
			}
		}
		// Re-running updates in place instead of duplicating.
		_, err := sa.UpdateOne(ctx(t), bson.M{"k": 1}, bson.M{"$set": bson.M{"v": "a1-new"}})
		must(t, err)
		merge(a, "k")
		docs := docsOf(t, a.Database("o").Collection("merged"), bson.M{"k": 1})
		if len(docs) != 1 || docs[0]["v"] != "a1-new" {
			t.Fatalf("merge did not update in place: %v", docs)
		}
		if bd := docsOf(t, b.Database("o").Collection("merged"), bson.M{"k": 1}); len(bd) != 1 || bd[0]["v"] != "b1" {
			t.Fatalf("A's merge touched B's data: %v", bd)
		}
	})

	t.Run("merge cannot target other tenants via on or stamping", func(t *testing.T) {
		cur, err := sa.Aggregate(ctx(t), mongo.Pipeline{
			{{Key: "$set", Value: bson.M{"tenantId": "tenant-b"}}},
			{{Key: "$project", Value: bson.M{"_id": 0}}},
			{{Key: "$merge", Value: bson.M{"into": "merged2", "on": bson.A{"tenantId", "k"}}}},
		})
		must(t, err)
		must(t, cur.Close(ctx(t)))
		if n := count(t, e.direct.Database("o").Collection("merged2"), bson.M{"tenantId": "tenant-b"}); n != 0 {
			t.Fatalf("pipeline forged tenant-b documents (%d)", n)
		}
		for name, p := range map[string]mongo.Pipeline{
			"merge not last":  {{{Key: "$merge", Value: "x"}}, {{Key: "$limit", Value: 1}}},
			"merge in lookup": {{{Key: "$lookup", Value: bson.M{"from": "src", "as": "x", "pipeline": bson.A{bson.M{"$merge": "x"}}}}}},
			"system target":   {{{Key: "$merge", Value: "system.users"}}},
			"other db target": {{{Key: "$merge", Value: bson.M{"into": bson.M{"db": "admin", "coll": "x"}}}}},
			"reserved target": {{{Key: "$merge", Value: "__mtp_views"}}},
		} {
			cur, err := sa.Aggregate(ctx(t), p)
			if err == nil {
				err = cur.All(ctx(t), &[]bson.M{})
			}
			mustFail(t, err, name)
		}
	})

	t.Run("out replaces only the tenant's documents", func(t *testing.T) {
		out := func(c *mongo.Client) {
			cur, err := c.Database("o").Collection("src").Aggregate(ctx(t), mongo.Pipeline{{{Key: "$out", Value: "outc"}}})
			must(t, err)
			must(t, cur.Close(ctx(t)))
		}
		out(a)
		out(b)
		oa, ob := a.Database("o").Collection("outc"), b.Database("o").Collection("outc")
		if count(t, oa, bson.M{}) != 2 || count(t, ob, bson.M{}) != 2 {
			t.Fatal("initial $out wrong")
		}
		// A deletes a source row and re-runs $out: its stale output goes, B's stays.
		_, err := sa.DeleteOne(ctx(t), bson.M{"k": 2})
		must(t, err)
		out(a)
		if n := count(t, oa, bson.M{}); n != 1 {
			t.Fatalf("A has %d docs after re-run, want 1 (stale removed)", n)
		}
		if n := count(t, ob, bson.M{}); n != 2 {
			t.Fatalf("B lost documents to A's $out: %d", n)
		}
		if n := count(t, e.direct.Database("o").Collection("outc"), bson.M{"__mtp_out": bson.M{"$exists": true}}); n != 0 {
			t.Fatalf("%d documents still carry the internal $out marker", n)
		}
	})
}

func TestJavaScriptAndMapReduce(t *testing.T) {
	e := setup(t, nil) // JavaScript is allowed by default
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	ca, cb := a.Database("js").Collection("c"), b.Database("js").Collection("c")
	_, err := ca.InsertMany(ctx(t), []any{bson.M{"cat": "x", "n": 1}, bson.M{"cat": "x", "n": 2}, bson.M{"cat": "y", "n": 5}})
	must(t, err)
	_, err = cb.InsertMany(ctx(t), []any{bson.M{"cat": "x", "n": 100}})
	must(t, err)

	t.Run("$where is scoped", func(t *testing.T) {
		for _, d := range docsOf(t, ca, bson.M{"$where": "this.n >= 1"}) {
			if d["tenantId"] != "tenant-a" {
				t.Fatalf("$where leaked %v", d)
			}
		}
		if n := len(docsOf(t, ca, bson.M{"$where": "this.n >= 1"})); n != 3 {
			t.Fatalf("$where matched %d, want 3", n)
		}
		// JavaScript cannot reach other collections or documents.
		cur, err := ca.Find(ctx(t), bson.M{"$where": "db.getSiblingDB('js').c.count() > 0"})
		if err == nil {
			err = cur.All(ctx(t), &[]bson.M{})
		}
		mustFail(t, err, "$where reaching db")
	})

	t.Run("mapReduce inline is scoped", func(t *testing.T) {
		var res struct {
			Results []struct {
				ID    string  `bson:"_id"`
				Value float64 `bson:"value"`
			} `bson:"results"`
		}
		err := a.Database("js").RunCommand(ctx(t), bson.D{
			{Key: "mapReduce", Value: "c"},
			{Key: "map", Value: bson.JavaScript("function(){ emit(this.cat, this.n); }")},
			{Key: "reduce", Value: bson.JavaScript("function(k, v){ return Array.sum(v); }")},
			{Key: "out", Value: bson.D{{Key: "inline", Value: 1}}},
		}).Decode(&res)
		must(t, err)
		sums := map[string]float64{}
		for _, r := range res.Results {
			sums[r.ID] = r.Value
		}
		if sums["x"] != 3 || sums["y"] != 5 {
			t.Fatalf("mapReduce sums = %v (B's 100 must not be included)", sums)
		}
		err = a.Database("js").RunCommand(ctx(t), bson.D{
			{Key: "mapReduce", Value: "c"},
			{Key: "map", Value: bson.JavaScript("function(){ emit(1,1); }")},
			{Key: "reduce", Value: bson.JavaScript("function(k,v){ return 1; }")},
			{Key: "out", Value: "somewhere"},
		}).Err()
		must(t, err) // collection output is supported (see TestMapReduceOut)
		mustFail(t, a.Database("js").RunCommand(ctx(t), bson.D{
			{Key: "mapReduce", Value: "c"},
			{Key: "map", Value: bson.JavaScript("function(){ emit(1,1); }")},
			{Key: "reduce", Value: bson.JavaScript("function(k,v){ return 1; }")},
			{Key: "out", Value: bson.M{"replace": "system.profile"}},
		}).Err(), "mapReduce to a system collection")
	})
}

func TestViews(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	da, db := a.Database("v"), b.Database("v")
	ia, ib := da.Collection("items"), db.Collection("items")
	var docsA, docsB []any
	for i := 1; i <= 30; i++ {
		docsA = append(docsA, bson.M{"n": i, "cat": []string{"x", "y"}[i%2]})
	}
	for i := 1; i <= 5; i++ {
		docsB = append(docsB, bson.M{"n": i * 100, "cat": "x"})
	}
	_, err := ia.InsertMany(ctx(t), docsA)
	must(t, err)
	_, err = ib.InsertMany(ctx(t), docsB)
	must(t, err)

	// Same view name, different definitions per tenant.
	must(t, da.CreateView(ctx(t), "big", "items", mongo.Pipeline{{{Key: "$match", Value: bson.M{"n": bson.M{"$gt": 20}}}}}))
	must(t, db.CreateView(ctx(t), "big", "items", mongo.Pipeline{{{Key: "$match", Value: bson.M{"n": bson.M{"$gt": 300}}}}}))
	// A view that aggregates across documents must not mix tenants.
	must(t, da.CreateView(ctx(t), "totals", "items", mongo.Pipeline{
		{{Key: "$group", Value: bson.M{"_id": "$cat", "sum": bson.M{"$sum": "$n"}}}},
	}))
	must(t, db.CreateView(ctx(t), "totals", "items", mongo.Pipeline{
		{{Key: "$group", Value: bson.M{"_id": "$cat", "sum": bson.M{"$sum": "$n"}}}},
	}))

	t.Run("reads", func(t *testing.T) {
		if n := count(t, da.Collection("big"), bson.M{}); n != 10 {
			t.Fatalf("A's big = %d, want 10", n)
		}
		if n := count(t, db.Collection("big"), bson.M{}); n != 2 {
			t.Fatalf("B's big = %d, want 2", n)
		}
		sums := map[string]int32{}
		for _, d := range docsOf(t, da.Collection("totals"), bson.M{}) {
			sums[d["_id"].(string)] = d["sum"].(int32)
		}
		if sums["x"]+sums["y"] != 465 || len(sums) != 2 {
			t.Fatalf("A's totals = %v (30*31/2 = 465, no B data)", sums)
		}
		bs := docsOf(t, db.Collection("totals"), bson.M{})
		if len(bs) != 1 || bs[0]["sum"] != int32(1500) {
			t.Fatalf("B's totals = %v", bs)
		}
	})

	t.Run("filters, pipelines and cursors on views", func(t *testing.T) {
		v := da.Collection("big")
		if n := count(t, v, bson.M{"cat": "x"}); n != 5 {
			t.Fatalf("filtered count = %d", n)
		}
		cur, err := v.Find(ctx(t), bson.M{}, options.Find().SetBatchSize(3).SetSort(bson.M{"n": 1}))
		must(t, err)
		var all []bson.M
		must(t, cur.All(ctx(t), &all))
		if len(all) != 10 || all[0]["n"] != int32(21) {
			t.Fatalf("paged view read: %d docs, first %v", len(all), all[0])
		}
		agg, err := v.Aggregate(ctx(t), mongo.Pipeline{{{Key: "$group", Value: bson.M{"_id": nil, "m": bson.M{"$max": "$n"}}}}})
		must(t, err)
		var res []bson.M
		must(t, agg.All(ctx(t), &res))
		if res[0]["m"] != int32(30) {
			t.Fatalf("aggregate on view: %v", res)
		}
	})

	t.Run("view on a view", func(t *testing.T) {
		must(t, da.CreateView(ctx(t), "bigger", "big", mongo.Pipeline{{{Key: "$match", Value: bson.M{"n": bson.M{"$gt": 28}}}}}))
		if n := count(t, da.Collection("bigger"), bson.M{}); n != 2 {
			t.Fatalf("bigger = %d, want 2", n)
		}
	})

	t.Run("listCollections", func(t *testing.T) {
		names, err := da.ListCollectionNames(ctx(t), bson.M{})
		must(t, err)
		seen := map[string]bool{}
		for _, n := range names {
			if strings.HasPrefix(n, "__mtp_") {
				t.Fatalf("internal collection %q leaked", n)
			}
			seen[n] = true
		}
		if !seen["big"] || !seen["totals"] || !seen["items"] {
			t.Fatalf("A sees %v", names)
		}
		specs, err := da.ListCollectionSpecifications(ctx(t), bson.M{"name": "big"})
		must(t, err)
		if len(specs) != 1 || specs[0].Type != "view" {
			t.Fatalf("view spec: %+v", specs)
		}
		bnames, _ := db.ListCollectionNames(ctx(t), bson.M{})
		for _, n := range bnames {
			if n == "bigger" {
				t.Fatal("B sees A's view")
			}
		}
	})

	t.Run("views are read-only and names are unique", func(t *testing.T) {
		_, err := da.Collection("big").InsertOne(ctx(t), bson.M{"n": 99})
		mustFail(t, err, "insert into a view")
		_, err = da.Collection("big").DeleteMany(ctx(t), bson.M{})
		mustFail(t, err, "delete from a view")
		mustFail(t, da.CreateCollection(ctx(t), "big"), "collection named like a view")
		mustFail(t, da.CreateView(ctx(t), "big", "items", mongo.Pipeline{}), "duplicate view")
		mustFail(t, da.CreateView(ctx(t), "items", "items", mongo.Pipeline{}), "view named like existing data")
		mustFail(t, da.CreateView(ctx(t), "evil", "items", mongo.Pipeline{{{Key: "$out", Value: "x"}}}), "view with $out")
		mustFail(t, da.CreateView(ctx(t), "__mtp_x", "items", mongo.Pipeline{}), "reserved view name")
		mustFail(t, da.Collection("__mtp_views").FindOne(ctx(t), bson.M{}).Err(), "reading the registry")
	})

	t.Run("collMod and drop", func(t *testing.T) {
		must(t, da.RunCommand(ctx(t), bson.D{{Key: "collMod", Value: "big"}, {Key: "viewOn", Value: "items"},
			{Key: "pipeline", Value: bson.A{bson.M{"$match": bson.M{"n": bson.M{"$gt": 25}}}}}}).Err())
		if n := count(t, da.Collection("big"), bson.M{}); n != 5 {
			t.Fatalf("after collMod big = %d, want 5", n)
		}
		must(t, da.Collection("totals").Drop(ctx(t)))
		names, _ := da.ListCollectionNames(ctx(t), bson.M{})
		for _, n := range names {
			if n == "totals" {
				t.Fatal("dropped view still listed")
			}
		}
		if n := count(t, db.Collection("totals"), bson.M{}); n != 1 {
			t.Fatalf("B's view was affected by A's drop (%d)", n)
		}
		mustFail(t, da.RunCommand(ctx(t), bson.D{{Key: "collMod", Value: "items"}, {Key: "expireAfterSeconds", Value: 1}}).Err(), "collMod on a collection")
	})
}
