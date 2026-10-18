package test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustFail(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s to be rejected", what)
	}
}

func count(t *testing.T, c *mongo.Collection, filter any) int64 {
	t.Helper()
	n, err := c.CountDocuments(ctx(t), filter)
	must(t, err)
	return n
}

func TestTenantIsolation(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	ca, cb := a.Database("app").Collection("items"), b.Database("app").Collection("items")
	raw := e.direct.Database("app").Collection("items")

	// Seed: 3 docs for A, 2 for B, through the proxy, with no tenant field.
	_, err := ca.InsertMany(ctx(t), []any{bson.M{"n": 1}, bson.M{"n": 2}, bson.M{"n": 3, "tag": "x"}})
	must(t, err)
	_, err = cb.InsertMany(ctx(t), []any{bson.M{"n": 1}, bson.M{"n": 2, "tag": "x"}})
	must(t, err)

	t.Run("insert stamps tenant", func(t *testing.T) {
		if got := count(t, raw, bson.M{"tenantId": "tenant-a"}); got != 3 {
			t.Fatalf("upstream has %d docs for A, want 3", got)
		}
		if got := count(t, raw, bson.M{"tenantId": "tenant-b"}); got != 2 {
			t.Fatalf("upstream has %d docs for B, want 2", got)
		}
	})

	t.Run("reads are scoped", func(t *testing.T) {
		if n := count(t, ca, bson.M{}); n != 3 {
			t.Fatalf("A sees %d, want 3", n)
		}
		if n := count(t, cb, bson.M{}); n != 2 {
			t.Fatalf("B sees %d, want 2", n)
		}
		if n := count(t, ca, bson.M{"tag": "x"}); n != 1 {
			t.Fatalf("A tag filter = %d, want 1", n)
		}
		// Trying to widen the filter must not escape the scope.
		for _, f := range []bson.M{
			{"$or": bson.A{bson.M{"tenantId": "tenant-b"}, bson.M{"n": 1}}},
			{"tenantId": "tenant-b"},
			{"tenantId": bson.M{"$ne": "tenant-a"}},
			{"$nor": bson.A{bson.M{"tenantId": "tenant-a"}}},
		} {
			cur, err := ca.Find(ctx(t), f)
			must(t, err)
			var docs []bson.M
			must(t, cur.All(ctx(t), &docs))
			for _, d := range docs {
				if d["tenantId"] != "tenant-a" {
					t.Fatalf("filter %v leaked %v", f, d)
				}
			}
		}
		vals, err := ca.Distinct(ctx(t), "tenantId", bson.M{}).Raw()
		must(t, err)
		if s := vals.String(); !strings.Contains(s, "tenant-a") || strings.Contains(s, "tenant-b") {
			t.Fatalf("distinct leaked: %s", s)
		}
	})

	t.Run("cursors paginate", func(t *testing.T) {
		docs := make([]any, 500)
		for i := range docs {
			docs[i] = bson.M{"page": i}
		}
		_, err := ca.InsertMany(ctx(t), docs)
		must(t, err)
		cur, err := ca.Find(ctx(t), bson.M{"page": bson.M{"$exists": true}}, options.Find().SetBatchSize(7).SetSort(bson.M{"page": 1}))
		must(t, err)
		var got []bson.M
		must(t, cur.All(ctx(t), &got))
		if len(got) != 500 {
			t.Fatalf("paged %d docs, want 500", len(got))
		}
		_, err = ca.DeleteMany(ctx(t), bson.M{"page": bson.M{"$exists": true}})
		must(t, err)
	})

	t.Run("cannot hijack another connection's cursor", func(t *testing.T) {
		_, err := ca.InsertMany(ctx(t), []any{bson.M{"hj": 1}, bson.M{"hj": 2}, bson.M{"hj": 3}})
		must(t, err)
		cur, err := ca.Find(ctx(t), bson.M{"hj": bson.M{"$exists": true}}, options.Find().SetBatchSize(1))
		must(t, err)
		id := cur.ID()
		if id == 0 {
			t.Fatal("expected an open cursor")
		}
		err = b.Database("app").RunCommand(ctx(t), bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: "items"}}).Err()
		mustFail(t, err, "getMore from another tenant")
		cur.Close(ctx(t))
		_, err = ca.DeleteMany(ctx(t), bson.M{"hj": bson.M{"$exists": true}})
		must(t, err)
	})

	t.Run("writes are scoped", func(t *testing.T) {
		res, err := cb.UpdateMany(ctx(t), bson.M{}, bson.M{"$set": bson.M{"touched": true}})
		must(t, err)
		if res.ModifiedCount != 2 {
			t.Fatalf("B modified %d, want 2", res.ModifiedCount)
		}
		if n := count(t, raw, bson.M{"tenantId": "tenant-a", "touched": true}); n != 0 {
			t.Fatalf("B's update touched %d of A's documents", n)
		}
		one := cb.FindOneAndUpdate(ctx(t), bson.M{"n": 1}, bson.M{"$set": bson.M{"fau": 1}})
		must(t, one.Err())
		if n := count(t, raw, bson.M{"tenantId": "tenant-a", "fau": 1}); n != 0 {
			t.Fatal("findAndModify crossed tenants")
		}
		// Deleting everything as B leaves A intact.
		_, err = cb.InsertOne(ctx(t), bson.M{"tmp": 1})
		must(t, err)
		dres, err := cb.DeleteMany(ctx(t), bson.M{"tmp": 1})
		must(t, err)
		if dres.DeletedCount != 1 {
			t.Fatalf("deleted %d, want 1", dres.DeletedCount)
		}
		if n := count(t, raw, bson.M{"tenantId": "tenant-a"}); n != 3 {
			t.Fatalf("A has %d docs after B's delete, want 3", n)
		}
	})

	t.Run("tenant field is immutable", func(t *testing.T) {
		_, err := ca.InsertOne(ctx(t), bson.M{"tenantId": "tenant-b", "evil": 1})
		mustFail(t, err, "insert for another tenant")
		_, err = ca.UpdateOne(ctx(t), bson.M{"n": 1}, bson.M{"$set": bson.M{"tenantId": "tenant-b"}})
		mustFail(t, err, "$set tenantId")
		_, err = ca.UpdateOne(ctx(t), bson.M{"n": 1}, bson.M{"$unset": bson.M{"tenantId": ""}})
		mustFail(t, err, "$unset tenantId")
		_, err = ca.UpdateOne(ctx(t), bson.M{"n": 1}, bson.M{"$rename": bson.M{"n": "tenantId"}})
		mustFail(t, err, "$rename onto tenantId")
		_, err = ca.ReplaceOne(ctx(t), bson.M{"n": 1}, bson.M{"n": 1, "tenantId": "tenant-b"})
		mustFail(t, err, "replace with foreign tenantId")
		// A pipeline update cannot move a document either.
		_, err = ca.UpdateOne(ctx(t), bson.M{"n": 1}, mongo.Pipeline{{{Key: "$set", Value: bson.M{"tenantId": "tenant-b"}}}})
		must(t, err)
		if n := count(t, raw, bson.M{"tenantId": "tenant-b", "n": 1, "tag": bson.M{"$exists": false}}); n != 1 {
			// B's own doc only; A's must remain A's
			t.Fatalf("unexpected docs for B: %d", n)
		}
		if n := count(t, ca, bson.M{"n": 1}); n != 1 {
			t.Fatal("pipeline update moved the document out of tenant A")
		}
	})

	t.Run("replace and upsert keep the tenant", func(t *testing.T) {
		_, err := ca.ReplaceOne(ctx(t), bson.M{"n": 2}, bson.M{"n": 2, "replaced": true})
		must(t, err)
		if n := count(t, raw, bson.M{"tenantId": "tenant-a", "replaced": true}); n != 1 {
			t.Fatalf("replacement lost its tenant (%d)", n)
		}
		_, err = ca.UpdateOne(ctx(t), bson.M{"key": "upserted"}, bson.M{"$set": bson.M{"v": 1}}, options.UpdateOne().SetUpsert(true))
		must(t, err)
		_, err = ca.ReplaceOne(ctx(t), bson.M{"key": "upserted2"}, bson.M{"key": "upserted2"}, options.Replace().SetUpsert(true))
		must(t, err)
		if n := count(t, raw, bson.M{"tenantId": "tenant-a", "key": bson.M{"$in": bson.A{"upserted", "upserted2"}}}); n != 2 {
			t.Fatalf("upserts did not carry the tenant (%d)", n)
		}
		// Same upsert key for B creates a separate document.
		_, err = cb.UpdateOne(ctx(t), bson.M{"key": "upserted"}, bson.M{"$set": bson.M{"v": 2}}, options.UpdateOne().SetUpsert(true))
		must(t, err)
		if n := count(t, raw, bson.M{"key": "upserted"}); n != 2 {
			t.Fatalf("expected one upsert per tenant, got %d", n)
		}
	})

	t.Run("disallowed operations", func(t *testing.T) {
		db := a.Database("app")
		for name, cmd := range map[string]bson.D{
			"dropDatabase":     {{Key: "dropDatabase", Value: 1}},
			"renameCollection": {{Key: "renameCollection", Value: "app.items"}, {Key: "to", Value: "app.x"}},
			"collStats":        {{Key: "collStats", Value: "items"}},
			"serverStatus":     {{Key: "serverStatus", Value: 1}},
			"currentOp":        {{Key: "currentOp", Value: 1}},
			"mapReduce":        {{Key: "mapReduce", Value: "items"}},
		} {
			mustFail(t, db.RunCommand(ctx(t), cmd).Err(), name)
		}
		mustFail(t, a.Database("admin").RunCommand(ctx(t), bson.D{{Key: "listCommands", Value: 1}}).Err(), "admin command")
		mustFail(t, a.Database("local").Collection("oplog.rs").FindOne(ctx(t), bson.M{}).Err(), "local db")
		mustFail(t, a.Database("app").Collection("system.users").FindOne(ctx(t), bson.M{}).Err(), "system collection")
		_, err := ca.Find(ctx(t), bson.M{"$where": "true"})
		if err == nil {
			cur, _ := ca.Find(ctx(t), bson.M{"$where": "true"})
			err = cur.Err()
			if err == nil {
				err = cur.All(ctx(t), &[]bson.M{})
			}
		}
		mustFail(t, err, "$where")
		_, err = ca.CountDocuments(ctx(t), bson.M{"$expr": bson.M{"$function": bson.M{"body": "function(){return true}", "args": bson.A{}, "lang": "js"}}})
		mustFail(t, err, "$function")
	})

	t.Run("drop only removes own documents", func(t *testing.T) {
		before := count(t, raw, bson.M{"tenantId": "tenant-b"})
		must(t, ca.Drop(ctx(t)))
		if n := count(t, ca, bson.M{}); n != 0 {
			t.Fatalf("A still sees %d docs after drop", n)
		}
		if n := count(t, raw, bson.M{"tenantId": "tenant-b"}); n != before || before == 0 {
			t.Fatalf("B lost documents on A's drop: %d -> %d", before, n)
		}
	})

	t.Run("listDatabases is filtered", func(t *testing.T) {
		names, err := a.ListDatabaseNames(ctx(t), bson.M{})
		must(t, err)
		for _, n := range names {
			if n == "admin" || n == "local" || n == "config" {
				t.Fatalf("saw internal database %q", n)
			}
		}
	})
}

func TestAggregationIsolation(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	db := "agg"
	for _, tc := range []struct {
		c      *mongo.Client
		prefix string
	}{{a, "a"}, {b, "b"}} {
		orders := tc.c.Database(db).Collection("orders")
		users := tc.c.Database(db).Collection("users")
		_, err := users.InsertMany(ctx(t), []any{
			bson.M{"uid": 1, "name": tc.prefix + "-alice", "parent": 2},
			bson.M{"uid": 2, "name": tc.prefix + "-bob"},
		})
		must(t, err)
		_, err = orders.InsertMany(ctx(t), []any{
			bson.M{"uid": 1, "amt": 10}, bson.M{"uid": 1, "amt": 5}, bson.M{"uid": 2, "amt": 7},
		})
		must(t, err)
	}
	orders := a.Database(db).Collection("orders")

	run := func(t *testing.T, p mongo.Pipeline) []bson.M {
		t.Helper()
		cur, err := orders.Aggregate(ctx(t), p)
		must(t, err)
		var out []bson.M
		must(t, cur.All(ctx(t), &out))
		return normAll(out)
	}

	t.Run("group sees only own", func(t *testing.T) {
		out := run(t, mongo.Pipeline{{{Key: "$group", Value: bson.M{"_id": nil, "total": bson.M{"$sum": "$amt"}}}}})
		if len(out) != 1 || out[0]["total"] != int32(22) {
			t.Fatalf("got %v, want total 22", out)
		}
	})

	t.Run("lookup is scoped", func(t *testing.T) {
		out := run(t, mongo.Pipeline{
			{{Key: "$lookup", Value: bson.M{"from": "users", "localField": "uid", "foreignField": "uid", "as": "u"}}},
		})
		if len(out) != 3 {
			t.Fatalf("got %d orders, want 3", len(out))
		}
		for _, o := range out {
			us := o["u"].(bson.A)
			if len(us) != 1 || !strings.HasPrefix(us[0].(bson.M)["name"].(string), "a-") {
				t.Fatalf("lookup leaked or missed: %v", o)
			}
		}
	})

	t.Run("lookup with pipeline is scoped", func(t *testing.T) {
		out := run(t, mongo.Pipeline{
			{{Key: "$lookup", Value: bson.M{"from": "users", "let": bson.M{"u": "$uid"},
				"pipeline": bson.A{bson.M{"$match": bson.M{"$expr": bson.M{"$eq": bson.A{"$uid", "$$u"}}}}}, "as": "u"}}},
		})
		for _, o := range out {
			us := o["u"].(bson.A)
			if len(us) != 1 || !strings.HasPrefix(us[0].(bson.M)["name"].(string), "a-") {
				t.Fatalf("lookup leaked: %v", o)
			}
		}
	})

	t.Run("unionWith is scoped", func(t *testing.T) {
		for _, uw := range []any{"users", bson.M{"coll": "users", "pipeline": bson.A{bson.M{"$match": bson.M{}}}}} {
			out := run(t, mongo.Pipeline{{{Key: "$unionWith", Value: uw}}})
			if len(out) != 5 {
				t.Fatalf("unionWith %v returned %d docs, want 5 (3 orders + 2 users)", uw, len(out))
			}
			for _, o := range out {
				if o["tenantId"] != "tenant-a" {
					t.Fatalf("unionWith leaked %v", o)
				}
			}
		}
	})

	t.Run("graphLookup is scoped", func(t *testing.T) {
		users := a.Database(db).Collection("users")
		cur, err := users.Aggregate(ctx(t), mongo.Pipeline{
			{{Key: "$match", Value: bson.M{"uid": 1}}},
			{{Key: "$graphLookup", Value: bson.M{"from": "users", "startWith": "$parent", "connectFromField": "parent", "connectToField": "uid", "as": "chain"}}},
		})
		must(t, err)
		var out []bson.M
		must(t, cur.All(ctx(t), &out))
		out = normAll(out)
		if len(out) != 1 {
			t.Fatalf("got %d", len(out))
		}
		for _, c := range out[0]["chain"].(bson.A) {
			if c.(bson.M)["tenantId"] != "tenant-a" {
				t.Fatalf("graphLookup leaked %v", c)
			}
		}
	})

	t.Run("facet branches are rewritten", func(t *testing.T) {
		out := run(t, mongo.Pipeline{{{Key: "$facet", Value: bson.M{
			"n":  bson.A{bson.M{"$count": "c"}},
			"lk": bson.A{bson.M{"$lookup": bson.M{"from": "users", "localField": "uid", "foreignField": "uid", "as": "u"}}},
		}}}})
		n := out[0]["n"].(bson.A)[0].(bson.M)["c"]
		if n != int32(3) {
			t.Fatalf("facet count = %v", n)
		}
		for _, d := range out[0]["lk"].(bson.A) {
			for _, u := range d.(bson.M)["u"].(bson.A) {
				if u.(bson.M)["tenantId"] != "tenant-a" {
					t.Fatalf("facet lookup leaked %v", u)
				}
			}
		}
	})

	t.Run("dangerous stages are refused", func(t *testing.T) {
		for _, st := range []bson.D{
			{{Key: "$out", Value: "stolen"}},
			{{Key: "$merge", Value: bson.M{"into": "stolen"}}},
			{{Key: "$currentOp", Value: bson.M{}}},
			{{Key: "$collStats", Value: bson.M{"count": bson.M{}}}},
			{{Key: "$indexStats", Value: bson.M{}}},
			{{Key: "$listSessions", Value: bson.M{}}},
		} {
			cur, err := orders.Aggregate(ctx(t), mongo.Pipeline{st})
			if err == nil {
				err = cur.All(ctx(t), &[]bson.M{})
			}
			mustFail(t, err, st[0].Key)
		}
	})

	t.Run("text search stays first stage", func(t *testing.T) {
		notes := a.Database(db).Collection("notes")
		_, err := notes.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "body", Value: "text"}}})
		must(t, err)
		_, err = notes.InsertOne(ctx(t), bson.M{"body": "hello tenant world"})
		must(t, err)
		_, err = b.Database(db).Collection("notes").InsertOne(ctx(t), bson.M{"body": "hello other tenant"})
		must(t, err)
		cur, err := notes.Find(ctx(t), bson.M{"$text": bson.M{"$search": "hello"}})
		must(t, err)
		var out []bson.M
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 || out[0]["tenantId"] != "tenant-a" {
			t.Fatalf("text search returned %v", out)
		}
		cur, err = notes.Aggregate(ctx(t), mongo.Pipeline{{{Key: "$match", Value: bson.M{"$text": bson.M{"$search": "hello"}}}}})
		must(t, err)
		out = nil
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 {
			t.Fatalf("aggregate $text returned %d", len(out))
		}
	})

	t.Run("geoNear is scoped", func(t *testing.T) {
		pl := a.Database(db).Collection("places")
		_, err := pl.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "loc", Value: "2dsphere"}}})
		must(t, err)
		pt := bson.M{"type": "Point", "coordinates": bson.A{1.0, 1.0}}
		_, err = pl.InsertOne(ctx(t), bson.M{"loc": pt})
		must(t, err)
		_, err = b.Database(db).Collection("places").InsertOne(ctx(t), bson.M{"loc": pt})
		must(t, err)
		cur, err := pl.Aggregate(ctx(t), mongo.Pipeline{{{Key: "$geoNear", Value: bson.M{"near": pt, "distanceField": "d", "spherical": true}}}})
		must(t, err)
		var out []bson.M
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 {
			t.Fatalf("geoNear returned %d, want 1", len(out))
		}
		cur, err = pl.Find(ctx(t), bson.M{"loc": bson.M{"$near": bson.M{"$geometry": pt}}})
		must(t, err)
		out = nil
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 {
			t.Fatalf("$near returned %d, want 1", len(out))
		}
	})
}

func TestIndexesAndBulk(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	ca, cb := a.Database("idx").Collection("people"), b.Database("idx").Collection("people")

	t.Run("unique indexes are per tenant", func(t *testing.T) {
		_, err := ca.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)})
		must(t, err)
		_, err = cb.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)})
		must(t, err)
		_, err = ca.InsertOne(ctx(t), bson.M{"email": "x@example.com"})
		must(t, err)
		_, err = cb.InsertOne(ctx(t), bson.M{"email": "x@example.com"})
		must(t, err) // same value, different tenant: allowed
		_, err = ca.InsertOne(ctx(t), bson.M{"email": "x@example.com"})
		mustFail(t, err, "duplicate within a tenant")
	})

	t.Run("listIndexes hides the prefix", func(t *testing.T) {
		cur, err := ca.Indexes().List(ctx(t))
		must(t, err)
		var specs []bson.M
		must(t, cur.All(ctx(t), &specs))
		specs = normAll(specs)
		found := false
		for _, s := range specs {
			if s["name"] == "email_1" {
				found = true
				if k := s["key"].(bson.M); len(k) != 1 {
					t.Fatalf("key = %v, want only email", k)
				}
			}
		}
		if !found {
			t.Fatal("email_1 not listed")
		}
	})

	t.Run("dropIndexes", func(t *testing.T) {
		mustFail(t, ca.Indexes().DropAll(ctx(t)), "drop all indexes")
		must(t, ca.Indexes().DropOne(ctx(t), "email_1"))
	})

	t.Run("large ordered and unordered bulk writes", func(t *testing.T) {
		docs := make([]any, 5000)
		for i := range docs {
			docs[i] = bson.M{"i": i, "pad": strings.Repeat("x", 100)}
		}
		_, err := ca.InsertMany(ctx(t), docs)
		must(t, err)
		if n := count(t, ca, bson.M{"i": bson.M{"$exists": true}}); n != 5000 {
			t.Fatalf("inserted %d, want 5000", n)
		}
		models := []mongo.WriteModel{
			mongo.NewInsertOneModel().SetDocument(bson.M{"bulk": 1}),
			mongo.NewUpdateManyModel().SetFilter(bson.M{"i": bson.M{"$lt": 10}}).SetUpdate(bson.M{"$set": bson.M{"small": true}}),
			mongo.NewReplaceOneModel().SetFilter(bson.M{"bulk": 1}).SetReplacement(bson.M{"bulk": 2}),
			mongo.NewDeleteManyModel().SetFilter(bson.M{"i": bson.M{"$gte": 4990}}),
		}
		res, err := ca.BulkWrite(ctx(t), models)
		must(t, err)
		if res.InsertedCount != 1 || res.ModifiedCount != 11 || res.DeletedCount != 10 {
			t.Fatalf("bulk result %+v", res)
		}
		if n := count(t, cb, bson.M{"small": true}); n != 0 {
			t.Fatal("bulk update leaked to B")
		}
		if n := count(t, e.direct.Database("idx").Collection("people"), bson.M{"bulk": 2, "tenantId": "tenant-a"}); n != 1 {
			t.Fatal("bulk replace lost tenant")
		}
	})

	t.Run("unacknowledged writes", func(t *testing.T) {
		wc := ca.Clone(options.Collection().SetWriteConcern(mongoW0()))
		_, err := wc.InsertOne(ctx(t), bson.M{"unack": 1})
		must(t, err)
		deadline := time.Now().Add(5 * time.Second)
		for count(t, e.direct.Database("idx").Collection("people"), bson.M{"unack": 1, "tenantId": "tenant-a"}) != 1 {
			if time.Now().After(deadline) {
				t.Fatal("w:0 insert never arrived with tenant")
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	t.Run("explain is scoped", func(t *testing.T) {
		var out bson.M
		err := ca.Database().RunCommand(ctx(t), bson.D{
			{Key: "explain", Value: bson.D{{Key: "find", Value: "people"}, {Key: "filter", Value: bson.M{"i": 1}}}},
			{Key: "verbosity", Value: "queryPlanner"},
		}).Decode(&out)
		must(t, err)
		if !strings.Contains(fmt.Sprint(out), "tenant-a") {
			t.Fatalf("explain plan does not mention the tenant filter: %v", out)
		}
	})
}

func mongoW0() *writeConcernT { return writeConcernW0() }

func TestTransactions(t *testing.T) {
	e := setup(t, nil)
	a := e.tenant(t, "tenant-a")
	c := a.Database("tx").Collection("t")
	_, err := c.InsertOne(ctx(t), bson.M{"seed": 1}) // create collection outside txn
	must(t, err)
	sess, err := a.StartSession()
	must(t, err)
	defer sess.EndSession(ctx(t))
	_, err = sess.WithTransaction(ctx(t), func(sc context.Context) (any, error) {
		if _, err := c.InsertOne(sc, bson.M{"in": "txn"}); err != nil {
			return nil, err
		}
		return nil, nil
	})
	must(t, err)
	if n := count(t, e.direct.Database("tx").Collection("t"), bson.M{"in": "txn", "tenantId": "tenant-a"}); n != 1 {
		t.Fatalf("transaction write missing tenant (%d)", n)
	}
	// An aborted transaction leaves nothing behind.
	must(t, sess.StartTransaction())
	_, err = c.InsertOne(mongo.NewSessionContext(ctx(t), sess), bson.M{"in": "aborted"})
	must(t, err)
	must(t, sess.AbortTransaction(ctx(t)))
	if n := count(t, c, bson.M{"in": "aborted"}); n != 0 {
		t.Fatal("aborted transaction persisted")
	}
}

func TestAppNameAuth(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Auth.AppNameSecret = "s3cret" })
	good := connect(t, fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, signed("s3cret", "tenant-a")))
	defer good.Disconnect(context.Background())
	_, err := good.Database("auth").Collection("c").InsertOne(ctx(t), bson.M{"ok": 1})
	must(t, err)
	if n := count(t, e.direct.Database("auth").Collection("c"), bson.M{"tenantId": "tenant-a"}); n != 1 {
		t.Fatal("signed appName not honoured")
	}
	for _, name := range []string{"tenant-a", "tenant-a.00000000000000000000000000000000", "tenant-b." + strings.Repeat("a", 32)} {
		bad := connectTimeout(t, fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, name), 3*time.Second)
		_, err := bad.Database("auth").Collection("c").InsertOne(ctx(t), bson.M{"forged": 1})
		bad.Disconnect(context.Background())
		mustFail(t, err, "forged appName "+name)
	}
	// No appName at all: no tenant, no data access.
	anon := connectTimeout(t, fmt.Sprintf("mongodb://%s/", e.proxyAddr), 5*time.Second)
	defer anon.Disconnect(context.Background())
	_, err = anon.Database("auth").Collection("c").InsertOne(ctx(t), bson.M{"anon": 1})
	mustFail(t, err, "anonymous insert")
}

func TestStaticMode(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		c.Auth = config.Auth{Mode: "static", StaticTenant: "only-tenant"}
	})
	c := connect(t, fmt.Sprintf("mongodb://%s/", e.proxyAddr))
	defer c.Disconnect(context.Background())
	_, err := c.Database("st").Collection("c").InsertOne(ctx(t), bson.M{"x": 1})
	must(t, err)
	if n := count(t, e.direct.Database("st").Collection("c"), bson.M{"tenantId": "only-tenant"}); n != 1 {
		t.Fatal("static tenant not applied")
	}
}

func norm(v any) any {
	switch x := v.(type) {
	case bson.D:
		m := bson.M{}
		for _, e := range x {
			m[e.Key] = norm(e.Value)
		}
		return m
	case bson.M:
		for k, vv := range x {
			x[k] = norm(vv)
		}
		return x
	case bson.A:
		for i := range x {
			x[i] = norm(x[i])
		}
		return x
	}
	return v
}

func normAll(docs []bson.M) []bson.M {
	for i := range docs {
		docs[i] = norm(docs[i]).(bson.M)
	}
	return docs
}
