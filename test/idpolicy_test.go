package test

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func idPolicy(p string) func(*config.Config) {
	return func(c *config.Config) {
		c.Tenant.IDPolicy = p
		c.Tenant.ExperimentalNamespace = p == "namespace"
		c.ChangeStreams.Disabled = true // keep these tests independent of replica-set change stream setup
	}
}

func isDup(err error) bool { return mongo.IsDuplicateKeyError(err) }

// Characterises the behaviour the policies exist to fix.
func TestIDPolicyNativeCollides(t *testing.T) {
	e := setup(t, idPolicy("native"))
	ca := e.tenant(t, "tenant-a").Database("app").Collection("items")
	cb := e.tenant(t, "tenant-b").Database("app").Collection("items")
	_, err := ca.InsertOne(ctx(t), bson.M{"_id": "alice", "who": "a"})
	must(t, err)
	_, err = cb.InsertOne(ctx(t), bson.M{"_id": "alice", "who": "b"})
	if !isDup(err) {
		t.Fatalf("native policy: expected the cross-tenant duplicate key collision, got %v", err)
	}
}

func TestIDPolicyRequireGenerated(t *testing.T) {
	e := setup(t, idPolicy("require-generated"))
	ca := e.tenant(t, "tenant-a").Database("app").Collection("items")
	cb := e.tenant(t, "tenant-b").Database("app").Collection("items")

	for name, id := range map[string]any{
		"int": 1, "string": "alice", "document": bson.M{"a": 1},
		"legacy uuid": bson.Binary{Subtype: 3, Data: make([]byte, 16)},
	} {
		if _, err := ca.InsertOne(ctx(t), bson.M{"_id": id}); err == nil {
			t.Errorf("%s _id accepted", name)
		}
	}
	oid := bson.NewObjectID()
	uuid := bson.Binary{Subtype: 4, Data: []byte("0123456789abcdef")}
	_, err := ca.InsertOne(ctx(t), bson.M{"_id": oid, "who": "a"})
	must(t, err)
	_, err = ca.InsertOne(ctx(t), bson.M{"_id": uuid, "who": "a"})
	must(t, err)
	_, err = ca.InsertOne(ctx(t), bson.M{"who": "a"}) // driver generates an ObjectId
	must(t, err)

	// Upserts.
	_, err = ca.UpdateOne(ctx(t), bson.M{"_id": 7}, bson.M{"$set": bson.M{"x": 1}}, options.UpdateOne().SetUpsert(true))
	mustFail(t, err, "upsert with an int _id")
	_, err = ca.UpdateOne(ctx(t), bson.M{"_id": bson.M{"$in": bson.A{oid}}}, bson.M{"$set": bson.M{"x": 1}}, options.UpdateOne().SetUpsert(true))
	mustFail(t, err, "upsert matching _id by $in")
	_, err = ca.ReplaceOne(ctx(t), bson.M{"who": "zz"}, bson.M{"_id": "named"}, options.Replace().SetUpsert(true))
	mustFail(t, err, "replacement upsert with a string _id")
	oid2 := bson.NewObjectID()
	r, err := ca.UpdateOne(ctx(t), bson.M{"_id": oid2}, bson.M{"$set": bson.M{"x": 1}}, options.UpdateOne().SetUpsert(true))
	must(t, err)
	if r.UpsertedCount != 1 {
		t.Fatal("upsert with a generated id failed")
	}
	res := ca.FindOneAndUpdate(ctx(t), bson.M{"_id": "str"}, bson.M{"$set": bson.M{"x": 1}}, options.FindOneAndUpdate().SetUpsert(true))
	mustFail(t, res.Err(), "findAndModify upsert with a string _id")

	// $merge cannot be vetted statically, so documents are checked at run time.
	_, err = ca.InsertOne(ctx(t), bson.M{"_id": oid2, "bad": false})
	if !isDup(err) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	cur, err := ca.Aggregate(ctx(t), bson.A{
		bson.M{"$match": bson.M{"who": "a", "_id": bson.M{"$type": "objectId"}}},
		bson.M{"$merge": bson.M{"into": "copy"}},
	})
	must(t, err)
	cur.Close(ctx(t))
	_, err = ca.InsertOne(ctx(t), bson.M{"_id": oid, "dup": 1})
	if !isDup(err) {
		t.Fatalf("expected duplicate, got %v", err)
	}
	// $merge whose documents have a non-generated _id fails.
	cur, err = ca.Aggregate(ctx(t), bson.A{
		bson.M{"$match": bson.M{"_id": oid}},
		bson.M{"$set": bson.M{"_id": "string-id"}},
		bson.M{"$merge": bson.M{"into": "copy2"}},
	})
	if err == nil {
		err = cur.All(ctx(t), &[]bson.M{})
	}
	mustFail(t, err, "$merge writing a string _id")

	// Cross-tenant: the same ObjectId collides, but the error reveals nothing.
	_, err = cb.InsertOne(ctx(t), bson.M{"_id": oid, "who": "b", "secret": "b-data"})
	if !isDup(err) {
		t.Fatalf("expected duplicate key, got %v", err)
	}
	msg := err.Error()
	for _, leak := range []string{"index", "dup key", "_id_", oid.Hex(), "tenant-a", "app.items"} {
		if strings.Contains(msg, leak) {
			t.Errorf("duplicate-key error leaks %q: %s", leak, msg)
		}
	}
	var we mongo.WriteException
	if ok := asWriteException(err, &we); ok {
		for _, w := range we.WriteErrors {
			if w.Raw != nil && (w.Raw.Lookup("keyValue").Type != 0 || w.Raw.Lookup("keyPattern").Type != 0) {
				t.Errorf("duplicate-key error still carries key details: %v", w.Raw)
			}
		}
	}
	// Unrelated, tenant-scoped unique index errors are left alone.
	em := e.tenant(t, "tenant-a").Database("app").Collection("emails")
	_, err = em.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.M{"email": 1}, Options: options.Index().SetUnique(true)})
	must(t, err)
	_, err = em.InsertOne(ctx(t), bson.M{"email": "x@example.com"})
	must(t, err)
	_, err = em.InsertOne(ctx(t), bson.M{"email": "x@example.com"})
	if !isDup(err) || !strings.Contains(err.Error(), "email_1") {
		t.Fatalf("expected an informative duplicate error for the email index, got %v", err)
	}
}

func asWriteException(err error, we *mongo.WriteException) bool {
	if w, ok := err.(mongo.WriteException); ok {
		*we = w
		return true
	}
	if b, ok := err.(mongo.BulkWriteException); ok {
		we.WriteErrors = nil
		for _, e := range b.WriteErrors {
			we.WriteErrors = append(we.WriteErrors, mongo.WriteError{Index: e.Index, Code: e.Code, Message: e.Message, Raw: e.Raw})
		}
		return true
	}
	return false
}

func TestIDPolicyNamespace(t *testing.T) {
	e := setup(t, idPolicy("namespace"))
	ca := e.tenant(t, "tenant-a").Database("app").Collection("items")
	cb := e.tenant(t, "tenant-b").Database("app").Collection("items")
	raw := e.direct.Database("app").Collection("items")

	// Two tenants, same natural ids.
	docs := func(who string) []any {
		return []any{
			bson.M{"_id": "alice", "who": who, "n": 1},
			bson.M{"_id": 42, "who": who, "n": 2},
			bson.M{"_id": bson.M{"k": "compound"}, "who": who, "n": 3},
			bson.M{"_id": 7, "who": who, "n": 4},
		}
	}
	_, err := ca.InsertMany(ctx(t), docs("a"))
	must(t, err)
	_, err = cb.InsertMany(ctx(t), docs("b"))
	must(t, err)

	t.Run("stored wrapped, read back unwrapped", func(t *testing.T) {
		stored, err := raw.FindOne(ctx(t), bson.M{"tenantId": "tenant-a", "who": "a", "n": 2}).Raw()
		must(t, err)
		w, ok := stored.Lookup("_id").DocumentOK()
		if !ok || w.Lookup("t").StringValue() != "tenant-a" || w.Lookup("id").Int32() != 42 {
			t.Fatalf("stored _id = %v, want {t: tenant-a, id: 42}", stored.Lookup("_id"))
		}
		var got bson.M
		must(t, ca.FindOne(ctx(t), bson.M{"_id": 42}).Decode(&got))
		if got["_id"] != int32(42) || got["who"] != "a" {
			t.Fatalf("got %v", got)
		}
		must(t, cb.FindOne(ctx(t), bson.M{"_id": "alice"}).Decode(&got))
		if got["_id"] != "alice" || got["who"] != "b" {
			t.Fatalf("tenant-b got %v", got)
		}
		must(t, ca.FindOne(ctx(t), bson.M{"_id": bson.M{"k": "compound"}}).Decode(&got))
		if got["n"] != int32(3) {
			t.Fatalf("compound _id lookup: %v", got)
		}
	})

	t.Run("duplicates within a tenant are generic", func(t *testing.T) {
		_, err := ca.InsertOne(ctx(t), bson.M{"_id": "alice"})
		if !isDup(err) {
			t.Fatalf("expected duplicate, got %v", err)
		}
		if strings.Contains(err.Error(), "tenant-a") || strings.Contains(err.Error(), "dup key") {
			t.Fatalf("leaky duplicate error: %v", err)
		}
	})

	t.Run("filters", func(t *testing.T) {
		n, err := ca.CountDocuments(ctx(t), bson.M{"_id": bson.M{"$in": bson.A{"alice", 42, "nobody"}}})
		must(t, err)
		if n != 2 {
			t.Fatalf("$in matched %d", n)
		}
		n, _ = ca.CountDocuments(ctx(t), bson.M{"_id": bson.M{"$ne": "alice"}})
		if n != 3 {
			t.Fatalf("$ne matched %d", n)
		}
		n, _ = ca.CountDocuments(ctx(t), bson.M{"_id": bson.M{"$gte": 7, "$lte": 42}, "who": "a", "n": bson.M{"$gte": 2}})
		if n < 2 {
			t.Fatalf("range matched %d", n)
		}
		n, _ = ca.CountDocuments(ctx(t), bson.M{"$or": bson.A{bson.M{"_id": 7}, bson.M{"_id": 42}}})
		if n != 2 {
			t.Fatalf("$or matched %d", n)
		}
		n, _ = ca.CountDocuments(ctx(t), bson.M{"_id.k": "compound"})
		if n != 1 {
			t.Fatalf("dotted _id matched %d", n)
		}
		// Sorting by _id stays within the tenant.
		cur, err := ca.Find(ctx(t), bson.M{"_id": bson.M{"$in": bson.A{7, 42}}}, options.Find().SetSort(bson.M{"_id": -1}).SetBatchSize(1))
		must(t, err)
		var all []bson.M
		must(t, cur.All(ctx(t), &all)) // exercises getMore unwrapping
		if len(all) != 2 || all[0]["_id"] != int32(42) || all[1]["_id"] != int32(7) {
			t.Fatalf("sorted batch: %v", all)
		}
		ids, err := ca.Distinct(ctx(t), "_id", bson.M{"_id": bson.M{"$in": bson.A{7, 42}}}).Raw()
		must(t, err)
		if s := ids.String(); !strings.Contains(s, "7") || !strings.Contains(s, "42") || strings.Contains(s, "tenant-a") {
			t.Fatalf("distinct _id = %s", s)
		}
	})

	t.Run("updates, upserts, deletes", func(t *testing.T) {
		r, err := ca.UpdateOne(ctx(t), bson.M{"_id": 42}, bson.M{"$set": bson.M{"touched": true}})
		must(t, err)
		if r.ModifiedCount != 1 {
			t.Fatal("update missed")
		}
		var other bson.M
		must(t, cb.FindOne(ctx(t), bson.M{"_id": 42}).Decode(&other))
		if other["touched"] != nil {
			t.Fatal("update leaked to tenant-b")
		}
		r, err = ca.UpdateOne(ctx(t), bson.M{"_id": "new-key"}, bson.M{"$set": bson.M{"v": 1}}, options.UpdateOne().SetUpsert(true))
		must(t, err)
		if r.UpsertedID != "new-key" {
			t.Fatalf("UpsertedID = %v (%T)", r.UpsertedID, r.UpsertedID)
		}
		var got bson.M
		must(t, ca.FindOne(ctx(t), bson.M{"_id": "new-key"}).Decode(&got))
		// Upsert by another field: proxy assigns a generated, wrapped _id.
		r, err = ca.UpdateOne(ctx(t), bson.M{"slug": "s1"}, bson.M{"$set": bson.M{"v": 2}}, options.UpdateOne().SetUpsert(true))
		must(t, err)
		oid, isOID := r.UpsertedID.(bson.ObjectID)
		if !isOID {
			t.Fatalf("UpsertedID = %v (%T), want an ObjectId", r.UpsertedID, r.UpsertedID)
		}
		must(t, ca.FindOne(ctx(t), bson.M{"_id": oid}).Decode(&got))
		_, err = ca.UpdateOne(ctx(t), bson.M{"_id": oid}, bson.M{"$set": bson.M{"v": 3}})
		must(t, err)
		// Replace keeps the _id.
		_, err = ca.ReplaceOne(ctx(t), bson.M{"_id": "alice"}, bson.M{"_id": "alice", "who": "a", "replaced": true})
		must(t, err)
		must(t, ca.FindOne(ctx(t), bson.M{"_id": "alice"}).Decode(&got))
		if got["replaced"] != true {
			t.Fatalf("replace: %v", got)
		}
		// findAndModify returns unwrapped documents and upserted ids.
		var fm bson.M
		must(t, ca.FindOneAndUpdate(ctx(t), bson.M{"_id": 7}, bson.M{"$inc": bson.M{"n": 10}},
			options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&fm))
		if fm["_id"] != int32(7) || fm["n"] != int32(14) {
			t.Fatalf("findAndModify: %v", fm)
		}
		must(t, ca.FindOneAndUpdate(ctx(t), bson.M{"_id": "fam-new"}, bson.M{"$set": bson.M{"z": 1}},
			options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)).Decode(&fm))
		if fm["_id"] != "fam-new" {
			t.Fatalf("findAndModify upsert: %v", fm)
		}
		// Updating _id itself is refused.
		_, err = ca.UpdateOne(ctx(t), bson.M{"_id": 7}, bson.M{"$set": bson.M{"_id": 8}})
		mustFail(t, err, "$set _id")

		d, err := ca.DeleteOne(ctx(t), bson.M{"_id": 7})
		must(t, err)
		if d.DeletedCount != 1 {
			t.Fatal("delete missed")
		}
		if n, _ := cb.CountDocuments(ctx(t), bson.M{"_id": 7}); n != 1 {
			t.Fatal("delete leaked to tenant-b")
		}
	})

	t.Run("aggregation", func(t *testing.T) {
		cur, err := ca.Aggregate(ctx(t), bson.A{
			bson.M{"$match": bson.M{"_id": "alice"}},
			bson.M{"$project": bson.M{"who": 1}},
		})
		must(t, err)
		var out []bson.M
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 || out[0]["_id"] != "alice" {
			t.Fatalf("aggregate: %v", out)
		}
		// $group's _id is the group key and must come back untouched.
		out = nil
		cur, err = ca.Aggregate(ctx(t), bson.A{
			bson.M{"$match": bson.M{"who": "a"}},
			bson.M{"$group": bson.M{"_id": "$who", "c": bson.M{"$sum": 1}}},
		})
		must(t, err)
		out = nil
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 || out[0]["_id"] != "a" {
			t.Fatalf("group: %v", out)
		}
		// A later $match on the group key is not an _id match.
		cur, err = ca.Aggregate(ctx(t), bson.A{
			bson.M{"$group": bson.M{"_id": "$who"}},
			bson.M{"$match": bson.M{"_id": "a"}},
		})
		must(t, err)
		out = nil
		must(t, cur.All(ctx(t), &out))
		if len(out) != 1 {
			t.Fatalf("match after group: %v", out)
		}
	})

	t.Run("unsupported operators are rejected clearly", func(t *testing.T) {
		bad := map[string]func() error{
			"regex on _id": func() error { return ca.FindOne(ctx(t), bson.M{"_id": bson.M{"$regex": "^a"}}).Err() },
			"$expr on _id": func() error {
				return ca.FindOne(ctx(t), bson.M{"$expr": bson.M{"$eq": bson.A{"$_id", "alice"}}}).Err()
			},
			"$lookup": func() error {
				_, err := ca.Aggregate(ctx(t), bson.A{bson.M{"$lookup": bson.M{"from": "items", "localField": "a", "foreignField": "b", "as": "x"}}})
				return err
			},
			"$group by $_id": func() error {
				_, err := ca.Aggregate(ctx(t), bson.A{bson.M{"$group": bson.M{"_id": "$_id"}}})
				return err
			},
			"$merge": func() error {
				_, err := ca.Aggregate(ctx(t), bson.A{bson.M{"$merge": "other"}})
				return err
			},
			"change stream": func() error { _, err := ca.Watch(ctx(t), mongo.Pipeline{}); return err },
		}
		for name, f := range bad {
			err := f()
			if err == nil {
				t.Errorf("%s was accepted", name)
			} else if !strings.Contains(err.Error(), "namespace") && !strings.Contains(err.Error(), "change streams") {
				t.Errorf("%s: unclear error: %v", name, err)
			}
		}
		_, err := e.tenant(t, "tenant-a").Database("app").Collection("v").InsertOne(ctx(t), bson.M{"a": 1})
		must(t, err)
		mustFail(t, e.tenant(t, "tenant-a").Database("app").CreateView(ctx(t), "vw", "v", mongo.Pipeline{}), "view creation")
	})

	t.Run("tenant isolation still holds", func(t *testing.T) {
		if n := count(t, raw, bson.M{"tenantId": "tenant-b"}); n != 4 {
			t.Fatalf("tenant-b has %d docs upstream, want 4 untouched", n)
		}
	})
}

func TestNamespaceRequiresExperimentalFlag(t *testing.T) {
	c := &config.Config{Auth: config.Auth{Mode: "static", StaticTenant: "x"}, Tenant: config.Tenant{IDPolicy: "namespace"}}
	if err := config.Validate(c); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("expected an error about the experimental flag, got %v", err)
	}
	c.Tenant.ExperimentalNamespace = true
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	if !c.ChangeStreams.Disabled || !c.DisableViews {
		t.Fatal("namespace must switch off change streams and views")
	}
	c.Tenant.IDPolicy = "bogus"
	if err := config.Validate(c); err == nil {
		t.Fatal("bogus policy accepted")
	}
}
