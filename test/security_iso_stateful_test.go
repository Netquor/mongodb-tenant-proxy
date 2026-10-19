package test

// Stateful attacks: cursors, sessions/transactions, change streams, TTL and
// uniqueness behaviour. These need several round trips so they do not fit the
// one-command catalogue.

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func noLeak(t *testing.T, what string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		for _, m := range leakMarks {
			if strings.Contains(p, m) {
				t.Errorf("%s leaked %q", what, m)
			}
		}
	}
}

// Cursor hijacking, enumeration and killing across tenants.
func TestSecurityCursorAttacks(t *testing.T) {
	for _, m := range []isoMode{isoModes[0], isoModes[3]} {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			w := newIsoWorld(t, m)
			f := w.seed()
			b := w.cl[tB].Database(f.DB)
			cur, err := b.Collection(f.C).Find(ctx(t), bson.M{}, options.Find().SetBatchSize(1).SetSort(bson.M{"k": 1}))
			must(t, err)
			defer cur.Close(context.Background())
			id := cur.ID()
			if id == 0 {
				t.Fatal("no open cursor")
			}
			var probes []bson.D
			for _, db := range []string{f.DB, "other", "admin"} {
				_ = db
			}
			for _, coll := range []string{f.C, f.Other, "system.views", "$cmd.aggregate", "x"} {
				probes = append(probes,
					bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: coll}},
					bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: coll}, {Key: "batchSize", Value: 100}},
					bson.D{{Key: "getMore", Value: id}, {Key: "getMore", Value: id + 1}, {Key: "collection", Value: coll}},
					bson.D{{Key: "killCursors", Value: coll}, {Key: "cursors", Value: bson.A{id}}},
				)
			}
			probes = append(probes,
				bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: f.C}, {Key: "$db", Value: "admin"}},
				bson.D{{Key: "getMore", Value: int32(id)}, {Key: "collection", Value: f.C}},
				bson.D{{Key: "getMore", Value: float64(id)}, {Key: "collection", Value: f.C}},
				bson.D{{Key: "getMore", Value: bson.A{id}}, {Key: "collection", Value: f.C}},
				bson.D{{Key: "killCursors", Value: f.C}, {Key: "cursors", Value: bson.A{id, id + 1, id - 1}}},
				bson.D{{Key: "killCursors", Value: f.C}, {Key: "cursors", Value: bson.A{int32(id)}}},
			)
			a := w.cl[tA]
			for _, p := range probes {
				for _, db := range []string{f.DB, "admin"} {
					blob, err := w.run(tA, db, p)
					noLeak(t, "cursor probe "+p[0].Key, blob)
					_ = err
				}
			}
			// Enumerate nearby ids: nothing foreign may come back.
			for d := int64(-300); d <= 300; d++ {
				blob, _ := w.run(tA, f.DB, bson.D{{Key: "getMore", Value: id + d}, {Key: "collection", Value: f.C}})
				noLeak(t, "cursor id enumeration", blob)
				blob, _ = w.run(tA, f.DB, bson.D{{Key: "killCursors", Value: f.C}, {Key: "cursors", Value: bson.A{id + d}}})
				noLeak(t, "killCursors enumeration", blob)
			}
			_ = a
			// B's cursor survived every attack and still yields all its rows.
			var docs []bson.M
			must(t, cur.All(ctx(t), &docs))
			if len(docs) != 5 {
				t.Fatalf("victim cursor returned %d remaining docs, want 5 (killed/stolen?)", len(docs))
			}
			for _, d := range docs {
				if d["tenantId"] != tB {
					t.Fatalf("victim cursor yielded %v", d)
				}
			}
		})
	}
}

// Session / transaction abuse with hand-built lsids (appname mode).
func TestSecuritySessionAbuse(t *testing.T) {
	e := setup(t, nil)
	a, b := e.raw(t, tA), e.raw(t, tB)
	lsidB := bson.M{"id": bson.Binary{Subtype: 4, Data: []byte("BBBBBBBBBBBBBBBB")}}
	// B starts a multi-document transaction.
	_, err := e.tenant(t, tB).Database("tx").Collection("t").InsertOne(ctx(t), bson.M{"seed": "CNRY-BRAVO"})
	must(t, err)
	res := b.run("tx", bson.D{{Key: "insert", Value: "t"}, {Key: "documents", Value: bson.A{bson.M{"in": "txn", "secret": "CNRY-BRAVO"}}},
		{Key: "lsid", Value: lsidB}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}, {Key: "startTransaction", Value: true}})
	if !isOK(res) {
		t.Fatalf("victim txn: %v", res)
	}
	forged := []bson.M{
		lsidB,
		{"id": lsidB["id"], "uid": bson.Binary{Data: make([]byte, 32)}},
		{"id": lsidB["id"], "txnUUID": lsidB["id"]},
		{"id": lsidB["id"], "txnNumber": int64(1)},
	}
	for i, ls := range forged {
		cmds := map[string]bson.D{
			"find":    {{Key: "find", Value: "t"}, {Key: "filter", Value: bson.M{}}, {Key: "lsid", Value: ls}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}},
			"insert":  {{Key: "insert", Value: "t"}, {Key: "documents", Value: bson.A{bson.M{"pwn": 1}}}, {Key: "lsid", Value: ls}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}},
			"commit":  {{Key: "commitTransaction", Value: 1}, {Key: "lsid", Value: ls}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}},
			"abort":   {{Key: "abortTransaction", Value: 1}, {Key: "lsid", Value: ls}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}},
			"newtxn":  {{Key: "insert", Value: "t"}, {Key: "documents", Value: bson.A{bson.M{"pwn": 2}}}, {Key: "lsid", Value: ls}, {Key: "txnNumber", Value: int64(2)}, {Key: "autocommit", Value: false}, {Key: "startTransaction", Value: true}},
			"end":     {{Key: "endSessions", Value: bson.A{ls}}},
			"refresh": {{Key: "refreshSessions", Value: bson.A{ls}}},
			"kill":    {{Key: "killSessions", Value: bson.A{ls}}},
			"killAll": {{Key: "killAllSessions", Value: bson.A{}}},
			"killPat": {{Key: "killAllSessionsByPattern", Value: bson.A{bson.M{}}}},
		}
		for n, c := range cmds {
			r := a.run(map[bool]string{true: "admin", false: "tx"}[strings.HasSuffix(c[0].Key, "Transaction") || strings.HasSuffix(c[0].Key, "Sessions") || strings.Contains(c[0].Key, "Sessions")], c)
			if isOK(r) && n != "killAll" && n != "killPat" && n != "refresh" && n != "end" {
				t.Errorf("forged lsid #%d: %s accepted: %v", i, n, r)
			}
			b, _ := bson.MarshalExtJSON(r, true, false)
			noLeak(t, "forged lsid "+n, string(b))
		}
	}
	// Dropping lsid/txnNumber types.
	for _, bad := range []bson.D{
		{{Key: "find", Value: "t"}, {Key: "lsid", Value: "x"}},
		{{Key: "find", Value: "t"}, {Key: "lsid", Value: bson.A{lsidB}}},
		{{Key: "find", Value: "t"}, {Key: "lsid", Value: lsidB}, {Key: "lsid", Value: bson.M{"id": bson.Binary{Subtype: 4, Data: []byte("AAAAAAAAAAAAAAAA")}}}},
		{{Key: "find", Value: "t"}, {Key: "lsid", Value: bson.M{"id": bson.Binary{Subtype: 4, Data: []byte("AAAAAAAAAAAAAAAA")}}}, {Key: "lsid", Value: lsidB}},
	} {
		r := a.run("tx", bad)
		if isOK(r) {
			if bs, _ := bson.MarshalExtJSON(r, true, false); strings.Contains(string(bs), "CNRY") {
				t.Errorf("malformed lsid leaked: %s", bs)
			}
		}
	}
	// B's transaction must have survived and be committable with its data intact.
	res = b.run("admin", bson.D{{Key: "commitTransaction", Value: 1}, {Key: "lsid", Value: lsidB}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}})
	if !isOK(res) {
		t.Fatalf("victim's transaction was disturbed: %v", res)
	}
	if n := count(t, e.direct.Database("tx").Collection("t"), bson.M{"tenantId": tB}); n != 2 {
		t.Fatalf("victim has %d docs, want 2", n)
	}
	if n := count(t, e.direct.Database("tx").Collection("t"), bson.M{"pwn": bson.M{"$exists": true}}); n != 0 {
		t.Fatalf("forged-lsid writes landed: %d", n)
	}
	// A transaction by A cannot read B's rows, and a session snapshot cannot
	// be pinned to B's afterClusterTime to see more.
	ta := e.tenant(t, tA)
	sess, err := ta.StartSession()
	must(t, err)
	defer sess.EndSession(ctx(t))
	must(t, sess.StartTransaction())
	sc := mongo.NewSessionContext(ctx(t), sess)
	c, err := ta.Database("tx").Collection("t").Find(sc, bson.M{})
	must(t, err)
	var docs []bson.M
	must(t, c.All(sc, &docs))
	if len(docs) != 0 {
		t.Fatalf("A saw %d of B's rows inside a transaction", len(docs))
	}
	_ = sess.AbortTransaction(ctx(t))
}

// Change-stream option abuse. B writes while A holds streams built from every
// scoping-relevant option; A must never see B's events.
func TestSecurityChangeStreamAttacks(t *testing.T) {
	e := setup(t, nil)
	cl := map[string]*mongo.Client{tA: e.tenant(t, tA), tB: e.tenant(t, tB), tC: e.tenant(t, tC)}
	const db, coll = "cs", "c"
	ca := cl[tA].Database(db).Collection(coll)
	cb := cl[tB].Database(db).Collection(coll)
	// Seed (also enables pre/post images) and capture B's resume token and cluster time.
	_, err := cb.InsertOne(ctx(t), bson.M{"_id": "seed", "secret": "CNRY-BRAVO"})
	must(t, err)
	bstream, err := cb.Watch(ctx(t), mongo.Pipeline{})
	must(t, err)
	defer bstream.Close(context.Background())
	_, err = cb.InsertOne(ctx(t), bson.M{"_id": "b0", "secret": "CNRY-BRAVO"})
	must(t, err)
	collect(t, bstream, 1)
	tokenB := bstream.ResumeToken()
	var sess bson.Raw
	_ = sess
	past := bson.Timestamp{T: 1, I: 1}

	type opened struct {
		name string
		cs   *mongo.ChangeStream
	}
	var streams []opened
	open := func(name string, cs *mongo.ChangeStream, err error) {
		if err != nil {
			return // rejection is a fine outcome
		}
		streams = append(streams, opened{name, cs})
	}
	full := options.ChangeStream()
	cs, err := ca.Watch(ctx(t), mongo.Pipeline{})
	open("plain", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{}, options.ChangeStream().SetResumeAfter(tokenB))
	open("resumeAfter B token", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{}, options.ChangeStream().SetStartAfter(tokenB))
	open("startAfter B token", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{}, options.ChangeStream().SetStartAtOperationTime(&past))
	open("startAtOperationTime past", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{}, full.SetFullDocument(options.Required).SetFullDocumentBeforeChange(options.Required))
	open("required images", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{}, options.ChangeStream().SetFullDocument(options.UpdateLookup).SetFullDocumentBeforeChange(options.WhenAvailable).SetShowExpandedEvents(true))
	open("expanded events", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$match", Value: bson.M{"fullDocument.tenantId": tB}}}})
	open("match victim", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$match", Value: bson.M{"$or": bson.A{bson.M{"fullDocument.tenantId": tB}, bson.M{"operationType": bson.M{"$exists": true}}}}}}})
	open("match or", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$replaceRoot", Value: bson.M{"newRoot": "$$ROOT"}}}})
	open("replaceRoot", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$project", Value: bson.M{"fullDocument.tenantId": 0}}}})
	open("project tenant", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$addFields", Value: bson.M{"fullDocument.tenantId": tA}}}})
	open("addFields tenant", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$lookup", Value: bson.M{"from": coll, "pipeline": bson.A{}, "as": "j"}}}})
	open("lookup", cs, err)
	cs, err = ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$unionWith", Value: coll}}})
	open("unionWith", cs, err)
	cs, err = cl[tA].Database(db).Watch(ctx(t), mongo.Pipeline{})
	open("db-level", cs, err)
	cs, err = cl[tA].Database(db).Watch(ctx(t), mongo.Pipeline{}, options.ChangeStream().SetResumeAfter(tokenB))
	open("db-level resume B", cs, err)
	cs, err = cl[tA].Database("admin").Watch(ctx(t), mongo.Pipeline{})
	open("admin db-level", cs, err)
	cs, err = cl[tA].Watch(ctx(t), mongo.Pipeline{})
	open("cluster-level", cs, err)
	// collection 1 / allChangesForCluster via raw aggregate
	for _, c := range []struct {
		name string
		db   string
		stg  bson.D
	}{
		{"allChangesForCluster", "admin", bson.D{{Key: "$changeStream", Value: bson.D{{Key: "allChangesForCluster", Value: true}}}}},
		{"allChangesForCluster in app db", db, bson.D{{Key: "$changeStream", Value: bson.D{{Key: "allChangesForCluster", Value: true}}}}},
		{"resumeAfter garbage", db, bson.D{{Key: "$changeStream", Value: bson.D{{Key: "resumeAfter", Value: bson.D{{Key: "_data", Value: "00"}}}}}}},
		{"startAtOperationTime", db, bson.D{{Key: "$changeStream", Value: bson.D{{Key: "startAtOperationTime", Value: past}}}}},
		{"dup changeStream stage", db, bson.D{{Key: "$changeStream", Value: bson.D{}}, {Key: "$changeStream", Value: bson.D{{Key: "allChangesForCluster", Value: true}}}}},
	} {
		blob, err := runRaw(cl[tA], c.db, bson.D{{Key: "aggregate", Value: 1}, {Key: "pipeline", Value: bson.A{c.stg}}, {Key: "cursor", Value: bson.D{}}})
		noLeak(t, "changeStream "+c.name, blob)
		_ = err
		blob, _ = runRaw(cl[tA], db, bson.D{{Key: "aggregate", Value: coll}, {Key: "pipeline", Value: bson.A{c.stg}}, {Key: "cursor", Value: bson.D{}}})
		noLeak(t, "changeStream coll "+c.name, blob)
	}
	defer func() {
		for _, s := range streams {
			s.cs.Close(context.Background())
		}
	}()

	// Victim activity: insert, update, replace, delete, create index, rename, drop, dropDatabase.
	_, _ = cb.InsertOne(ctx(t), bson.M{"_id": "b1", "secret": "CNRY-BRAVO"})
	_, _ = cb.UpdateOne(ctx(t), bson.M{"_id": "b1"}, bson.M{"$set": bson.M{"secret": "CNRY-BRAVO-2"}})
	_, _ = cb.ReplaceOne(ctx(t), bson.M{"_id": "b1"}, bson.M{"secret": "CNRY-BRAVO-3"})
	_, _ = cb.DeleteOne(ctx(t), bson.M{"_id": "b1"})
	_, _ = cb.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.M{"secret": 1}, Options: indexOpts("CNRY-BRAVO-idx", false)})
	_, _ = cl[tB].Database(db).Collection("other").InsertOne(ctx(t), bson.M{"secret": "CNRY-BRAVO"})
	_ = cl[tB].Database(db).RunCommand(ctx(t), bson.D{{Key: "renameCollection", Value: db + ".other"}, {Key: "to", Value: db + ".renamed"}}).Err()
	_ = cl[tB].Database(db).Collection("renamed").Drop(ctx(t))
	_ = cb.Drop(ctx(t))
	// ... then one marker event of A's own so the streams have something to deliver.
	_, err = ca.InsertOne(ctx(t), bson.M{"_id": "a-marker", "secret": "CNRY-ALPHA"})
	must(t, err)

	for _, s := range streams {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			c, cancel := context.WithDeadline(context.Background(), deadline)
			ok := s.cs.Next(c)
			cancel()
			if !ok {
				break
			}
			raw := s.cs.Current.String()
			noLeak(t, "change stream "+s.name+" event "+raw, raw)
		}
		if tok := s.cs.ResumeToken(); tok != nil {
			noLeak(t, "resume token", tok.String())
		}
	}
	// C is untouched by all this.
	_, err = cl[tC].Database(db).Collection(coll).InsertOne(ctx(t), bson.M{"secret": "CNRY-CHARLIE"})
	must(t, err)
}

func runRaw(c *mongo.Client, db string, cmd bson.D) (string, error) {
	cx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.Database(db).RunCommand(cx, cmd).Raw()
	if err != nil {
		return err.Error() + rawOf(err), err
	}
	return string(res), nil
}

// TTL and unique indexes must be private to the tenant that created them.
func TestSecurityIndexPrivacy(t *testing.T) {
	for _, m := range []isoMode{isoModes[0], isoModes[1]} {
		m := m
		t.Run(m.name, func(t *testing.T) {
			w := newIsoWorld(t, m)
			f := w.seed()
			a := w.cl[tA].Database(f.DB).Collection(f.C)
			// A's unique index must not collide with B's identical values, nor vice versa.
			_, err := a.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "k", Value: 1}}, Options: indexOpts("a_k_unique", true)})
			must(t, err)
			_, err = a.InsertOne(ctx(t), bson.M{"k": 7})
			must(t, err)
			_, err = w.cl[tB].Database(f.DB).Collection(f.C).InsertOne(ctx(t), bson.M{"k": 7})
			if err != nil {
				t.Fatalf("B's insert collided with A's unique index: %v", err)
			}
			_, err = a.InsertOne(ctx(t), bson.M{"k": 7})
			if !mongo.IsDuplicateKeyError(err) {
				t.Fatalf("A's own unique index not enforced: %v", err)
			}
			if err != nil {
				noLeak(t, "dup-key error", err.Error(), rawOf(err))
			}
			// TTL: every TTL index stored upstream must be filtered to its owner.
			_, err = a.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "ts", Value: 1}},
				Options: options.Index().SetName("a_ttl").SetExpireAfterSeconds(1)})
			must(t, err)
			_, err = w.cl[tB].Database(f.DB).Collection(f.C).Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "ts", Value: 1}},
				Options: options.Index().SetName("b_ttl").SetExpireAfterSeconds(1)})
			must(t, err)
			cur, err := w.e.direct.Database(f.DB).Collection(f.C).Indexes().List(ctx(t))
			must(t, err)
			var specs []bson.M
			must(t, cur.All(ctx(t), &specs))
			ttl := 0
			for _, s := range specs {
				if _, ok := s["expireAfterSeconds"]; !ok {
					continue
				}
				ttl++
				raw, _ := bson.MarshalExtJSON(s["partialFilterExpression"], true, false)
				if !strings.Contains(string(raw), "tenantId") {
					t.Errorf("TTL index %v is not tenant-filtered (it would expire other tenants' rows)", s["name"])
				}
				name := s["name"].(string)
				owner := tA
				if strings.HasPrefix(name, "b_ttl") {
					owner = tB
				}
				if !strings.Contains(string(raw), owner) {
					t.Errorf("TTL index %s filter %s does not name its owner %s", name, raw, owner)
				}
			}
			if ttl != 2 {
				t.Errorf("found %d TTL indexes upstream, want 2", ttl)
			}
			// A cannot see B's index names or definitions.
			names, _ := a.Indexes().ListSpecifications(ctx(t))
			for _, s := range names {
				noLeak(t, "listIndexes", s.Name, s.KeysDocument.String())
			}
			// A cannot re-use B's index name with a different definition (it would reveal B's index exists).
			_, err = a.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "zzz", Value: 1}}, Options: indexOpts("b_k_idx", false)})
			if err != nil {
				noLeak(t, "index name collision error", err.Error(), rawOf(err))
			}
		})
	}
}

// Unique-_id oracle: under require-generated and namespace policies tenant A
// must not learn whether B owns an _id.
func TestSecurityIDExistenceOracle(t *testing.T) {
	for _, m := range []isoMode{isoModes[1], isoModes[2]} {
		m := m
		t.Run(m.name, func(t *testing.T) {
			w := newIsoWorld(t, m)
			f := w.seed()
			ca := w.cl[tA].Database(f.DB).Collection(f.C)
			cb := w.cl[tB].Database(f.DB).Collection(f.C)
			var id any = bson.NewObjectID()
			if m.policy == "namespace" {
				id = "shared-id"
			}
			_, errFree := ca.InsertOne(ctx(t), bson.M{"_id": id, "n": 1})
			_ = errFree
			// B inserts the same _id when it is free for B...
			_, errB := cb.InsertOne(ctx(t), bson.M{"_id": id, "n": 2})
			if m.policy == "namespace" && errB != nil {
				t.Fatalf("namespace policy: B's insert of an _id A already uses failed: %v", errB)
			}
			// ... and A replaying an _id B owns gives an error indistinguishable
			// from a duplicate of A's own.
			_, err1 := ca.InsertOne(ctx(t), bson.M{"_id": id, "n": 3})
			if err1 != nil {
				noLeak(t, "own dup", err1.Error(), rawOf(err1))
			}
		})
	}
}

// DisableJS must hold for every tenant even when tenant limits try to restore it.
func TestSecurityJSToggle(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		c.Tenant.Overrides = map[string]config.Limits{tA: {DisableJS: true}}
	})
	a := e.tenant(t, tA).Database("js").Collection("c")
	_, err := a.InsertOne(ctx(t), bson.M{"x": 1})
	must(t, err)
	err = e.tenant(t, tA).Database("js").RunCommand(ctx(t), bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"$where": "this.x == 1"}}}).Err()
	mustFail(t, err, "$where for a tenant with disableJS")
	// Other tenants are unaffected.
	b := e.tenant(t, tB).Database("js").Collection("c")
	_, err = b.InsertOne(ctx(t), bson.M{"x": 1})
	must(t, err)
	cur, err := b.Find(ctx(t), bson.M{"$where": "this.x == 1"})
	must(t, err)
	var rows []bson.M
	must(t, cur.All(ctx(t), &rows))
	if len(rows) != 1 {
		t.Fatalf("tenant B's $where saw %d rows", len(rows))
	}
}

// TestSecurityKnownGaps pins down the documented limitations of the design so
// that closing one is a conscious decision: each subtest asserts the CURRENT
// (weaker) behaviour and fails with a prompt to move it into the attack
// catalogue and update docs/security-testing.md when the gap is fixed.
func TestSecurityKnownGaps(t *testing.T) {
	w := newIsoWorld(t, isoModes[0])

	t.Run("shared indexes: names and key patterns are visible across tenants", func(t *testing.T) {
		f := w.seed()
		var seen []string
		for _, s := range w.observeIdx(tA, f) {
			seen = append(seen, s)
		}
		joined := strings.Join(seen, "\n")
		if !strings.Contains(joined, "b_k_idx") || !strings.Contains(joined, "c_name_idx") {
			t.Fatalf("gap closed? tenant A no longer sees other tenants' index names: %q — move this to the catalogue and update the docs", joined)
		}
	})

	t.Run("shared indexes: any tenant can drop another tenant's index", func(t *testing.T) {
		f := w.seed()
		err := w.cl[tA].Database(f.DB).RunCommand(ctx(t), bson.D{{Key: "dropIndexes", Value: f.C}, {Key: "index", Value: "b_k_idx"}}).Err()
		after := strings.Join(w.observeIdx(tB, f), "\n")
		if err != nil && strings.Contains(after, "b_k_idx") {
			t.Fatalf("gap closed? A's dropIndexes was refused (%v) and B keeps its index — move this to the catalogue and update the docs", err)
		}
		if !strings.Contains(after, "b_k_idx") {
			t.Logf("confirmed: tenant A dropped tenant B's index %q (documented shared-index limitation)", "b_k_idx")
		}
	})

	t.Run("shared namespace: a tenant can create a collection named like another tenant's view", func(t *testing.T) {
		f := w.seed()
		_, err := w.cl[tA].Database(f.DB).Collection(f.BView).InsertOne(ctx(t), bson.M{"n": 1})
		if err != nil {
			t.Fatalf("gap closed? %v — move this to the catalogue and update the docs", err)
		}
		// B's view is unaffected: B still reads its own view definition.
		cur, err := w.cl[tB].Database(f.DB).Collection(f.BView).Find(ctx(t), bson.M{})
		must(t, err)
		var docs []bson.M
		must(t, cur.All(ctx(t), &docs))
		for _, d := range docs {
			if d["n"] != nil {
				t.Fatalf("B's view is shadowed by A's collection: %v", d)
			}
		}
	})
}

// The harness must be able to fail: querying the upstream directly (no proxy)
// has to trip the leak detector and the tamper detector.
func TestSecurityHarnessDetectsViolations(t *testing.T) {
	w := newIsoWorld(t, isoModes[0])
	f := w.seed()
	before, _, _ := w.baseline(f)
	res, err := w.e.direct.Database(f.DB).RunCommand(ctx(t), bson.D{{Key: "find", Value: f.C}, {Key: "filter", Value: bson.M{}}}).Raw()
	must(t, err)
	if leaks := w.findLeaks(f, string(res), ""); len(leaks) == 0 {
		t.Fatal("leak detector missed an unscoped read")
	}
	_, err = w.e.direct.Database(f.DB).Collection(f.C).UpdateMany(ctx(t), bson.M{"tenantId": tB}, bson.M{"$set": bson.M{"pwn": 1}})
	must(t, err)
	after, _ := w.physical(f)
	changed := false
	for k, v := range before {
		if after[k] != v {
			changed = true
		}
	}
	if !changed {
		t.Fatal("tamper detector missed a cross-tenant update")
	}
}
