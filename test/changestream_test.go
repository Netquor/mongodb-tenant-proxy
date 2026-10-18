package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

type event struct {
	Op     string `bson:"operationType"`
	Full   bson.M `bson:"fullDocument"`
	Before bson.M `bson:"fullDocumentBeforeChange"`
}

func collect(t *testing.T, cs *mongo.ChangeStream, n int) []event {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out []event
	for len(out) < n && cs.Next(c) {
		var ev event
		must(t, cs.Decode(&ev))
		out = append(out, ev)
	}
	if len(out) < n {
		t.Fatalf("got %d events, want %d (err=%v)", len(out), n, cs.Err())
	}
	return out
}

func TestChangeStreams(t *testing.T) {
	e := setup(t, nil) // change streams are on by default
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	ca, cb := a.Database("cs").Collection("c"), b.Database("cs").Collection("c")

	plain, err := ca.Watch(ctx(t), mongo.Pipeline{})
	must(t, err)
	defer plain.Close(context.Background())
	rich, err := ca.Watch(ctx(t), mongo.Pipeline{},
		options.ChangeStream().SetFullDocument(options.UpdateLookup).SetFullDocumentBeforeChange(options.WhenAvailable))
	must(t, err)
	defer rich.Close(context.Background())
	bs, err := cb.Watch(ctx(t), mongo.Pipeline{})
	must(t, err)
	defer bs.Close(context.Background())

	// Interleave both tenants' writes; each stream must see only its own.
	_, err = cb.InsertOne(ctx(t), bson.M{"_id": "b1", "v": 1})
	must(t, err)
	_, err = ca.InsertOne(ctx(t), bson.M{"_id": "a1", "v": 1})
	must(t, err)
	_, err = cb.UpdateOne(ctx(t), bson.M{"_id": "b1"}, bson.M{"$set": bson.M{"v": 2}})
	must(t, err)
	_, err = ca.UpdateOne(ctx(t), bson.M{"_id": "a1"}, bson.M{"$set": bson.M{"v": 2}})
	must(t, err)
	_, err = cb.DeleteOne(ctx(t), bson.M{"_id": "b1"})
	must(t, err)
	_, err = ca.DeleteOne(ctx(t), bson.M{"_id": "a1"})
	must(t, err)

	evs := collect(t, plain, 3)
	for i, op := range []string{"insert", "update", "delete"} {
		if evs[i].Op != op {
			t.Fatalf("event %d = %s, want %s", i, evs[i].Op, op)
		}
	}
	if evs[0].Full["tenantId"] != "tenant-a" {
		t.Fatalf("insert event: %v", evs[0].Full)
	}
	if evs[1].Full != nil || evs[1].Before != nil || evs[2].Before != nil {
		t.Fatalf("plain stream leaked images: %+v", evs[1:])
	}

	rv := collect(t, rich, 3)
	if rv[1].Full["v"] != int32(2) || rv[1].Before["v"] != int32(1) {
		t.Fatalf("update with images: %+v", rv[1])
	}
	if rv[2].Before["tenantId"] != "tenant-a" {
		t.Fatalf("delete before-image: %+v", rv[2])
	}

	bev := collect(t, bs, 3)
	for _, ev := range bev {
		for _, d := range []bson.M{ev.Full, ev.Before} {
			if d != nil && d["tenantId"] != "tenant-b" {
				t.Fatalf("B's stream saw %v", d)
			}
		}
	}
	// Nothing else is pending on A's stream: no B events slipped through.
	c, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if plain.TryNext(c) {
		var ev event
		plain.Decode(&ev)
		t.Fatalf("unexpected extra event on A's stream: %+v", ev)
	}

	// Db-level and cluster-level streams are refused.
	if cs, err := a.Database("cs").Watch(ctx(t), mongo.Pipeline{}); err == nil {
		ok := cs.TryNext(ctx(t))
		err = cs.Err()
		cs.Close(context.Background())
		if ok || err == nil {
			t.Fatal("database-level change stream was allowed")
		}
	}
	if cs, err := a.Watch(ctx(t), mongo.Pipeline{}); err == nil {
		ok := cs.TryNext(ctx(t))
		err = cs.Err()
		cs.Close(context.Background())
		if ok || err == nil {
			t.Fatal("cluster-level change stream was allowed")
		}
	}
}

func TestChangeStreamsCanBeDisabled(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.ChangeStreams.Disabled = true })
	a := e.tenant(t, "tenant-a")
	cs, err := a.Database("cs").Collection("c").Watch(ctx(t), mongo.Pipeline{})
	if err == nil {
		cs.TryNext(ctx(t))
		err = cs.Err()
		cs.Close(context.Background())
	}
	mustFail(t, err, "change stream when disabled")
}

func openCursors(t *testing.T, e *env) int64 {
	t.Helper()
	var out struct {
		Metrics struct {
			Cursor struct {
				Open struct {
					Total int64 `bson:"total"`
				} `bson:"open"`
			} `bson:"cursor"`
		} `bson:"metrics"`
	}
	must(t, e.direct.Database("admin").RunCommand(ctx(t), bson.D{{Key: "serverStatus", Value: 1}}).Decode(&out))
	return out.Metrics.Cursor.Open.Total
}

func TestChangeStreamFanout(t *testing.T) {
	const tenants, perTenant = 5, 8
	run := func(t *testing.T, disableFanout bool) int64 {
		e := setup(t, func(c *config.Config) { c.ChangeStreams.DisableFanout = disableFanout })
		base := openCursors(t, e)
		type watcher struct {
			cs     *mongo.ChangeStream
			tenant int
		}
		var ws []watcher
		var colls []*mongo.Collection
		for i := 0; i < tenants; i++ {
			cli := e.tenant(t, fmt.Sprintf("t%d", i))
			coll := cli.Database("fan").Collection("c")
			colls = append(colls, coll)
			for j := 0; j < perTenant; j++ {
				cs, err := coll.Watch(ctx(t), mongo.Pipeline{})
				must(t, err)
				t.Cleanup(func() { cs.Close(context.Background()) })
				ws = append(ws, watcher{cs, i})
			}
		}
		open := openCursors(t, e) - base

		// Events that happened before the watches must not be delivered.
		// (Inserted after Watch returned, so every watcher must see them.)
		for i, coll := range colls {
			for k := 0; k < 3; k++ {
				_, err := coll.InsertOne(ctx(t), bson.M{"tenant": i, "k": k})
				must(t, err)
			}
		}
		for _, w := range ws {
			for _, ev := range collect(t, w.cs, 3) {
				if ev.Op != "insert" || ev.Full["tenant"] != int32(w.tenant) || ev.Full["tenantId"] != fmt.Sprintf("t%d", w.tenant) {
					t.Fatalf("watcher of tenant %d got %+v", w.tenant, ev)
				}
			}
		}
		return open
	}
	var fan, direct int64
	t.Run("fanout", func(t *testing.T) { fan = run(t, false) })
	t.Run("private", func(t *testing.T) { direct = run(t, true) })
	t.Logf("open upstream cursors for %d watchers: fan-out=%d, private=%d", tenants*perTenant, fan, direct)
	if fan > 3 {
		t.Fatalf("fan-out used %d upstream cursors for %d watchers", fan, tenants*perTenant)
	}
	if direct < tenants*perTenant {
		t.Fatalf("expected one upstream cursor per watcher without fan-out, got %d", direct)
	}
}

func TestChangeStreamResumeAndPipelines(t *testing.T) {
	e := setup(t, nil)
	a, b := e.tenant(t, "tenant-a"), e.tenant(t, "tenant-b")
	ca, cb := a.Database("cs").Collection("r"), b.Database("cs").Collection("r")

	cs, err := ca.Watch(ctx(t), mongo.Pipeline{})
	must(t, err)
	defer cs.Close(context.Background())
	only, err := ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$match", Value: bson.M{"operationType": "delete"}}}})
	must(t, err)
	defer only.Close(context.Background())
	proj, err := ca.Watch(ctx(t), mongo.Pipeline{{{Key: "$project", Value: bson.M{"operationType": 1, "documentKey": 1}}}})
	must(t, err)
	defer proj.Close(context.Background())

	_, err = ca.InsertOne(ctx(t), bson.M{"_id": 1})
	must(t, err)
	collect(t, cs, 1)
	token := cs.ResumeToken()
	// More events, from both tenants, while nobody is reading `cs`.
	_, err = cb.InsertOne(ctx(t), bson.M{"_id": "b"})
	must(t, err)
	_, err = ca.InsertOne(ctx(t), bson.M{"_id": 2})
	must(t, err)
	_, err = ca.DeleteOne(ctx(t), bson.M{"_id": 1})
	must(t, err)

	// Resuming (private server-side stream) replays only this tenant's events.
	rs, err := ca.Watch(ctx(t), mongo.Pipeline{}, options.ChangeStream().SetResumeAfter(token))
	must(t, err)
	defer rs.Close(context.Background())
	evs := collect(t, rs, 2)
	if evs[0].Op != "insert" || evs[0].Full["_id"] != int32(2) || evs[1].Op != "delete" {
		t.Fatalf("resumed stream: %+v", evs)
	}

	// Fan-out stream with an operationType filter.
	if ev := collect(t, only, 1)[0]; ev.Op != "delete" {
		t.Fatalf("filtered stream: %+v", ev)
	}
	// Custom stages run server-side but stay tenant-scoped.
	pe := collect(t, proj, 3)
	if len(pe) != 3 || pe[0].Op != "insert" || pe[2].Op != "delete" {
		t.Fatalf("projected stream: %+v", pe)
	}
}

func TestChangeStreamLifecycleEvents(t *testing.T) {
	e := setup(t, nil)
	a := e.tenant(t, "tenant-a")
	ca := a.Database("cs").Collection("life")
	_, err := ca.InsertOne(ctx(t), bson.M{"x": 1})
	must(t, err)
	cs, err := ca.Watch(ctx(t), mongo.Pipeline{})
	must(t, err)
	defer cs.Close(context.Background())

	// An administrator drops the physical collection.
	must(t, e.direct.Database("cs").Collection("life").Drop(ctx(t)))
	evs := collect(t, cs, 2)
	if evs[0].Op != "drop" || evs[1].Op != "invalidate" {
		t.Fatalf("lifecycle events: %+v", evs)
	}
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if cs.Next(c) {
		t.Fatal("stream should be closed after invalidate")
	}
}
