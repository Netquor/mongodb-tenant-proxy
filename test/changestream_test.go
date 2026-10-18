package test

import (
	"context"
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
	e := setup(t, func(c *config.Config) {
		c.ChangeStreams = config.ChangeStreams{Enabled: true, AutoEnableImages: true}
	})
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

func TestChangeStreamsDisabledByDefault(t *testing.T) {
	e := setup(t, nil)
	a := e.tenant(t, "tenant-a")
	cs, err := a.Database("cs").Collection("c").Watch(ctx(t), mongo.Pipeline{})
	if err == nil {
		cs.TryNext(ctx(t))
		err = cs.Err()
		cs.Close(context.Background())
	}
	mustFail(t, err, "change stream when disabled")
}
