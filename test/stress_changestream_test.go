package test

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Fan-out hubs under load: steady writers on several tenants, long-lived
// watchers (collection and database level) that must receive exactly their
// own tenant's inserts, and churning watchers that subscribe, read a little
// and leave - some by dropping the connection without closing the cursor.
//
// Invariants: no tenant ever sees another tenant's event; long-lived watchers
// miss nothing; subscriber counters reconcile to zero afterwards; no goroutine
// or descriptor leaks once the proxy has shut down (including the hubs'
// upstream streams).
func TestStressChangeStreamFanout(t *testing.T) {
	defer stresstest.Watchdog(t, 5*time.Minute)()
	t.Cleanup(stresstest.NoLeak(t, 12))
	e := setup(t, nil)
	tenants := []string{"ta", "tb", "tc"}
	// The proxy only lets a connection use cursors it opened itself (README:
	// "only cursors opened on the same connection are usable"), so anything
	// that holds a cursor gets a single-connection client; writers share a pool.
	mkPool := func(tn string, n uint64) *mongo.Client {
		c, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, tn)).SetMaxPoolSize(n))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	mk := func(tn string) *mongo.Client { return mkPool(tn, 1) }
	clients := map[string]*mongo.Client{} // writers
	for _, tn := range tenants {
		clients[tn] = mkPool(tn, 8)
	}
	defer func() {
		for _, c := range clients {
			c.Disconnect(context.Background())
		}
	}()
	// make sure the collection exists so collection-level streams can open
	for _, tn := range tenants {
		if _, err := clients[tn].Database("cs").Collection("c").InsertOne(ctx(t), bson.M{"o": tn, "w": -1, "seq": 0}); err != nil {
			t.Fatal(err)
		}
	}

	type key struct{ w, seq int }
	const writersPer = 2
	inserted := map[string]*sync.Map{}
	seen := map[string]*sync.Map{} // per long-lived watcher: tenant+"/"+kind
	for _, tn := range tenants {
		inserted[tn] = &sync.Map{}
		seen[tn+"/coll"], seen[tn+"/db"] = &sync.Map{}, &sync.Map{}
	}
	var dups atomic.Int64

	wctx, stopWatch := context.WithCancel(context.Background())
	var watchers sync.WaitGroup
	long := func(tn, kind string) {
		var cs *mongo.ChangeStream
		var err error
		wc := mk(tn)
		if kind == "coll" {
			cs, err = wc.Database("cs").Collection("c").Watch(wctx, mongo.Pipeline{})
		} else {
			cs, err = wc.Database("cs").Watch(wctx, mongo.Pipeline{})
		}
		if err != nil {
			t.Errorf("watch %s/%s: %v", tn, kind, err)
			return
		}
		watchers.Add(1)
		go func() {
			defer watchers.Done()
			defer wc.Disconnect(context.Background())
			defer cs.Close(context.Background())
			for cs.Next(wctx) {
				var ev struct {
					Op   string `bson:"operationType"`
					Full bson.M `bson:"fullDocument"`
					NS   struct {
						Coll string `bson:"coll"`
					} `bson:"ns"`
				}
				if err := cs.Decode(&ev); err != nil {
					t.Errorf("decode: %v", err)
					return
				}
				if ev.Op != "insert" {
					continue
				}
				if ev.Full["o"] != tn || ev.Full["tenantId"] != tn {
					t.Errorf("%s/%s watcher got foreign event %v", tn, kind, ev.Full)
					continue
				}
				w, _ := ev.Full["w"].(int32)
				sq, _ := ev.Full["seq"].(int32)
				if _, dup := seen[tn+"/"+kind].LoadOrStore(key{int(w), int(sq)}, true); dup {
					dups.Add(1)
				}
			}
		}()
	}
	for _, tn := range tenants {
		long(tn, "coll")
		long(tn, "db")
	}

	dur := stresstest.D(4*time.Second, 60*time.Second)
	end := time.Now().Add(dur)
	var wg sync.WaitGroup
	// writers
	for _, tn := range tenants {
		for w := 0; w < writersPer; w++ {
			wg.Add(1)
			go func(tn string, w int) {
				defer wg.Done()
				coll := clients[tn].Database("cs").Collection("c")
				for seq := 1; time.Now().Before(end); seq++ {
					cx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_, err := coll.InsertOne(cx, bson.M{"o": tn, "w": w, "seq": seq})
					cancel()
					if err != nil {
						stresstest.DumpOnce("insert stalled: " + err.Error())
						t.Errorf("insert: %v", err)
						return
					}
					inserted[tn].Store(key{w, seq}, true)
					if seq%10 == 0 {
						time.Sleep(time.Millisecond)
					}
				}
			}(tn, w)
		}
	}
	// churning watchers
	var churned atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(i)))
			for time.Now().Before(end) {
				tn := tenants[rng.Intn(len(tenants))]
				c := mk(tn) // fresh client: its connections can be dropped abruptly
				var cs *mongo.ChangeStream
				var err error
				cx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				switch rng.Intn(3) {
				case 0:
					cs, err = c.Database("cs").Collection("c").Watch(cx, mongo.Pipeline{},
						options.ChangeStream().SetFullDocument(options.UpdateLookup))
				case 1:
					cs, err = c.Database("cs").Watch(cx, mongo.Pipeline{{{Key: "$match", Value: bson.M{"operationType": "insert"}}}})
				default:
					cs, err = c.Database("cs").Collection("c").Watch(cx, mongo.Pipeline{},
						options.ChangeStream().SetFullDocumentBeforeChange(options.WhenAvailable))
				}
				if err != nil {
					cancel()
					c.Disconnect(context.Background())
					continue
				}
				for n := rng.Intn(5); n > 0; n-- {
					rc, rcancel := context.WithTimeout(cx, 150*time.Millisecond)
					ok := cs.Next(rc)
					rcancel()
					if !ok {
						break
					}
					var ev struct {
						Full bson.M `bson:"fullDocument"`
					}
					cs.Decode(&ev)
					if ev.Full != nil && ev.Full["o"] != tn {
						t.Errorf("churn %s saw %v", tn, ev.Full)
					}
				}
				if rng.Intn(2) == 0 {
					cs.Close(context.Background())
				} // else: vanish with the stream open
				cancel()
				c.Disconnect(context.Background())
				churned.Add(1)
			}
		}(i)
	}
	wg.Wait()

	// long-lived watchers must catch up on everything written
	for _, tn := range tenants {
		for _, kind := range []string{"coll", "db"} {
			tn, kind := tn, kind
			eventually(t, 30*time.Second, tn+"/"+kind+" watcher to catch up", func() bool {
				missing := 0
				inserted[tn].Range(func(k, _ any) bool {
					if _, ok := seen[tn+"/"+kind].Load(k); !ok {
						missing++
					}
					return missing == 0
				})
				return missing == 0
			})
		}
	}
	stopWatch()
	watchers.Wait()
	for _, tn := range tenants {
		tn := tn
		eventually(t, 15*time.Second, tn+" change-stream subscribers to reconcile to 0", func() bool {
			st := e.srv.TenantStats(tn)
			return st.ChangeStream == 0
		})
	}
	t.Logf("churned=%d dups=%d", churned.Load(), dups.Load())
}
