package test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Graceful shutdown while commands are in flight: slow reads, open cursors,
// long-polling change streams, transactions and writes. Serve must return
// promptly (no deadlock between connection teardown, pools and hubs), and
// afterwards neither side may hold anything: no proxy goroutines, no
// descriptors, and mongod is back to its own connections.
func TestStressShutdownInFlight(t *testing.T) {
	for _, mode := range []string{"pooled", "dedicated"} {
		t.Run(mode, func(t *testing.T) {
			defer stresstest.Watchdog(t, 5*time.Minute)()
			t.Cleanup(stresstest.NoLeak(t, 10))
			up := startMongod(t, false)
			direct := connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", up))
			defer direct.Disconnect(context.Background())
			base, _ := upstreamGauges(t, direct)

			for round := 0; round < stresstest.N(3, 15); round++ {
				_, addr, stop := startProxyAt(t, up, func(c *config.Config) { c.Upstream.Pool.Mode = mode })
				tenants := []string{"sa", "sb"}
				var inflight, errs atomic.Int64
				var wg sync.WaitGroup
				for _, tn := range tenants {
					for w := 0; w < 6; w++ {
						wg.Add(1)
						go func(tn string, w int) {
							defer wg.Done()
							cl, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?appName=%s", addr, tn)).
								SetMaxPoolSize(1).SetServerSelectionTimeout(5 * time.Second))
							if err != nil {
								return
							}
							defer cl.Disconnect(context.Background())
							coll := cl.Database("sd").Collection("c")
							cx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
							defer cancel()
							coll.InsertOne(cx, bson.M{"o": tn, "w": w})
							switch w % 3 {
							case 0: // slow command running when shutdown begins
								inflight.Add(1)
								// $where runs once per document: keep the collection at one doc
								// per tenant so this really takes ~400ms
								slow := cl.Database("sd").Collection("slow")
								slow.InsertOne(cx, bson.M{"o": tn, "w": w})
								_, err := slow.Find(cx, bson.M{"w": w, "$where": "sleep(400) || true"})
								if err != nil {
									errs.Add(1)
								}
							case 1: // long-polling change stream
								cs, err := coll.Watch(cx, mongo.Pipeline{})
								if err != nil {
									return
								}
								inflight.Add(1)
								cs.Next(cx)
							default: // cursor + writes
								cur, err := coll.Find(cx, bson.M{}, options.Find().SetBatchSize(1))
								if err != nil {
									return
								}
								inflight.Add(1)
								for cur.Next(cx) {
									coll.InsertOne(cx, bson.M{"o": tn, "again": true})
								}
							}
						}(tn, w)
					}
				}
				eventually(t, 20*time.Second, "workers to be in flight", func() bool { return inflight.Load() >= int64(len(tenants)*6)-2 })
				time.Sleep(100 * time.Millisecond)
				started := time.Now()
				stop(15 * time.Second)
				t.Logf("%s round %d: shutdown took %s", mode, round, time.Since(started).Round(time.Millisecond))
				wg.Wait()
			}
			eventually(t, 20*time.Second, "mongod to drop the proxy's connections", func() bool {
				n, cur := upstreamGauges(t, direct)
				t.Logf("mongod: connections=%d (baseline %d) open cursors=%d", n, base, cur)
				return n <= base+2 && cur == 0
			})
		})
	}
}
