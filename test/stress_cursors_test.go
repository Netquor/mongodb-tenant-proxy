package test

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Cursor open / getMore / killCursors / abrupt-disconnect churn from several
// tenants at once, in both pool modes.
//
// Invariants: a tenant only ever sees its own documents; another tenant's
// cursor id is unusable; when everything has disconnected the proxy's
// connection, cursor and subscriber counters are zero, mongod has no cursor
// left open (the proxy killed the abandoned ones), and no goroutines or file
// descriptors leaked on either side.
func TestStressCursorChurn(t *testing.T) {
	for _, mode := range []string{"pooled", "dedicated"} {
		t.Run(mode, func(t *testing.T) {
			defer stresstest.Watchdog(t, 4*time.Minute)()
			t.Cleanup(stresstest.NoLeak(t, 10))
			e := setup(t, func(c *config.Config) {
				c.Upstream.Pool.Mode = mode
				c.Tenant.Limits.MaxOpenCursors = 50
			})
			tenants := []string{"ta", "tb", "tc"}
			for _, tn := range tenants {
				docs := make([]any, 120)
				for i := range docs {
					docs[i] = bson.M{"o": tn, "n": i}
				}
				cl := connect(t, fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, tn))
				_, err := cl.Database("cc").Collection("c").InsertMany(ctx(t), docs)
				cl.Disconnect(ctx(t))
				if err != nil {
					t.Fatal(err)
				}
			}
			_, cur0 := upstreamGauges(t, e.direct)

			var foreign sync.Map // cursor id -> owning tenant
			dur := stresstest.D(4*time.Second, 60*time.Second)
			end := time.Now().Add(dur)
			var ops, abrupt, crossTried atomic.Int64
			workers(len(tenants)*4, func(w int) {
				me := tenants[w%len(tenants)]
				rng := rand.New(rand.NewSource(int64(w)))
				for time.Now().Before(end) {
					c, err := dialSC(e.proxyAddr, me)
					if err != nil {
						// loopback ephemeral ports can run out under heavy churn (TIME_WAIT)
						time.Sleep(50 * time.Millisecond)
						continue
					}
					var mine []int64
					for i, n := 0, 4+rng.Intn(12); i < n; i++ {
						var res bson.M
						switch rng.Intn(4) {
						case 0, 1:
							res, err = c.run("cc", bson.D{{Key: "find", Value: "c"}, {Key: "batchSize", Value: 7}})
						case 2:
							res, err = c.run("cc", bson.D{{Key: "aggregate", Value: "c"},
								{Key: "pipeline", Value: bson.A{bson.M{"$sort": bson.M{"n": 1}}}},
								{Key: "cursor", Value: bson.M{"batchSize": 5}}})
						case 3:
							_, err = c.run("cc", bson.D{{Key: "insert", Value: "w"},
								{Key: "documents", Value: bson.A{bson.M{"o": me}}}})
						}
						if err != nil {
							t.Errorf("%s: %v", me, err)
							break
						}
						ops.Add(1)
						id, batch, ok := cursorOf(res)
						for _, d := range batch {
							if d["o"] != me {
								t.Errorf("tenant %s saw %v", me, d)
							}
						}
						if !ok || id == 0 {
							continue
						}
						mine = append(mine, id)
						foreign.Store(id, me)
						for g := rng.Intn(4); g > 0; g-- {
							gm, err := c.run("cc", bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: "c"}, {Key: "batchSize", Value: 9}})
							if err != nil {
								t.Errorf("%s getMore: %v", me, err)
								break
							}
							_, b, _ := cursorOf(gm)
							for _, d := range b {
								if d["o"] != me {
									t.Errorf("tenant %s saw %v via getMore", me, d)
								}
							}
							if nid, _, _ := cursorOf(gm); nid == 0 {
								mine = mine[:len(mine)-1]
								break
							}
						}
					}
					// someone else's cursor id must be unusable on this connection
					foreign.Range(func(k, v any) bool {
						if v.(string) != me {
							crossTried.Add(1)
							r, err := c.run("cc", bson.D{{Key: "getMore", Value: k.(int64)}, {Key: "collection", Value: "c"}})
							if err == nil && isOK(r) {
								t.Errorf("tenant %s used %s's cursor %d", me, v, k)
							}
							return false
						}
						return true
					})
					switch {
					case len(mine) > 0 && rng.Intn(3) == 0:
						c.run("cc", bson.D{{Key: "killCursors", Value: "c"}, {Key: "cursors", Value: toArr(mine)}})
						c.close()
					default: // vanish with cursors still open
						abrupt.Add(1)
						c.close()
					}
				}
			})

			eventually(t, 20*time.Second, "all client connections to be gone", func() bool { return len(e.srv.Connections("")) == 0 })
			for _, tn := range tenants {
				tn := tn
				eventually(t, 10*time.Second, tn+" open-cursor counter to reconcile to 0", func() bool {
					return e.srv.TenantStats(tn).OpenCursors == 0 && e.srv.TenantStats(tn).Connections == 0
				})
			}
			eventually(t, 15*time.Second, "mongod to have no abandoned cursors", func() bool {
				_, cur := upstreamGauges(t, e.direct)
				return cur <= cur0
			})
			t.Logf("ops=%d abrupt=%d crossTried=%d", ops.Load(), abrupt.Load(), crossTried.Load())
		})
	}
}

func toArr(ids []int64) bson.A {
	a := make(bson.A, len(ids))
	for i, id := range ids {
		a[i] = id
	}
	return a
}

var _ = fmt.Sprint
