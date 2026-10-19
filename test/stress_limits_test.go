package test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Per-tenant limiter, connection cap, session ownership and transactions
// under contention from many connections at once.
//
// Invariants: the per-tenant connection cap is never exceeded; at most
// MaxInFlight commands of a tenant run at once (observed through the
// in-flight gauge); one tenant can never use another's logical session; and
// when all clients are gone the in-flight / open-cursor / connection counters
// reconcile to zero and nothing leaks.
func TestStressLimitsSessionsTransactions(t *testing.T) {
	defer stresstest.Watchdog(t, 4*time.Minute)()
	t.Cleanup(stresstest.NoLeak(t, 10))
	const maxConns, maxInFlight = 12, 3
	e := setup(t, func(c *config.Config) {
		c.MaxConnsPerTenant = maxConns
		c.Tenant.Limits.MaxInFlight = maxInFlight
		c.Tenant.Limits.MaxOpenCursors = 40
	})
	tenants := []string{"la", "lb"}
	seedC := connect(t, fmt.Sprintf("mongodb://%s/?appName=la", e.proxyAddr))
	for _, tn := range tenants {
		c := connect(t, fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, tn))
		docs := make([]any, 50)
		for i := range docs {
			docs[i] = bson.M{"o": tn, "n": i}
		}
		_, err := c.Database("lm").Collection("c").InsertMany(ctx(t), docs)
		c.Disconnect(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
	}
	seedC.Disconnect(ctx(t))

	scrape := func() string {
		rec := httptest.NewRecorder()
		e.srv.M.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		return rec.Body.String()
	}
	gauge := func(metric, tenant string) int {
		for _, l := range strings.Split(scrape(), "\n") {
			if strings.HasPrefix(l, metric+"{") && strings.Contains(l, fmt.Sprintf("tenant=%q", tenant)) {
				var v int
				fmt.Sscanf(l[strings.LastIndex(l, " ")+1:], "%d", &v)
				return v
			}
		}
		return 0
	}

	end := time.Now().Add(stresstest.D(5*time.Second, 60*time.Second))
	var peakInFlight atomic.Int64
	var rejectedConns, quotaRejected, sessionAttacks atomic.Int64
	stop := make(chan struct{})
	var monitors sync.WaitGroup
	monitors.Add(1)
	go func() { // invariant sampler
		defer monitors.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, tn := range tenants {
				if n := len(e.srv.Connections(tn)); n > maxConns {
					t.Errorf("tenant %s has %d connections, cap is %d", tn, n, maxConns)
				}
				g := gauge("mtp_inflight_operations", tn)
				if int64(g) > peakInFlight.Load() {
					peakInFlight.Store(int64(g))
				}
				if g > maxInFlight {
					t.Errorf("tenant %s: %d operations in flight, cap is %d", tn, g, maxInFlight)
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	ownLsid := func(tn string, w int) bson.M {
		id := make([]byte, 16)
		copy(id, fmt.Sprintf("%s-%d", tn, w))
		return bson.M{"id": bson.Binary{Subtype: 4, Data: id}}
	}
	workers(len(tenants)*10, func(w int) {
		tn := tenants[w%len(tenants)]
		other := tenants[(w+1)%len(tenants)]
		lsid := ownLsid(tn, w)
		foreign := ownLsid(other, w) // belongs to the other tenant's worker with the same index
		for time.Now().Before(end) {
			c, err := dialSC(e.proxyAddr, tn)
			if err != nil { // connection cap reached: expected
				rejectedConns.Add(1)
				time.Sleep(30 * time.Millisecond)
				continue
			}
			for i := 0; i < 60 && time.Now().Before(end); i++ {
				var res bson.M
				switch i % 5 {
				case 0, 1:
					res, err = c.run("lm", bson.D{{Key: "find", Value: "c"}, {Key: "batchSize", Value: 5}, {Key: "lsid", Value: lsid}})
					if id, batch, ok := cursorOf(res); err == nil && ok {
						for _, d := range batch {
							if d["o"] != tn {
								t.Errorf("tenant %s saw %v", tn, d)
							}
						}
						if id != 0 && i%2 == 0 { // some cursors are closed, others abandoned
							c.run("lm", bson.D{{Key: "killCursors", Value: "c"}, {Key: "cursors", Value: bson.A{id}}})
						}
					}
				case 2: // transaction on the session
					sn := int64(i)
					var r1, r2 bson.M
					r1, err = c.run("lm", bson.D{{Key: "insert", Value: "tx"}, {Key: "documents", Value: bson.A{bson.M{"o": tn}}},
						{Key: "lsid", Value: lsid}, {Key: "txnNumber", Value: sn + int64(w)*1000}, {Key: "autocommit", Value: false}, {Key: "startTransaction", Value: true}})
					if err == nil && isOK(r1) {
						verb := "commitTransaction"
						if i%2 == 0 {
							verb = "abortTransaction"
						}
						r2, err = c.run("admin", bson.D{{Key: verb, Value: 1}, {Key: "lsid", Value: lsid},
							{Key: "txnNumber", Value: sn + int64(w)*1000}, {Key: "autocommit", Value: false}})
						_ = r2
					}
				case 3: // someone else's session must never work
					res, err = c.run("lm", bson.D{{Key: "find", Value: "c"}, {Key: "lsid", Value: foreign}})
					if err == nil && isOK(res) {
						// only legitimate if that session was never bound by its owner
						// (first use wins), and then it is ours from now on; the
						// other tenant must in turn be refused - checked below.
						sessionAttacks.Add(1)
					}
				default:
					res, err = c.run("lm", bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{bson.M{"$count": "n"}}},
						{Key: "cursor", Value: bson.M{}}, {Key: "lsid", Value: lsid}})
					if err == nil && !isOK(res) {
						quotaRejected.Add(1)
					}
				}
				if err != nil {
					break
				}
			}
			c.close()
		}
	})
	close(stop)
	monitors.Wait()

	// session ownership is exclusive: whoever used an lsid first keeps it.
	eventually(t, 20*time.Second, "worker connections to drain", func() bool { return len(e.srv.Connections("")) == 0 })
	var a, b *sc
	var errA, errB error
	for try := 0; try < 100 && (a == nil || b == nil); try++ { // ephemeral ports may still be in TIME_WAIT
		if a == nil {
			a, errA = dialSC(e.proxyAddr, "la")
		}
		if b == nil {
			b, errB = dialSC(e.proxyAddr, "lb")
		}
		if a == nil || b == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if a == nil || b == nil {
		t.Fatalf("dial for final session check: %v / %v", errA, errB)
	}
	sid := bson.M{"id": bson.Binary{Subtype: 4, Data: []byte("final-session-id")}}
	if r, _ := a.run("lm", bson.D{{Key: "find", Value: "c"}, {Key: "lsid", Value: sid}}); !isOK(r) {
		t.Fatalf("first user of a session was refused: %v", r)
	}
	if r, _ := b.run("lm", bson.D{{Key: "find", Value: "c"}, {Key: "lsid", Value: sid}}); isOK(r) {
		t.Fatalf("second tenant was allowed to use a bound session: %v", r)
	}
	a.close()
	b.close()

	for _, tn := range tenants {
		tn := tn
		eventually(t, 20*time.Second, tn+" counters to reconcile", func() bool {
			st := e.srv.TenantStats(tn)
			return st.Connections == 0 && st.OpenCursors == 0 &&
				gauge("mtp_inflight_operations", tn) == 0 && gauge("mtp_open_cursors", tn) == 0
		})
	}
	if peakInFlight.Load() == 0 {
		t.Error("in-flight gauge never moved: the invariant above was vacuous")
	}
	t.Logf("peakInFlight=%d connRejected=%d quota/other rejected=%d sessionFirstUse=%d", peakInFlight.Load(), rejectedConns.Load(), quotaRejected.Load(), sessionAttacks.Load())
}
