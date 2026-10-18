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
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Pool checkout / return / pinning under repeated primary step-downs, in the
// 3-node replica-set harness: retryable inserts, multi-document transactions
// (connection pinned from start to commit), tailable cursors and change
// streams (connection pinned for the cursor's life), and secondary reads, for
// several tenants at once.
//
// Invariants: no recovered panic, no tenant ever reads another tenant's
// documents, every acknowledged write is durable, and when the clients are
// gone every pooled upstream connection is back in the pool (InUse == 0) and
// nothing of the proxy's keeps running after shutdown.
func TestStressFailover(t *testing.T) {
	defer stresstest.Watchdog(t, 8*time.Minute)()
	t.Cleanup(stresstest.NoLeak(t, 20))
	e := setupRS(t, nil)
	tenants := []string{"fa", "fb"}
	const db = "fo"

	mk := func(tn string, pool uint64) *mongo.Client {
		o := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, tn)).
			SetServerSelectionTimeout(30 * time.Second).SetMaxPoolSize(pool).
			SetWriteConcern(writeconcern.Majority()).SetReadConcern(readconcern.Majority())
		c, err := mongo.Connect(o)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var closers []func()
	var closeMu sync.Mutex
	own := func(c *mongo.Client) *mongo.Client {
		closeMu.Lock()
		closers = append(closers, func() { c.Disconnect(context.Background()) })
		closeMu.Unlock()
		return c
	}
	// setup: one shared capped collection (the proxy refuses `capped` itself
	// because collections are shared between tenants, so it is made directly)
	if err := e.direct.Database(db).CreateCollection(ctx(t), "capped", options.CreateCollection().SetCapped(true).SetSizeInBytes(1<<20)); err != nil {
		t.Fatalf("capped setup: %v", err)
	}
	for _, tn := range tenants {
		c := mk(tn, 1)
		_, err := c.Database(db).Collection("capped").InsertOne(ctx(t), bson.M{"o": tn, "seed": true})
		c.Disconnect(context.Background())
		if err != nil {
			t.Fatalf("capped seed: %v", err)
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	acked := map[string]*sync.Map{}
	for _, tn := range tenants {
		acked[tn] = &sync.Map{}
	}
	var okOps, failOps atomic.Int64
	var seqs atomic.Int64
	check := func(tn string, d bson.M, where string) {
		if d["o"] != tn {
			t.Errorf("tenant %s read %v via %s", tn, d, where)
		}
	}
	tolerate := func(err error) bool { // failover noise is expected, panics are not
		if err == nil {
			okOps.Add(1)
			return true
		}
		failOps.Add(1)
		return false
	}

	for _, tn := range tenants {
		tn := tn
		pool := own(mk(tn, 20))
		coll := pool.Database(db).Collection("w")
		for w := 0; w < 3; w++ { // retryable inserts
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					n := seqs.Add(1)
					cx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					_, err := coll.InsertOne(cx, bson.M{"o": tn, "n": n})
					cancel()
					if tolerate(err) {
						acked[tn].Store(n, true)
					}
				}
			}()
		}
		for w := 0; w < 2; w++ { // transactions
			wg.Add(1)
			go func() {
				defer wg.Done()
				sess, err := pool.StartSession()
				if err != nil {
					t.Error(err)
					return
				}
				defer sess.EndSession(context.Background())
				for {
					select {
					case <-stop:
						return
					default:
					}
					n := seqs.Add(1)
					cx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					_, err := sess.WithTransaction(cx, func(sc context.Context) (any, error) {
						if _, err := coll.InsertOne(sc, bson.M{"o": tn, "n": n, "tx": 1}); err != nil {
							return nil, err
						}
						_, err := coll.InsertOne(sc, bson.M{"o": tn, "n": n, "tx": 2})
						return nil, err
					})
					cancel()
					if tolerate(err) {
						acked[tn].Store(-n, true) // both halves must exist
					}
				}
			}()
		}
		wg.Add(1)
		go func() { // secondary reads
			defer wg.Done()
			rc := own(mk(tn, 4))
			sec := rc.Database(db).Collection("w", options.Collection().SetReadPreference(readpref.SecondaryPreferred()))
			for {
				select {
				case <-stop:
					return
				default:
				}
				cx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				cur, err := sec.Find(cx, bson.M{}, options.Find().SetBatchSize(50).SetLimit(200))
				if tolerate(err) {
					var docs []bson.M
					if err := cur.All(cx, &docs); err == nil {
						for _, d := range docs {
							check(tn, d, "secondary read")
						}
					}
				}
				cancel()
			}
		}()
		wg.Add(1)
		go func() { // tailable cursor (pinned connection)
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tc := mk(tn, 1)
				cx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				cur, err := tc.Database(db).Collection("capped").Find(cx, bson.M{},
					options.Find().SetCursorType(options.TailableAwait).SetMaxAwaitTime(200*time.Millisecond))
				if tolerate(err) {
					for i := 0; i < 5 && cur.Next(cx); i++ {
						var d bson.M
						cur.Decode(&d)
						check(tn, d, "tailable cursor")
					}
					cur.Close(context.Background())
				}
				cancel()
				tc.Disconnect(context.Background())
			}
		}()
		wg.Add(1)
		go func() { // change stream (fan-out) + capped writer feeding the tail
			defer wg.Done()
			tc := mk(tn, 1)
			defer tc.Disconnect(context.Background())
			wc := own(mk(tn, 2))
			for {
				select {
				case <-stop:
					return
				default:
				}
				cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				wc.Database(db).Collection("capped").InsertOne(cx, bson.M{"o": tn})
				cs, err := tc.Database(db).Collection("w").Watch(cx, mongo.Pipeline{})
				if tolerate(err) {
					for i := 0; i < 3; i++ {
						rc, rcancel := context.WithTimeout(cx, 300*time.Millisecond)
						if !cs.Next(rc) {
							rcancel()
							break
						}
						rcancel()
						var ev struct {
							Full bson.M `bson:"fullDocument"`
						}
						cs.Decode(&ev)
						check(tn, ev.Full, "change stream")
					}
					cs.Close(context.Background())
				}
				cancel()
			}
		}()
	}

	rounds := stresstest.N(2, 12)
	for r := 0; r < rounds; r++ {
		time.Sleep(2 * time.Second)
		before := e.primaryIndex(t)
		if before < 0 {
			continue
		}
		pc := e.member(t, before)
		err := pc.Database("admin").RunCommand(context.Background(),
			bson.D{{Key: "replSetStepDown", Value: 10}, {Key: "force", Value: true}}).Err()
		if err != nil && !mongo.IsNetworkError(err) {
			t.Errorf("stepDown: %v", err)
		}
		eventually(t, 40*time.Second, "a new primary", func() bool { n := e.primaryIndex(t); return n >= 0 && n != before })
	}
	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()

	// durability of acknowledged writes
	verify := e.direct.Database(db).Collection("w", options.Collection().SetReadConcern(readconcern.Majority()))
	for _, tn := range tenants {
		present := map[int64]int{}
		cx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cur, err := verify.Find(cx, bson.M{"o": tn})
		if err != nil {
			t.Fatal(err)
		}
		var docs []bson.M
		cur.All(cx, &docs)
		cancel()
		for _, d := range docs {
			n, _ := d["n"].(int64)
			present[n]++
		}
		missing := 0
		acked[tn].Range(func(k, _ any) bool {
			n := k.(int64)
			want := 1
			if n < 0 {
				n, want = -n, 2
			}
			if present[n] < want {
				missing++
			}
			return true
		})
		if missing > 0 {
			t.Errorf("tenant %s: %d acknowledged writes/transactions missing after failover", tn, missing)
		}
	}

	for _, c := range closers {
		c()
	}
	eventually(t, 30*time.Second, "client connections to close", func() bool { return len(e.srv.Connections("")) == 0 })
	eventually(t, 30*time.Second, "pooled upstream connections to be returned", func() bool {
		for _, m := range e.srv.UpstreamStats().Members {
			if m.InUse != 0 {
				return false
			}
		}
		return true
	})
	t.Logf("ok=%d failed=%d rounds=%d", okOps.Load(), failOps.Load(), rounds)
	e.stop()
}
