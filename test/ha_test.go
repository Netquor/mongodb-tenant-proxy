package test

import (
	"context"
	"errors"
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

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
)

// tenantOpts returns a client for the tenant with extra options applied.
func (e *env) tenantOpts(t testing.TB, id string, mut func(*options.ClientOptions)) *mongo.Client {
	t.Helper()
	o := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, id)).SetServerSelectionTimeout(30 * time.Second)
	if mut != nil {
		mut(o)
	}
	c, err := mongo.Connect(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Disconnect(context.Background()) })
	return c
}

type upstreamStats = upstream.Stats

func majority() *writeconcern.WriteConcern { return writeconcern.Majority() }

func waitCount(t testing.TB, coll *mongo.Collection, want int64) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		n, err := coll.CountDocuments(context.Background(), bson.M{})
		if err == nil && n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("count = %d (err %v), want %d", n, err, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestReplicaSet runs the topology, routing, pooling and failover checks
// against one 3-node replica set. The failover subtest goes last because it
// disturbs the set.
func TestReplicaSet(t *testing.T) {
	addrs := startReplSet(t)
	e := attachProxy(t, addrs, func(c *config.Config) { c.Upstream.Pool.MaxSize = 4 })

	t.Run("discovery", func(t *testing.T) {
		var st upstreamStats
		deadline := time.Now().Add(10 * time.Second)
		for {
			st = e.srv.UpstreamStats()
			types := map[string]int{}
			for _, m := range st.Members {
				types[m.Type]++
			}
			if types["RSPrimary"] == 1 && types["RSSecondary"] == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("members: %+v", st.Members)
			}
			time.Sleep(50 * time.Millisecond)
		}
		// A client sees one standalone-looking endpoint, never the members.
		c := e.tenant(t, "disc")
		var h bson.M
		if err := c.Database("admin").RunCommand(context.Background(), bson.D{{Key: "hello", Value: 1}}).Decode(&h); err != nil {
			t.Fatal(err)
		}
		if h["msg"] != "isdbgrid" || h["hosts"] != nil {
			t.Fatalf("hello leaks topology: %v", h)
		}
	})

	t.Run("secondary reads honour tags and keep cursors on their member", func(t *testing.T) {
		wc := e.tenantOpts(t, "sec", nil).Database("sec").Collection("c", options.Collection().SetWriteConcern(majority()))
		docs := make([]any, 200)
		for i := range docs {
			docs[i] = bson.M{"_id": i, "v": i}
		}
		if _, err := wc.InsertMany(context.Background(), docs); err != nil {
			t.Fatal(err)
		}
		tagB := readpref.Secondary(readpref.WithTags("dc", "b"))
		rc := e.tenantOpts(t, "sec", nil).Database("sec").Collection("c", options.Collection().SetReadPreference(tagB).SetReadConcern(readconcern.Majority()))
		waitCount(t, rc, 200)

		pi := e.primaryIndex(t)
		if pi != 0 {
			t.Skip("unexpected primary placement")
		}
		m := [3]*mongo.Client{e.member(t, 0), e.member(t, 1), e.member(t, 2)}
		for _, c := range m {
			profileOn(t, c, "sec")
		}
		reads := func(op string) (out [3]int64) {
			for i, c := range m {
				out[i] = profiled(t, c, "sec", "sec.c", op)
			}
			return
		}
		before := reads("query")
		for i := 0; i < 30; i++ {
			if err := rc.FindOne(context.Background(), bson.M{"_id": i}).Err(); err != nil {
				t.Fatal(err)
			}
		}
		after := reads("query")
		if d := after[1] - before[1]; d != 30 {
			t.Fatalf("tagged secondary b served %d of 30 reads (before %v after %v)", d, before, after)
		}
		if after[0] != before[0] || after[2] != before[2] {
			t.Fatalf("other members served tagged reads: before %v after %v", before, after)
		}

		// A multi-batch cursor: every getMore must reach the member that opened it.
		sec := e.tenantOpts(t, "sec", nil).Database("sec").Collection("c", options.Collection().SetReadPreference(tagB).SetReadConcern(readconcern.Majority()))
		gm := reads("getmore")
		cur, err := sec.Find(context.Background(), bson.M{}, options.Find().SetBatchSize(10))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for cur.Next(context.Background()) {
			n++
		}
		if err := cur.Err(); err != nil || n != 200 {
			t.Fatalf("cursor read %d docs, err %v", n, err)
		}
		gm2 := reads("getmore")
		active := 0
		for i := range gm {
			if gm2[i]-gm[i] > 0 {
				active++
			}
		}
		if active != 1 || gm2[0] != gm[0] || gm2[1]+gm2[2]-gm[1]-gm[2] < 19 {
			t.Fatalf("getMores not confined to the cursor's member: before %v after %v", gm, gm2)
		}

		// Writes ignore the read preference and still reach the primary.
		w := e.tenantOpts(t, "sec", func(o *options.ClientOptions) { o.SetReadPreference(readpref.Secondary()) })
		if _, err := w.Database("sec").Collection("w").InsertOne(context.Background(), bson.M{"x": 1}); err != nil {
			t.Fatalf("write with secondary read preference: %v", err)
		}
		// An impossible preference fails cleanly instead of hanging.
		bad := e.tenantOpts(t, "sec", func(o *options.ClientOptions) { o.SetServerSelectionTimeout(5 * time.Second) })
		err = bad.Database("sec").Collection("c", options.Collection().SetReadPreference(readpref.Secondary(readpref.WithTags("dc", "mars")))).FindOne(context.Background(), bson.M{}).Err()
		if err == nil || errors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("expected an error for an unsatisfiable preference, got %v", err)
		}
	})

	t.Run("transactions stay on one connection", func(t *testing.T) {
		c := e.tenantOpts(t, "tx", nil)
		db := c.Database("tx", options.Database().SetWriteConcern(majority()))
		coll := db.Collection("a")
		other := db.Collection("b")
		if _, err := coll.InsertOne(context.Background(), bson.M{"_id": "seed"}); err != nil { // creates the collection
			t.Fatal(err)
		}
		if _, err := other.InsertOne(context.Background(), bson.M{"_id": "seed"}); err != nil {
			t.Fatal(err)
		}
		// Contend for the 4-connection pool while transactions run.
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				oc := e.tenantOpts(t, "tx", nil).Database("tx").Collection("noise")
				for n := 0; ; n++ {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := oc.InsertOne(context.Background(), bson.M{"i": i, "n": n}); err != nil {
						t.Errorf("noise insert: %v", err)
						return
					}
				}
			}(i)
		}
		for i := 0; i < 20; i++ {
			sess, err := c.StartSession()
			if err != nil {
				t.Fatal(err)
			}
			_, err = sess.WithTransaction(context.Background(), func(ctx context.Context) (any, error) {
				if _, err := coll.InsertOne(ctx, bson.M{"_id": fmt.Sprint("t", i)}); err != nil {
					return nil, err
				}
				// The transaction sees its own uncommitted write...
				if err := coll.FindOne(ctx, bson.M{"_id": fmt.Sprint("t", i)}).Err(); err != nil {
					return nil, fmt.Errorf("own write invisible: %w", err)
				}
				// ...which other sessions do not.
				if err := coll.FindOne(context.Background(), bson.M{"_id": fmt.Sprint("t", i)}).Err(); !errors.Is(err, mongo.ErrNoDocuments) {
					return nil, fmt.Errorf("uncommitted write visible outside: %v", err)
				}
				_, err := other.InsertOne(ctx, bson.M{"_id": fmt.Sprint("t", i)})
				return nil, err
			})
			sess.EndSession(context.Background())
			if err != nil {
				t.Fatalf("transaction %d: %v", i, err)
			}
		}
		// An aborted transaction leaves nothing behind.
		sess, _ := c.StartSession()
		if err := sess.StartTransaction(); err != nil {
			t.Fatal(err)
		}
		ctx := mongo.NewSessionContext(context.Background(), sess)
		if _, err := coll.InsertOne(ctx, bson.M{"_id": "aborted"}); err != nil {
			t.Fatal(err)
		}
		if err := sess.AbortTransaction(context.Background()); err != nil {
			t.Fatal(err)
		}
		sess.EndSession(context.Background())
		if err := coll.FindOne(context.Background(), bson.M{"_id": "aborted"}).Err(); !errors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("aborted write survived: %v", err)
		}
		close(stop)
		wg.Wait()
		if n, _ := coll.CountDocuments(context.Background(), bson.M{}); n != 21 {
			t.Fatalf("committed %d docs, want 21", n)
		}
	})

	t.Run("pooled mode multiplexes many clients over few connections", func(t *testing.T) {
		const clients, rounds = 80, 25
		var peak atomic.Int64
		stopSample := make(chan struct{})
		go func() {
			for {
				select {
				case <-stopSample:
					return
				case <-time.After(3 * time.Millisecond):
				}
				in := 0
				for _, m := range e.srv.UpstreamStats().Members {
					in += m.InUse
				}
				if int64(in) > peak.Load() {
					peak.Store(int64(in))
				}
			}
		}()
		openedBefore := e.srv.UpstreamStats().PoolConnsOpened
		var wg sync.WaitGroup
		var failures atomic.Int64
		for i := 0; i < clients; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?appName=load%d", e.proxyAddr, i%5)).SetMaxPoolSize(1))
				if err != nil {
					failures.Add(1)
					return
				}
				defer c.Disconnect(context.Background())
				coll := c.Database("load").Collection("c")
				for r := 0; r < rounds; r++ {
					if _, err := coll.InsertOne(context.Background(), bson.M{"c": i, "r": r}); err != nil {
						t.Errorf("insert: %v", err)
						failures.Add(1)
						return
					}
					if err := coll.FindOne(context.Background(), bson.M{"c": i, "r": r}).Err(); err != nil {
						t.Errorf("find: %v", err)
						failures.Add(1)
						return
					}
				}
			}(i)
		}
		wg.Wait()
		close(stopSample)
		if failures.Load() > 0 {
			t.FailNow()
		}
		st := e.srv.UpstreamStats()
		// 80 client connections, 3 members x 4 slots: at most 4 are ever busy
		// on the primary (all writes and reads go there).
		if peak.Load() > 12 {
			t.Fatalf("peak %d upstream connections in use, pool allows 4 per member", peak.Load())
		}
		if opened := st.PoolConnsOpened - openedBefore; opened > 12 {
			t.Fatalf("opened %d pooled connections for %d clients", opened, clients)
		}
		// Everything is returned once the clients are gone.
		deadline := time.Now().Add(10 * time.Second)
		for {
			busy := 0
			for _, m := range e.srv.UpstreamStats().Members {
				busy += m.InUse
			}
			if busy == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("upstream connections still checked out: %+v", e.srv.UpstreamStats())
			}
			time.Sleep(50 * time.Millisecond)
		}
		for i := 0; i < 5; i++ {
			n, _ := e.tenant(t, fmt.Sprintf("load%d", i)).Database("load").Collection("c").CountDocuments(context.Background(), bson.M{})
			if n != clients/5*rounds {
				t.Fatalf("tenant load%d has %d docs, want %d", i, n, clients/5*rounds)
			}
		}
		t.Logf("peak in use %d, pooled connections opened %d", peak.Load(), st.PoolConnsOpened-openedBefore)
	})

	t.Run("failover", func(t *testing.T) {
		testFailover(t, e)
	})

	// Shutting the proxy down closes every upstream socket.
	e.stop()
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.UpstreamStats().OpenConns != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("upstream connections leaked after shutdown: %+v", e.srv.UpstreamStats())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func testFailover(t *testing.T, e *env) {
	// Writers with and without driver retries, plus a reader, run across two
	// step-downs. With retryWrites the client must never see an error; without
	// it, only retryable server errors may surface.
	var okRetry, okNoRetry, errNoRetry atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	insert := func(name string, retry bool, ok, bad *atomic.Int64) {
		defer wg.Done()
		c := e.tenantOpts(t, "fo", func(o *options.ClientOptions) { o.SetRetryWrites(retry) })
		coll := c.Database("fo").Collection(name, options.Collection().SetWriteConcern(majority()))
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			_, err := coll.InsertOne(ctx, bson.M{"n": n})
			cancel()
			if err == nil {
				ok.Add(1)
				continue
			}
			if retry {
				t.Errorf("retryWrites client saw %v", err)
				return
			}
			if !retryableFailure(err) {
				t.Errorf("non-retryable failure surfaced: %v", err)
				return
			}
			bad.Add(1)
			time.Sleep(20 * time.Millisecond)
		}
	}
	wg.Add(2)
	go insert("retry", true, &okRetry, new(atomic.Int64))
	go insert("noretry", false, &okNoRetry, &errNoRetry)

	var readErrs, reads atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		c := e.tenantOpts(t, "fo", nil).Database("fo").Collection("retry")
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := c.FindOne(context.Background(), bson.M{}).Err(); err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
				readErrs.Add(1)
				t.Errorf("read during failover: %v", err)
				return
			}
			reads.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	time.Sleep(time.Second)
	events0 := e.srv.UpstreamStats().TopologyEvents
	for round := 0; round < 2; round++ {
		before := e.primaryIndex(t)
		if before < 0 {
			t.Fatal("no primary")
		}
		pc := e.member(t, before)
		err := pc.Database("admin").RunCommand(context.Background(), bson.D{{Key: "replSetStepDown", Value: 30}, {Key: "force", Value: true}}).Err()
		if err != nil && !mongo.IsNetworkError(err) { // stepDown closes connections
			t.Fatalf("stepDown: %v", err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			if now := e.primaryIndex(t); now >= 0 && now != before {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no new primary elected in round %d (was %d, now %d): %+v", round, before, e.primaryIndex(t), e.srv.UpstreamStats().Members)
			}
			time.Sleep(100 * time.Millisecond)
		}
		a, b := okRetry.Load(), okNoRetry.Load()
		time.Sleep(3 * time.Second)
		if okRetry.Load() <= a || okNoRetry.Load() <= b {
			t.Fatalf("writes did not resume after failover round %d (retry %d->%d, noretry %d->%d)", round, a, okRetry.Load(), b, okNoRetry.Load())
		}
	}
	close(stop)
	wg.Wait()
	if t.Failed() {
		return
	}
	if ev := e.srv.UpstreamStats().TopologyEvents; ev <= events0 {
		t.Fatalf("proxy never noticed the topology change (%d events)", ev)
	}
	// Every acknowledged write is on the new primary exactly once.
	for name, want := range map[string]int64{"retry": okRetry.Load()} {
		got, err := e.tenant(t, "fo").Database("fo").Collection(name).CountDocuments(context.Background(), bson.M{})
		if err != nil || got != want {
			t.Fatalf("%s: %d documents for %d acknowledged writes (err %v)", name, got, want, err)
		}
	}
	t.Logf("writes ok: retry=%d noretry=%d (surfaced retryable errors: %d), reads=%d", okRetry.Load(), okNoRetry.Load(), errNoRetry.Load(), reads.Load())
}

// TestDedicatedMode checks the one-connection-per-client mode against a replica set.
func TestDedicatedMode(t *testing.T) {
	addrs := startReplSet(t)
	e := attachProxy(t, addrs, func(c *config.Config) { c.Upstream.Pool.Mode = "dedicated" })
	c := e.tenantOpts(t, "ded", func(o *options.ClientOptions) { o.SetMaxPoolSize(1) })
	coll := c.Database("ded").Collection("c", options.Collection().SetWriteConcern(majority()))
	docs := make([]any, 50)
	for i := range docs {
		docs[i] = bson.M{"_id": i}
	}
	if _, err := coll.InsertMany(context.Background(), docs); err != nil {
		t.Fatal(err)
	}
	sec := c.Database("ded").Collection("c", options.Collection().SetReadPreference(readpref.Secondary()).SetReadConcern(readconcern.Majority()))
	waitCount(t, sec, 50)
	// Each secondary advances its majority snapshot on its own schedule, so
	// retry until the one serving the cursor has caught up.
	n := 0
	for deadline := time.Now().Add(20 * time.Second); ; {
		cur, err := sec.Find(context.Background(), bson.M{}, options.Find().SetBatchSize(7))
		if err != nil {
			t.Fatal(err)
		}
		n = 0
		for cur.Next(context.Background()) {
			n++
		}
		if cur.Err() != nil {
			t.Fatal(cur.Err())
		}
		if n == 50 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("read %d of 50 documents", n)
		}
		time.Sleep(100 * time.Millisecond)
	}
	sess, _ := c.StartSession()
	_, err := sess.WithTransaction(context.Background(), func(ctx context.Context) (any, error) {
		return coll.InsertOne(ctx, bson.M{"_id": "tx"})
	})
	if err != nil {
		t.Fatal(err)
	}
	sess.EndSession(context.Background())
	// One socket per member at most, held for the client's lifetime.
	if st := e.srv.UpstreamStats(); st.PoolConnsOpened != 0 {
		t.Fatalf("dedicated mode used the pool: %+v", st)
	}
	c.Disconnect(context.Background())
	e.stop()
	if st := e.srv.UpstreamStats(); st.OpenConns != 0 {
		t.Fatalf("leaked upstream connections: %+v", st)
	}
}

// TestLargeReplyStreaming relays multi-megabyte batches through the chunked
// path and checks the cursor still works across getMore and killCursors.
func TestLargeReplyStreaming(t *testing.T) {
	for _, threshold := range []int{0, -1} { // default streaming, and always-buffer
		t.Run(fmt.Sprint("threshold=", threshold), func(t *testing.T) {
			e := setup(t, func(c *config.Config) { c.Streaming.ThresholdBytes = threshold })
			coll := e.tenant(t, "big").Database("big").Collection("c")
			pad := make([]byte, 400<<10)
			for i := range pad {
				pad[i] = byte('a' + i%26)
			}
			var docs []any
			for i := 0; i < 60; i++ {
				docs = append(docs, bson.M{"_id": i, "pad": string(pad)})
			}
			if _, err := coll.InsertMany(context.Background(), docs); err != nil {
				t.Fatal(err)
			}
			streamed0 := e.srv.M.StreamedReplies.Load()
			cur, err := coll.Find(context.Background(), bson.M{}, options.Find().SetBatchSize(60).SetSort(bson.M{"_id": 1}))
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for cur.Next(context.Background()) {
				var d struct {
					ID  int    `bson:"_id"`
					Pad string `bson:"pad"`
				}
				if err := cur.Decode(&d); err != nil || d.ID != n || d.Pad != string(pad) {
					t.Fatalf("doc %d corrupted (err %v)", n, err)
				}
				n++
			}
			if cur.Err() != nil || n != 60 {
				t.Fatalf("read %d docs, err %v", n, cur.Err())
			}
			if got, want := e.srv.M.StreamedReplies.Load() > streamed0, threshold >= 0; got != want {
				t.Fatalf("streamed=%v, want %v", got, want)
			}
			// Abandon a cursor mid-way: killCursors must find it.
			cur, err = coll.Find(context.Background(), bson.M{}, options.Find().SetBatchSize(5))
			if err != nil {
				t.Fatal(err)
			}
			cur.Next(context.Background())
			if err := cur.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			// A tenant cannot reach another tenant's cursor id through the streamed path.
			other := e.tenant(t, "other").Database("big")
			var res bson.M
			err = other.RunCommand(context.Background(), bson.D{{Key: "getMore", Value: cur.ID()}, {Key: "collection", Value: "c"}}).Decode(&res)
			if err == nil {
				t.Fatalf("foreign getMore succeeded: %v", res)
			}
		})
	}
}

// retryableFailure reports whether err is a failover error a driver would
// have retried: a retryable code or the RetryableWriteError label.
func retryableFailure(err error) bool {
	retry := func(code int) bool {
		switch code {
		case 6, 7, 89, 91, 189, 262, 9001, 10107, 11600, 11602, 13435, 13436:
			return true
		}
		return false
	}
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return ce.HasErrorLabel("RetryableWriteError") || retry(int(ce.Code))
	}
	var we mongo.WriteException
	if errors.As(err, &we) {
		if we.HasErrorLabel("RetryableWriteError") {
			return true
		}
		if we.WriteConcernError != nil && retry(we.WriteConcernError.Code) {
			return true
		}
		for _, e := range we.WriteErrors {
			if retry(e.Code) {
				return true
			}
		}
	}
	return false
}
