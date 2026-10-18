package test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func quotaErr(err error) bool {
	if err == nil {
		return false
	}
	var ce mongo.CommandError
	if asCommandError(err, &ce) {
		return ce.Code == 8000 && ce.Name == "TenantQuotaExceeded"
	}
	return strings.Contains(err.Error(), "quota exceeded")
}

func asCommandError(err error, ce *mongo.CommandError) bool {
	if c, ok := err.(mongo.CommandError); ok {
		*ce = c
		return true
	}
	return false
}

func limitsFor(tenant string, l config.Limits) func(*config.Config) {
	return func(c *config.Config) {
		c.Tenant.Overrides = map[string]config.Limits{tenant: l}
	}
}

func TestQuotaOpsRateLimit(t *testing.T) {
	e := setup(t, limitsFor("tenant-slow", config.Limits{OpsPerSec: 5, OpsBurst: 5}))
	slow := e.tenant(t, "tenant-slow").Database("app").Collection("q")
	free := e.tenant(t, "tenant-free").Database("app").Collection("q")
	_, err := free.InsertOne(ctx(t), bson.M{"n": 1})
	must(t, err)

	rejected, ok := 0, 0
	start := time.Now()
	for i := 0; i < 40; i++ {
		if _, err := slow.CountDocuments(ctx(t), bson.M{}); err != nil {
			if !quotaErr(err) {
				t.Fatalf("unexpected error: %v", err)
			}
			rejected++
		} else {
			ok++
		}
	}
	// 5 burst + about 5/s refill over the loop's duration.
	budget := 5 + int(time.Since(start).Seconds()*5) + 2
	if rejected == 0 || ok > budget {
		t.Fatalf("rate limit not enforced: ok=%d rejected=%d (budget %d)", ok, rejected, budget)
	}
	// Other tenants are unaffected.
	for i := 0; i < 40; i++ {
		if _, err := free.CountDocuments(ctx(t), bson.M{}); err != nil {
			t.Fatalf("unlimited tenant throttled: %v", err)
		}
	}
	// Tokens come back.
	time.Sleep(1200 * time.Millisecond)
	if _, err := slow.CountDocuments(ctx(t), bson.M{}); err != nil {
		t.Fatalf("still throttled after refill: %v", err)
	}
}

func TestQuotaDefaultsAndBytes(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		c.Tenant.Limits = config.Limits{BytesPerSec: 20000, BytesBurst: 20000}
		c.Tenant.Overrides = map[string]config.Limits{"vip": {BytesPerSec: 1 << 30}}
	})
	big := strings.Repeat("x", 2000)
	insert := func(c *mongo.Collection) error {
		docs := make([]any, 10)
		for i := range docs {
			docs[i] = bson.M{"i": i, "pad": big}
		}
		_, err := c.InsertMany(ctx(t), docs)
		return err
	}
	a := e.tenant(t, "tenant-a").Database("app").Collection("b")
	var sawQuota bool
	for i := 0; i < 20 && !sawQuota; i++ {
		if err := insert(a); err != nil {
			if !quotaErr(err) {
				t.Fatal(err)
			}
			sawQuota = true
		}
	}
	if !sawQuota {
		t.Fatal("default bytes/sec limit not enforced")
	}
	vip := e.tenant(t, "vip").Database("app").Collection("b")
	for i := 0; i < 20; i++ {
		must(t, insert(vip))
	}
}

func TestQuotaCursorsAndIndexes(t *testing.T) {
	e := setup(t, limitsFor("tenant-a", config.Limits{MaxOpenCursors: 2, MaxIndexes: 2}))
	ca := e.tenant(t, "tenant-a").Database("app").Collection("c")
	docs := make([]any, 10)
	for i := range docs {
		docs[i] = bson.M{"i": i}
	}
	_, err := ca.InsertMany(ctx(t), docs)
	must(t, err)

	open := func() *mongo.Cursor {
		cur, err := ca.Find(ctx(t), bson.M{}, options.Find().SetBatchSize(1))
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		return cur
	}
	c1, c2 := open(), open()
	_, err = ca.Find(ctx(t), bson.M{}, options.Find().SetBatchSize(1))
	if !quotaErr(err) {
		t.Fatalf("third cursor should hit the cap, got %v", err)
	}
	// Another tenant has its own budget.
	cb := e.tenant(t, "tenant-b").Database("app").Collection("c")
	_, err = cb.InsertOne(ctx(t), bson.M{"i": 1})
	must(t, err)
	for i := 0; i < 4; i++ {
		cur, err := cb.Find(ctx(t), bson.M{}, options.Find().SetBatchSize(1))
		must(t, err)
		defer cur.Close(ctx(t))
	}
	// Closing a cursor frees a slot.
	must(t, c1.Close(ctx(t)))
	c3 := open()
	// Exhausting a cursor frees one too.
	var all []bson.M
	must(t, c2.All(ctx(t), &all))
	c4 := open()
	c3.Close(ctx(t))
	c4.Close(ctx(t))

	// Index budget.
	idx := func(field string) error {
		_, err := ca.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: field, Value: 1}}})
		return err
	}
	must(t, idx("a"))
	must(t, idx("b"))
	must(t, idx("a")) // already exists: free
	if err := idx("c"); !quotaErr(err) {
		t.Fatalf("third index should hit the cap, got %v", err)
	}
	err = ca.Indexes().DropOne(ctx(t), "a_1")
	must(t, err)
	must(t, idx("c"))
}

func TestQuotaInFlightAndJS(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		c.Tenant.Overrides = map[string]config.Limits{
			"tenant-a": {MaxInFlight: 1},
			"nojs":     {DisableJS: true},
			"jsrate":   {JSPerSec: 1},
		}
	})
	ca := e.tenant(t, "tenant-a").Database("app").Collection("j")
	_, err := ca.InsertOne(ctx(t), bson.M{"n": 1})
	must(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Holds the tenant's only slot for about a second.
		ca.FindOne(ctx(t), bson.M{"$where": "sleep(1200) || true"}).Err()
	}()
	time.Sleep(400 * time.Millisecond)
	_, err = ca.CountDocuments(ctx(t), bson.M{})
	if !quotaErr(err) {
		t.Fatalf("second concurrent operation should be rejected, got %v", err)
	}
	wg.Wait()
	if _, err = ca.CountDocuments(ctx(t), bson.M{}); err != nil {
		t.Fatalf("slot not released: %v", err)
	}

	nojs := e.tenant(t, "nojs").Database("app").Collection("j")
	_, err = nojs.InsertOne(ctx(t), bson.M{"n": 1})
	must(t, err)
	if err := nojs.FindOne(ctx(t), bson.M{"$where": "true"}).Err(); !quotaErr(err) {
		t.Fatalf("$where should be refused for this tenant, got %v", err)
	}
	if _, err := nojs.CountDocuments(ctx(t), bson.M{"n": 1}); err != nil {
		t.Fatal(err)
	}
	// Other tenants may still run JavaScript.
	if err := ca.FindOne(ctx(t), bson.M{"$where": "true"}).Err(); err != nil {
		t.Fatalf("JS should be allowed for tenant-a: %v", err)
	}

	jr := e.tenant(t, "jsrate").Database("app").Collection("j")
	_, err = jr.InsertOne(ctx(t), bson.M{"n": 1})
	must(t, err)
	var js, limited int
	for i := 0; i < 5; i++ {
		err := jr.FindOne(ctx(t), bson.M{"$where": "true"}).Err()
		if quotaErr(err) {
			limited++
		} else if err == nil {
			js++
		} else {
			t.Fatal(err)
		}
	}
	if js == 0 || limited == 0 {
		t.Fatalf("JS rate limit: ran=%d limited=%d", js, limited)
	}
	// Non-JS work isn't affected by the JS budget.
	for i := 0; i < 5; i++ {
		if _, err := jr.CountDocuments(ctx(t), bson.M{"n": 1}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQuotaMaxTimeAndSizes(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		c.Tenant.Limits = config.Limits{MaxTimeMSCap: 600, DefaultMaxTimeMS: 600, MaxCommandBytes: 200000, MaxResultBytes: 30000}
	})
	c := e.tenant(t, "tenant-a").Database("app").Collection("m")
	pad := strings.Repeat("y", 1000)
	docs := make([]any, 50)
	for i := range docs {
		docs[i] = bson.M{"i": i, "pad": pad}
	}
	_, err := c.InsertMany(ctx(t), docs)
	must(t, err)

	// Default maxTimeMS applies to reads that specify none.
	start := time.Now()
	err = c.FindOne(ctx(t), bson.M{"$where": "sleep(4000) || true"}).Err()
	if err == nil || !mongo.IsTimeout(err) && !strings.Contains(err.Error(), "time limit") {
		t.Fatalf("expected a time limit error, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("maxTimeMS default not enforced (took %s)", time.Since(start))
	}
	// An over-large client maxTimeMS is clamped; a small one passes through.
	r := e.raw(t, "tenant-a")
	slow := bson.D{{Key: "count", Value: "m"}, {Key: "query", Value: bson.M{"$where": "sleep(4000) || true"}}}
	start = time.Now()
	res := r.run("app", append(slow, bson.E{Key: "maxTimeMS", Value: 60000}))
	if isOK(res) || res["code"] != int32(50) || time.Since(start) > 3*time.Second {
		t.Fatalf("maxTimeMS cap not enforced: %v after %s", res, time.Since(start))
	}
	res = r.run("app", bson.D{{Key: "count", Value: "m"}, {Key: "maxTimeMS", Value: 500}})
	if !isOK(res) || res["n"] != int32(50) {
		t.Fatalf("count with a small maxTimeMS: %v", res)
	}
	start = time.Now()
	res = r.run("app", append(slow, bson.E{Key: "maxTimeMS", Value: 0})) // 0 means "no limit" to the server
	if isOK(res) || time.Since(start) > 3*time.Second {
		t.Fatalf("maxTimeMS 0 must not bypass the cap: %v after %s", res, time.Since(start))
	}

	// Result size: the batch is too big, the cursor is released.
	_, err = c.Find(ctx(t), bson.M{})
	if !quotaErr(err) {
		t.Fatalf("oversized reply should be refused, got %v", err)
	}
	cur, err := c.Find(ctx(t), bson.M{}, options.Find().SetBatchSize(5))
	must(t, err)
	var got []bson.M
	must(t, cur.All(ctx(t), &got))
	if len(got) != 50 {
		t.Fatalf("paged read returned %d", len(got))
	}

	// Command size.
	huge := strings.Repeat("z", 300000)
	_, err = c.InsertOne(ctx(t), bson.M{"huge": huge})
	if !quotaErr(err) {
		t.Fatalf("oversized command should be refused, got %v", err)
	}
}
