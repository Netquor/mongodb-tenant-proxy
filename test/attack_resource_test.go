package test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Resource exhaustion by an authenticated (malicious) tenant: cursor floods,
// pathological commands, session and view floods, configuration reload storms
// and one tenant starving another.

func (e *atkEnv) openCursors(t *testing.T) int64 {
	t.Helper()
	var res bson.M
	err := e.direct.Database("admin").RunCommand(ctx(t), bson.D{{Key: "serverStatus", Value: 1}}).Decode(&res)
	must(t, err)
	m, _ := res["metrics"].(bson.M)
	c, _ := m["cursor"].(bson.M)
	o, _ := c["open"].(bson.M)
	switch v := o["total"].(type) {
	case int64:
		return v
	case int32:
		return int64(v)
	}
	return -1
}

func TestAttackCursorFlood(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Tenant.Overrides = map[string]config.Limits{"tenant-capped": {MaxOpenCursors: 25}}
	}, nil)
	cl := e.tenant(t, "tenant-flood").Database("atk").Collection("cur")
	_, err := cl.InsertMany(ctx(t), []any{bson.M{"i": 1}, bson.M{"i": 2}, bson.M{"i": 3}})
	must(t, err)
	base := e.openCursors(t)

	t.Run("per-connection cap", func(t *testing.T) {
		r := e.atkDialTenant(t, "tenant-flood")
		opened, refused := 0, 0
		for i := 0; i < 10200; i++ {
			res := r.cmd("atk", bson.D{{Key: "find", Value: "cur"}, {Key: "batchSize", Value: 1}})
			if isOK(res) {
				opened++
			} else {
				refused++
				if refused > 3 {
					break
				}
			}
		}
		if refused == 0 || opened > 10000 {
			t.Fatalf("opened %d cursors on one connection, refused %d (cap is 10000)", opened, refused)
		}
		if n := e.openCursors(t) - base; n > 10000+100 {
			t.Fatalf("%d cursors open upstream", n)
		}
		// Hanging up releases every one of them upstream.
		r.nc.Close()
		deadline := time.Now().Add(20 * time.Second)
		for e.openCursors(t)-base > 50 {
			if time.Now().After(deadline) {
				t.Fatalf("%d cursors still open upstream 20s after the client left", e.openCursors(t)-base)
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	t.Run("per-tenant quota across connections, others unaffected", func(t *testing.T) {
		var conns []*atkRaw
		opened := 0
		for c := 0; c < 5; c++ {
			conns = append(conns, e.atkDialTenant(t, "tenant-capped"))
		}
		_, err := e.tenant(t, "tenant-capped").Database("atk").Collection("cur").InsertMany(ctx(t), []any{bson.M{"i": 1}, bson.M{"i": 2}})
		must(t, err)
		for i := 0; i < 60; i++ {
			if isOK(conns[i%5].cmd("atk", bson.D{{Key: "find", Value: "cur"}, {Key: "batchSize", Value: 1}})) {
				opened++
			}
		}
		if opened > 25 {
			t.Fatalf("tenant opened %d cursors with a quota of 25", opened)
		}
		// Another tenant opens cursors freely meanwhile.
		other := e.atkDialTenant(t, "tenant-other")
		_, err = e.tenant(t, "tenant-other").Database("atk").Collection("cur").InsertMany(ctx(t), []any{bson.M{"i": 1}, bson.M{"i": 2}})
		must(t, err)
		for i := 0; i < 40; i++ {
			if res := other.cmd("atk", bson.D{{Key: "find", Value: "cur"}, {Key: "batchSize", Value: 1}}); !isOK(res) {
				t.Fatalf("tenant-other refused at %d: %v", i, res)
			}
		}
		// Recovery: closing the flooding connections gives the quota back.
		for _, c := range conns {
			c.nc.Close()
		}
		fresh := e.atkDialTenant(t, "tenant-capped")
		deadline := time.Now().Add(10 * time.Second)
		for {
			if isOK(fresh.cmd("atk", bson.D{{Key: "find", Value: "cur"}, {Key: "batchSize", Value: 1}})) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("cursor quota never recovered")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	e.noPanics(t)
}

// Gigantic and deeply nested commands: bounded time, bounded memory, no panic.
func TestAttackHugeCommands(t *testing.T) {
	e := atkSetup(t, nil, nil)
	_, err := e.tenant(t, "tenant-a").Database("atk").Collection("big").InsertMany(ctx(t), []any{bson.M{"a": 1, "s": "x"}, bson.M{"a": 2, "s": "y"}})
	must(t, err)

	nest := func(key string, depth int, leaf any) any {
		v := leaf
		for i := 0; i < depth; i++ {
			v = bson.D{{Key: key, Value: bson.A{v}}}
		}
		return v
	}
	stages := func(n int) bson.A {
		a := make(bson.A, n)
		for i := range a {
			a[i] = bson.D{{Key: "$match", Value: bson.D{{Key: "a", Value: bson.D{{Key: "$gte", Value: 0}}}}}}
		}
		return a
	}
	bigIn := make(bson.A, 800000)
	for i := range bigIn {
		bigIn[i] = int32(i)
	}
	type tc struct {
		name string
		cmd  bson.D
	}
	cases := []tc{
		{"50k pipeline stages", bson.D{{Key: "aggregate", Value: "big"}, {Key: "pipeline", Value: stages(50000)}, {Key: "cursor", Value: bson.M{}}}},
		{"nested $and depth 90", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: nest("$and", 90, bson.D{{Key: "a", Value: 1}})}}},
		{"nested $and depth 101", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: nest("$and", 101, bson.D{{Key: "a", Value: 1}})}}},
		{"nested $and depth 5000", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: nest("$and", 5000, bson.D{{Key: "a", Value: 1}})}}},
		{"nested $facet", bson.D{{Key: "aggregate", Value: "big"}, {Key: "pipeline", Value: bson.A{nest("$facet", 60, bson.D{})}}, {Key: "cursor", Value: bson.M{}}}},
		{"nested $lookup pipelines", bson.D{{Key: "aggregate", Value: "big"}, {Key: "pipeline", Value: bson.A{
			bson.D{{Key: "$lookup", Value: bson.D{{Key: "from", Value: "big"}, {Key: "as", Value: "x"}, {Key: "pipeline", Value: bson.A{
				bson.D{{Key: "$lookup", Value: bson.D{{Key: "from", Value: "big"}, {Key: "as", Value: "y"}, {Key: "pipeline", Value: bson.A{
					bson.D{{Key: "$lookup", Value: bson.D{{Key: "from", Value: "big"}, {Key: "as", Value: "z"}, {Key: "pipeline", Value: bson.A{}}}}}}}}}}}}}}}}},
			{Key: "cursor", Value: bson.M{}}}},
		{"$in with 800k elements", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: bson.D{{Key: "a", Value: bson.D{{Key: "$in", Value: bigIn}}}}}}},
		{"$or with 100k branches", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: bson.D{{Key: "$or", Value: func() bson.A {
			a := make(bson.A, 100000)
			for i := range a {
				a[i] = bson.D{{Key: "a", Value: int32(i)}}
			}
			return a
		}()}}}}},
		{"filter with 300k keys", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: func() bson.D {
			d := make(bson.D, 300000)
			for i := range d {
				d[i] = bson.E{Key: fmt.Sprint("k", i), Value: 1}
			}
			return d
		}()}}},
		{"500 KB field name", bson.D{{Key: "find", Value: "big"}, {Key: "filter", Value: bson.D{{Key: strings.Repeat("f", 500000), Value: 1}}}}},
		{"$project with 10k fields", bson.D{{Key: "aggregate", Value: "big"}, {Key: "pipeline", Value: bson.A{bson.D{{Key: "$project", Value: func() bson.D {
			d := make(bson.D, 10000)
			for i := range d {
				d[i] = bson.E{Key: fmt.Sprint("p", i), Value: 1}
			}
			return d
		}()}}}}, {Key: "cursor", Value: bson.M{}}}},
		{"$group by 1M-way expression", bson.D{{Key: "aggregate", Value: "big"}, {Key: "pipeline", Value: bson.A{
			bson.D{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$a"}, {Key: "all", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}}},
			{Key: "cursor", Value: bson.M{}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.atkDialTenant(t, "tenant-a")
			heap := atkWatchHeap()
			start := time.Now()
			r.nc.SetDeadline(time.Now().Add(60 * time.Second))
			body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("atk", c.cmd))}).Encode()
			if len(body)+16 > 48<<20 {
				t.Skipf("generated command is %d bytes, over the message limit", len(body))
			}
			r.write(atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body))
			if _, _, err := r.readMsg(); err != nil {
				// A closed connection is an acceptable answer to garbage; what
				// is not acceptable is a hang or a crash.
				t.Logf("connection ended: %v", err)
			}
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("took %v", d)
			}
			if g := heap.growth(); g > 1<<30 {
				t.Errorf("heap grew %d MiB", g>>20)
			}
			e.noPanics(t)
		})
	}
	e.alive(t, "tenant-b")
}

// Regular expressions and slow operators are bounded by the tenant's
// maxTimeMS policy, however the client asks.
func TestAttackExpensiveOperators(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Tenant.Limits = config.Limits{DefaultMaxTimeMS: 1500, MaxTimeMSCap: 2000}
		c.Tenant.Overrides = map[string]config.Limits{"tenant-nojs": {DisableJS: true}}
	}, nil)
	col := e.tenant(t, "tenant-a").Database("atk").Collection("ex")
	var docs []any
	for i := 0; i < 3000; i++ {
		docs = append(docs, bson.M{"i": i, "s": strings.Repeat("a", 200) + "!", "k": i % 7})
	}
	_, err := col.InsertMany(ctx(t), docs)
	must(t, err)
	r := e.atkDialTenant(t, "tenant-a")
	timed := func(name string, cmd bson.D) {
		t.Helper()
		start := time.Now()
		t.Logf("running %s", name)
		res := r.cmd("atk", cmd)
		t.Logf("%s: %v ok=%v %v", name, time.Since(start).Round(time.Millisecond), isOK(res), res["codeName"])
		if d := time.Since(start); d > 12*time.Second {
			t.Errorf("%s ran for %v despite maxTimeMS caps (reply ok=%v)", name, d, isOK(res))
		}
	}
	timed("catastrophic regex", atkD("find", "ex", "filter", atkD("s", atkD("$regex", "^(a+)+$"))))
	timed("catastrophic regex, huge maxTimeMS", atkD("find", "ex", "filter", atkD("s", atkD("$regex", "(a|aa)+$")), "maxTimeMS", int64(1)<<40))
	timed("regex via $expr", atkD("aggregate", "ex", "cursor", atkD(), "maxTimeMS", 0, "pipeline", bson.A{
		atkD("$match", atkD("$expr", atkD("$regexMatch", atkD("input", "$s", "regex", "^(a*)*b"))))}))
	timed("self-join cartesian product", atkD("aggregate", "ex", "cursor", atkD(), "maxTimeMS", int64(1)<<40, "pipeline", bson.A{
		atkD("$lookup", atkD("from", "ex", "let", atkD("k", "$k"), "as", "j", "pipeline", bson.A{
			atkD("$match", atkD("$expr", atkD("$gte", bson.A{"$k", -1})))})),
		atkD("$unwind", "$j"),
		atkD("$group", atkD("_id", nil, "n", atkD("$sum", 1)))}))
	timed("$sort without index plus allowDiskUse", atkD("aggregate", "ex", "cursor", atkD(), "allowDiskUse", true, "pipeline", bson.A{
		atkD("$sort", atkD("s", 1, "i", -1))}))
	timed("$where busy loop", atkD("find", "ex", "filter", atkD("$where", "while(true){}")))
	// mongod does not interrupt a $function/$accumulator busy loop on maxTimeMS
	// (verified against 7.0 directly), so for tenants that must not burn CPU
	// the control is disableJS: every JS entry point is refused up front.
	nojs := e.atkDialTenant(t, "tenant-nojs")
	for name, cmd := range map[string]bson.D{
		"$function": atkD("aggregate", "ex", "cursor", atkD(), "pipeline", bson.A{
			atkD("$addFields", atkD("x", atkD("$function", atkD("body", "function(){while(true){}}", "args", bson.A{}, "lang", "js"))))}),
		"$accumulator": atkD("aggregate", "ex", "cursor", atkD(), "pipeline", bson.A{
			atkD("$group", atkD("_id", nil, "x", atkD("$accumulator", atkD("init", "function(){return 0}", "accumulate", "function(s){while(true){}}",
				"accumulateArgs", bson.A{}, "merge", "function(a,b){return a}", "lang", "js"))))}),
		"$where find":         atkD("find", "ex", "filter", atkD("$where", "while(true){}")),
		"$where in $or":       atkD("find", "ex", "filter", atkD("$or", bson.A{atkD("$where", "while(true){}")})),
		"$where in $expr":     atkD("find", "ex", "filter", atkD("$expr", atkD("$function", atkD("body", "function(){}", "args", bson.A{}, "lang", "js")))),
		"$where in lookup":    atkD("aggregate", "ex", "cursor", atkD(), "pipeline", bson.A{atkD("$lookup", atkD("from", "ex", "as", "j", "pipeline", bson.A{atkD("$match", atkD("$where", "1"))}))}),
		"$where in facet":     atkD("aggregate", "ex", "cursor", atkD(), "pipeline", bson.A{atkD("$facet", atkD("f", bson.A{atkD("$match", atkD("$where", "1"))}))}),
		"mapReduce":           atkD("mapReduce", "ex", "map", "function(){}", "reduce", "function(){}", "out", atkD("inline", 1)),
		"eval-like system.js": atkD("find", "system.js"),
	} {
		start := time.Now()
		res := nojs.cmd("atk", cmd)
		if isOK(res) && name != "eval-like system.js" {
			t.Errorf("%s ran for a disableJS tenant: %v", name, res)
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("%s took %v to be refused", name, time.Since(start))
		}
	}
	e.alive(t, "tenant-b")
	e.noPanics(t)
}

// One tenant's flood of requests does not slow another tenant down, and the
// flooder recovers once it stops.
func TestAttackNoisyNeighbour(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Tenant.Overrides = map[string]config.Limits{"tenant-noisy": {OpsPerSec: 50, OpsBurst: 50, MaxInFlight: 4}}
	}, nil)
	quiet := e.tenant(t, "tenant-quiet").Database("atk").Collection("n")
	_, err := quiet.InsertOne(ctx(t), bson.M{"x": 1})
	must(t, err)

	measure := func() (worst time.Duration, errs int) {
		for i := 0; i < 150; i++ {
			s := time.Now()
			if _, err := quiet.CountDocuments(ctx(t), bson.M{}); err != nil {
				errs++
			}
			if d := time.Since(s); d > worst {
				worst = d
			}
		}
		return
	}
	idleWorst, idleErrs := measure()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var limited, served atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.atkDialTenant(t, "tenant-noisy")
			for {
				select {
				case <-stop:
					return
				default:
				}
				if isOK(r.cmd("atk", bson.D{{Key: "count", Value: "n"}})) {
					served.Add(1)
				} else {
					limited.Add(1)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	busyWorst, busyErrs := measure()
	close(stop)
	wg.Wait()
	if idleErrs != 0 || busyErrs != 0 {
		t.Fatalf("quiet tenant saw errors: idle %d, under flood %d", idleErrs, busyErrs)
	}
	if limited.Load() == 0 {
		t.Fatal("the flood was never rate limited")
	}
	if busyWorst > 2*time.Second && busyWorst > 20*idleWorst {
		t.Fatalf("quiet tenant's worst latency rose from %v to %v under a neighbour's flood", idleWorst, busyWorst)
	}
	// Recovery: the flooder is served again after its bucket refills.
	r := e.atkDialTenant(t, "tenant-noisy")
	deadline := time.Now().Add(10 * time.Second)
	for !isOK(r.cmd("atk", bson.D{{Key: "count", Value: "n"}})) {
		if time.Now().After(deadline) {
			t.Fatal("rate-limited tenant never recovered")
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.noPanics(t)
}

// Sessions, views and indexes: counts are bounded and one tenant's flood does
// not use up another's allowance.
func TestAttackSessionsViewsIndexes(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Tenant.Limits = config.Limits{MaxIndexes: 30}
	}, nil)
	r := e.atkDialTenant(t, "tenant-a")

	t.Run("sessions", func(t *testing.T) {
		heap := atkWatchHeap()
		refused := 0
		for i := 0; i < 3000; i++ {
			id := bson.D{{Key: "id", Value: bson.Binary{Subtype: 4, Data: []byte(fmt.Sprintf("%016d", i))}}}
			if res := r.cmd("atk", bson.D{{Key: "ping", Value: 1}, {Key: "lsid", Value: id}}); !isOK(res) {
				refused++
			}
		}
		if g := heap.growth(); g > 256<<20 {
			t.Fatalf("3000 sessions grew the heap by %d MiB", g>>20)
		}
		// Forged session ids cannot be used to reach another tenant's sessions
		// (covered by TestSessions*); here only liveness matters.
		e.alive(t, "tenant-b")
		_ = refused
	})
	t.Run("views", func(t *testing.T) {
		_, err := e.tenant(t, "tenant-a").Database("atk").Collection("src").InsertOne(ctx(t), bson.M{"x": 1})
		must(t, err)
		heap := atkWatchHeap()
		ok := 0
		for i := 0; i < 400; i++ {
			res := r.cmd("atk", bson.D{{Key: "create", Value: fmt.Sprintf("v%d", i)}, {Key: "viewOn", Value: "src"},
				{Key: "pipeline", Value: bson.A{bson.D{{Key: "$match", Value: bson.D{{Key: "x", Value: 1}}}}}}})
			if isOK(res) {
				ok++
			}
		}
		if g := heap.growth(); g > 256<<20 {
			t.Fatalf("%d views grew the heap by %d MiB", ok, g>>20)
		}
		// Every view still reads correctly and stays tenant-scoped.
		res := r.cmd("atk", bson.D{{Key: "find", Value: "v0"}})
		if ok > 0 && !isOK(res) {
			t.Fatalf("view unreadable after the flood: %v", res)
		}
		e.alive(t, "tenant-b")
	})
	t.Run("index quota is per tenant", func(t *testing.T) {
		made := 0
		for i := 0; i < 60; i++ {
			coll := fmt.Sprintf("ix%d", i/10)
			res := r.cmd("atk", bson.D{{Key: "createIndexes", Value: coll}, {Key: "indexes", Value: bson.A{
				bson.D{{Key: "key", Value: bson.D{{Key: fmt.Sprintf("f%d", i), Value: 1}}}, {Key: "name", Value: fmt.Sprintf("i%d", i)}}}}})
			if isOK(res) {
				made++
			}
		}
		if made > 30 {
			t.Fatalf("tenant created %d indexes with a quota of 30", made)
		}
		rb := e.atkDialTenant(t, "tenant-b")
		if res := rb.cmd("atk", bson.D{{Key: "createIndexes", Value: "ixb"}, {Key: "indexes", Value: bson.A{
			bson.D{{Key: "key", Value: bson.D{{Key: "q", Value: 1}}}, {Key: "name", Value: "qi"}}}}}); !isOK(res) {
			t.Fatalf("another tenant was refused an index because of tenant-a's flood: %v", res)
		}
	})
	e.noPanics(t)
}

// Configuration reload storms while clients are active.
func TestAttackReloadStorm(t *testing.T) {
	e := atkSetup(t, nil, nil)
	cfg := *e.cfg
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cl := e.tenant(t, fmt.Sprintf("tenant-%d", i)).Database("atk").Collection("reload")
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := cl.InsertOne(ctx(t), bson.M{"i": i}); err != nil {
					failures.Add(1)
				}
			}
		}(i)
	}
	start := time.Now()
	var rw sync.WaitGroup
	for i := 0; i < 64; i++ {
		rw.Add(1)
		go func() {
			defer rw.Done()
			for j := 0; j < 20; j++ {
				c := cfg
				if _, err := e.srv.ReloadConfig(&c); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	rw.Wait()
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("1280 reloads took %v", d)
	}
	close(stop)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d client operations failed during the reload storm", failures.Load())
	}
	e.noPanics(t)
	e.alive(t, "tenant-after")
}

// atkD builds an ordered document from alternating keys and values.
func atkD(kv ...any) bson.D {
	d := make(bson.D, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		d = append(d, bson.E{Key: kv[i].(string), Value: kv[i+1]})
	}
	return d
}

// Change streams count against the tenant's open-cursor quota, so a tenant
// cannot open unbounded subscribers.
func TestAttackChangeStreamSubscribers(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Tenant.Overrides = map[string]config.Limits{"tenant-cs": {MaxOpenCursors: 4}}
	}, nil)
	_, err := e.tenant(t, "tenant-cs").Database("atk").Collection("cs").InsertOne(ctx(t), bson.M{"x": 1})
	must(t, err)
	r := e.atkDialTenant(t, "tenant-cs")
	opened := 0
	for i := 0; i < 20; i++ {
		res := r.cmd("atk", atkD("aggregate", "cs", "cursor", atkD(), "pipeline", bson.A{atkD("$changeStream", atkD())}))
		if isOK(res) {
			opened++
		}
	}
	if opened == 0 || opened > 4 {
		t.Fatalf("opened %d change streams with a quota of 4", opened)
	}
	e.noPanics(t)
	e.alive(t, "tenant-other")
}
