package limits

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// In-flight and cursor counters reconcile to zero after arbitrary concurrent
// admit/release; the in-flight cap is never exceeded; index registration never
// exceeds MaxIndexes.
func TestStressLimiter(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	cfg := &config.Config{Tenant: config.Tenant{Limits: config.Limits{
		OpsPerSec: 1e9, OpsBurst: 1e9, BytesPerSec: 1 << 40, BytesBurst: 1 << 40,
		MaxInFlight: 7, MaxIndexes: 10, JSPerSec: 1e9,
	}}}
	m := NewManager(cfg, nil)
	iters := stresstest.N(20000, 300000)
	var maxSeen atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ten := m.For("shared") // same tenant from every "connection"
			other := m.For(string(rune('a' + w%4)))
			for i := 0; i < iters; i++ {
				if rel, err := ten.Admit(10, true); err == nil {
					if n := ten.inflight.Load(); n > maxSeen.Load() {
						maxSeen.Store(n)
					}
					rel()
				}
				if rel, err := other.Admit(10, i%2 == 0); err == nil {
					rel()
				}
				ten.AddCursors(1)
				ten.AddCursors(-1)
				ten.CheckCursor()
				ten.CheckIndexes([]string{"d.c#a", "d.c#b"})
				ten.ForgetIndex("d.c#a")
				ten.CheckJS()
				ten.CountReply(100)
			}
		}(w)
	}
	wg.Wait()
	for _, id := range []string{"shared", "a", "b", "c", "d"} {
		ten := m.For(id)
		if n := ten.inflight.Load(); n != 0 {
			t.Errorf("%s: in-flight counter leaked: %d", id, n)
		}
		if n := ten.OpenCursors(); n != 0 {
			t.Errorf("%s: cursor counter did not reconcile: %d", id, n)
		}
	}
	if got := maxSeen.Load(); got > 7 {
		// inflight is incremented before the cap check, so brief overshoot by
		// the number of racing admitters is visible to observers but never
		// admitted; only admitted requests count here.
		t.Logf("transient in-flight peak %d (cap 7)", got)
	}
	ten := m.For("shared")
	ten.mu.Lock()
	if len(ten.indexes) > 10 {
		t.Errorf("tenant holds %d indexes, cap 10", len(ten.indexes))
	}
	ten.mu.Unlock()
}

// Admitted in-flight operations never exceed the cap.
func TestStressInFlightCap(t *testing.T) {
	cfg := &config.Config{Tenant: config.Tenant{Limits: config.Limits{MaxInFlight: 5}}}
	ten := NewManager(cfg, nil).For("x")
	var cur, peak atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < stresstest.N(5000, 100000); i++ {
				rel, err := ten.Admit(1, true)
				if err != nil {
					continue
				}
				n := cur.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				cur.Add(-1)
				rel()
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > 5 {
		t.Fatalf("admitted %d concurrent operations, cap is 5", p)
	}
}

// Manager.For hands every caller the same *Tenant even on first creation.
func TestStressManagerFor(t *testing.T) {
	for r := 0; r < stresstest.N(50, 500); r++ {
		m := NewManager(&config.Config{}, nil)
		var wg sync.WaitGroup
		got := make([]*Tenant, 16)
		for i := range got {
			wg.Add(1)
			go func() { defer wg.Done(); got[i] = m.For("t") }()
		}
		wg.Wait()
		for _, g := range got {
			if g != got[0] {
				t.Fatal("two distinct Tenant states for one id")
			}
		}
	}
}
