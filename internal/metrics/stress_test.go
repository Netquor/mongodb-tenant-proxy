package metrics

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Counters are updated from every connection goroutine while scrapes and
// per-tenant snapshots run. Totals must reconcile exactly and the gauge
// source (which takes the proxy's own lock) must be callable mid-update.
func TestStressRegistry(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	r := New()
	var gmu sync.Mutex
	r.SetGaugeSource(func() []TenantGauges { gmu.Lock(); defer gmu.Unlock(); return []TenantGauges{{Tenant: "t0", Conns: 1}} })
	const workers, iters = 16, 3000
	n := stresstest.N(iters, iters*20)
	stop := make(chan struct{})
	var scrapers sync.WaitGroup
	for i := 0; i < 2; i++ {
		scrapers.Add(1)
		go func() {
			defer scrapers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rec := httptest.NewRecorder()
				r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
				r.Stats("t1")
			}
		}()
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ten := fmt.Sprint("t", w%4)
			for i := 0; i < n; i++ {
				tm := r.Tenant(ten)
				tm.ConnsTotal.Add(1)
				tm.Command("find", "ok", time.Microsecond)
				r.Command("find", "ok")
				r.Quota(ten, "ops_rate")
				r.Gauge("inflight_operations", ten).Add(1)
				r.Gauge("inflight_operations", ten).Add(-1)
				r.ConnsActive.Add(1)
				r.ConnsActive.Add(-1)
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	scrapers.Wait()
	for k := 0; k < 4; k++ {
		ten := fmt.Sprint("t", k)
		st := r.Stats(ten)
		if want := int64(workers / 4 * n); st.ConnsTotal != want || st.Commands["find|ok"] != want {
			t.Errorf("%s: connsTotal=%d commands=%d, want %d", ten, st.ConnsTotal, st.Commands["find|ok"], want)
		}
		if g := r.Gauge("inflight_operations", ten).Load(); g != 0 {
			t.Errorf("%s: in-flight gauge %d, want 0", ten, g)
		}
	}
	if r.ConnsActive.Load() != 0 {
		t.Errorf("active connections gauge = %d", r.ConnsActive.Load())
	}
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "mtp_commands_total") {
		t.Error("scrape lost the command counters")
	}
}
