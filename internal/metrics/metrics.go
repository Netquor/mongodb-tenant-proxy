// Package metrics exposes a minimal Prometheus-format endpoint without any
// third-party dependency.
//
// Global series (mtp_connections_*, mtp_client_bytes_total, mtp_commands_total)
// keep their original names. Per-tenant series are mtp_tenant_*; their "tenant"
// label is bounded (see TenantLabel).
package metrics

import (
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

const (
	maxCommandNames  = 256   // distinct command names tracked globally
	maxTenantCmds    = 64    // distinct command/outcome pairs per tenant
	maxTrackedTenant = 10000 // tenants with their own counters
	// Unauthenticated is the tenant bucket for pre-auth traffic.
	Unauthenticated = "-"
)

// Counter is a monotonically increasing value.
type Counter struct{ v atomic.Int64 }

// Add increments the counter.
func (c *Counter) Add(n int64) { c.v.Add(n) }

// Load returns the current value.
func (c *Counter) Load() int64 { return c.v.Load() }

// Gauge is a value that can go up and down.
type Gauge struct{ v atomic.Int64 }

// Add adjusts the gauge.
func (g *Gauge) Add(n int64) { g.v.Add(n) }

// Load returns the current value.
func (g *Gauge) Load() int64 { return g.v.Load() }

var latencyBuckets = []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Tenant holds one tenant's counters.
type Tenant struct {
	ConnsTotal Counter
	BytesIn    Counter
	BytesOut   Counter
	Errors     Counter
	Denials    Counter

	mu   sync.Mutex
	cmds map[string]*Counter // "command|outcome"

	hist  [14]atomic.Int64 // non-cumulative bucket counts (+Inf last)
	sumNs atomic.Int64
	count atomic.Int64
}

// Command records a finished command: outcome is "ok", "denied" or "error".
func (t *Tenant) Command(name, outcome string, d time.Duration) {
	if t == nil {
		return
	}
	k := name + "|" + outcome
	t.mu.Lock()
	c := t.cmds[k]
	if c == nil {
		if len(t.cmds) >= maxTenantCmds {
			k = "other|" + outcome
			c = t.cmds[k]
		}
		if c == nil {
			c = &Counter{}
			t.cmds[k] = c
		}
	}
	t.mu.Unlock()
	c.Add(1)
	switch outcome {
	case "denied":
		t.Denials.Add(1)
	case "error":
		t.Errors.Add(1)
	}
	if d >= 0 {
		s := d.Seconds()
		i := sort.SearchFloat64s(latencyBuckets, s)
		t.hist[i].Add(1)
		t.sumNs.Add(int64(d))
		t.count.Add(1)
	}
}

// TenantGauges are point-in-time values read at scrape time.
type TenantGauges struct {
	Tenant  string
	Conns   int64
	Cursors int64
	Streams int64
}

// TenantStats is a JSON-friendly per-tenant snapshot.
type TenantStats struct {
	Tenant       string           `json:"tenant"`
	Connections  int64            `json:"connections"`
	OpenCursors  int64            `json:"openCursors"`
	ChangeStream int64            `json:"changeStreamSubscribers"`
	ConnsTotal   int64            `json:"connectionsTotal"`
	Commands     map[string]int64 `json:"commands"` // "find|ok" -> n
	Errors       int64            `json:"errors"`
	Denials      int64            `json:"denials"`
	BytesIn      int64            `json:"bytesIn"`
	BytesOut     int64            `json:"bytesOut"`
	AvgLatencyMs float64          `json:"avgLatencyMs"`
}

// Registry holds all proxy metrics.
type Registry struct {
	ConnsTotal  Counter
	ConnsActive Gauge
	BytesIn     Counter
	BytesOut    Counter

	mu       sync.Mutex
	commands map[string]*Counter // "command|outcome"
	quotas   map[string]*Counter // see quota.go
	gauges   map[string]*Gauge

	lab     *labeler
	tmu     sync.RWMutex
	tenants map[string]*Tenant
	tgauges atomic.Pointer[func() []TenantGauges]
}

// New returns an empty registry with the default tenant labelling.
func New() *Registry { return NewWith(config.TenantLabel{}) }

// NewWith returns a registry with the given tenant-label policy.
func NewWith(tl config.TenantLabel) *Registry {
	return &Registry{commands: map[string]*Counter{}, tenants: map[string]*Tenant{}, lab: newLabeler(tl)}
}

// SetGaugeSource installs the scrape-time provider of per-tenant gauges.
func (r *Registry) SetGaugeSource(f func() []TenantGauges) { r.tgauges.Store(&f) }

// PinTenants reserves label slots for declared tenants so they are never
// folded into "other" because of connection order.
func (r *Registry) PinTenants(ids []string) { r.lab.pin(ids) }

// Command counts a command by name and outcome ("ok", "denied", "error").
func (r *Registry) Command(name, outcome string) {
	k := name + "|" + outcome
	r.mu.Lock()
	c := r.commands[k]
	if c == nil {
		if len(r.commands) >= maxCommandNames {
			k = "other|" + outcome
			c = r.commands[k]
		}
		if c == nil {
			c = &Counter{}
			r.commands[k] = c
		}
	}
	r.mu.Unlock()
	c.Add(1)
}

// Tenant returns (creating if needed) the counters for a tenant id. Beyond
// maxTrackedTenant distinct ids, new tenants share the "other" counters.
func (r *Registry) Tenant(id string) *Tenant {
	if id == "" {
		id = Unauthenticated
	}
	r.tmu.RLock()
	t := r.tenants[id]
	r.tmu.RUnlock()
	if t != nil {
		return t
	}
	r.tmu.Lock()
	defer r.tmu.Unlock()
	if t = r.tenants[id]; t != nil {
		return t
	}
	if len(r.tenants) >= maxTrackedTenant {
		id = "other"
		if t = r.tenants[id]; t != nil {
			return t
		}
	}
	t = &Tenant{cmds: map[string]*Counter{}}
	r.tenants[id] = t
	r.lab.label(id) // fix the label now so "first N seen" is deterministic
	return t
}

// Stats returns a snapshot for one tenant (zero values if unseen).
func (r *Registry) Stats(id string) TenantStats {
	st := TenantStats{Tenant: id, Commands: map[string]int64{}}
	r.tmu.RLock()
	t := r.tenants[id]
	r.tmu.RUnlock()
	if t != nil {
		st.ConnsTotal = t.ConnsTotal.Load()
		st.Errors, st.Denials = t.Errors.Load(), t.Denials.Load()
		st.BytesIn, st.BytesOut = t.BytesIn.Load(), t.BytesOut.Load()
		t.mu.Lock()
		for k, c := range t.cmds {
			st.Commands[k] = c.Load()
		}
		t.mu.Unlock()
		if n := t.count.Load(); n > 0 {
			st.AvgLatencyMs = float64(t.sumNs.Load()) / float64(n) / 1e6
		}
	}
	if g := r.tgauges.Load(); g != nil {
		for _, tg := range (*g)() {
			if tg.Tenant == id {
				st.Connections += tg.Conns
				st.OpenCursors += tg.Cursors
				st.ChangeStream += tg.Streams
			}
		}
	}
	return st
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

type agg struct {
	cmds                        map[string]int64
	conns, cursors, streams     int64
	hist                        [14]int64
	sumNs, count                int64
	connsTotal, errs, den, b, o int64
}

func (r *Registry) write(w io.Writer) {
	fmt.Fprintf(w, "# TYPE mtp_connections_total counter\nmtp_connections_total %d\n", r.ConnsTotal.v.Load())
	fmt.Fprintf(w, "# TYPE mtp_connections_active gauge\nmtp_connections_active %d\n", r.ConnsActive.v.Load())
	fmt.Fprintf(w, "# TYPE mtp_client_bytes_total counter\nmtp_client_bytes_total{direction=\"in\"} %d\nmtp_client_bytes_total{direction=\"out\"} %d\n",
		r.BytesIn.v.Load(), r.BytesOut.v.Load())
	r.mu.Lock()
	keys := make([]string, 0, len(r.commands))
	for k := range r.commands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# TYPE mtp_commands_total counter\n")
	for _, k := range keys {
		name, outcome, _ := strings.Cut(k, "|")
		fmt.Fprintf(w, "mtp_commands_total{command=\"%s\",outcome=\"%s\"} %d\n", esc(name), esc(outcome), r.commands[k].v.Load())
	}
	r.writeQuota(w)
	r.mu.Unlock()
	r.writeTenants(w)
}

func (r *Registry) writeTenants(w io.Writer) {
	if r.lab.mode == "off" {
		return
	}
	groups := map[string]*agg{}
	get := func(id string) *agg {
		l := r.lab.label(id)
		a := groups[l]
		if a == nil {
			a = &agg{cmds: map[string]int64{}}
			groups[l] = a
		}
		return a
	}
	r.tmu.RLock()
	for id, t := range r.tenants {
		a := get(id)
		a.connsTotal += t.ConnsTotal.Load()
		a.errs += t.Errors.Load()
		a.den += t.Denials.Load()
		a.b += t.BytesIn.Load()
		a.o += t.BytesOut.Load()
		t.mu.Lock()
		for k, c := range t.cmds {
			a.cmds[k] += c.Load()
		}
		t.mu.Unlock()
		for i := range t.hist {
			a.hist[i] += t.hist[i].Load()
		}
		a.sumNs += t.sumNs.Load()
		a.count += t.count.Load()
	}
	r.tmu.RUnlock()
	if g := r.tgauges.Load(); g != nil {
		for _, tg := range (*g)() {
			a := get(tg.Tenant)
			a.conns += tg.Conns
			a.cursors += tg.Cursors
			a.streams += tg.Streams
		}
	}
	labels := make([]string, 0, len(groups))
	for l := range groups {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	type fam struct{ name, typ string }
	emit := func(f fam, line func(l string, a *agg)) {
		fmt.Fprintf(w, "# TYPE %s %s\n", f.name, f.typ)
		for _, l := range labels {
			line(esc(l), groups[l])
		}
	}
	emit(fam{"mtp_tenant_connections_total", "counter"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_connections_total{tenant=\"%s\"} %d\n", l, a.connsTotal)
	})
	emit(fam{"mtp_tenant_connections_active", "gauge"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_connections_active{tenant=\"%s\"} %d\n", l, a.conns)
	})
	emit(fam{"mtp_tenant_open_cursors", "gauge"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_open_cursors{tenant=\"%s\"} %d\n", l, a.cursors)
	})
	emit(fam{"mtp_tenant_changestream_subscribers", "gauge"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_changestream_subscribers{tenant=\"%s\"} %d\n", l, a.streams)
	})
	emit(fam{"mtp_tenant_commands_total", "counter"}, func(l string, a *agg) {
		ks := make([]string, 0, len(a.cmds))
		for k := range a.cmds {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			name, outcome, _ := strings.Cut(k, "|")
			fmt.Fprintf(w, "mtp_tenant_commands_total{tenant=\"%s\",command=\"%s\",outcome=\"%s\"} %d\n", l, esc(name), esc(outcome), a.cmds[k])
		}
	})
	emit(fam{"mtp_tenant_errors_total", "counter"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_errors_total{tenant=\"%s\"} %d\n", l, a.errs)
	})
	emit(fam{"mtp_tenant_denials_total", "counter"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_denials_total{tenant=\"%s\"} %d\n", l, a.den)
	})
	emit(fam{"mtp_tenant_client_bytes_total", "counter"}, func(l string, a *agg) {
		fmt.Fprintf(w, "mtp_tenant_client_bytes_total{tenant=\"%s\",direction=\"in\"} %d\n", l, a.b)
		fmt.Fprintf(w, "mtp_tenant_client_bytes_total{tenant=\"%s\",direction=\"out\"} %d\n", l, a.o)
	})
	emit(fam{"mtp_tenant_command_duration_seconds", "histogram"}, func(l string, a *agg) {
		var cum int64
		for i, le := range latencyBuckets {
			cum += a.hist[i]
			fmt.Fprintf(w, "mtp_tenant_command_duration_seconds_bucket{tenant=\"%s\",le=\"%g\"} %d\n", l, le, cum)
		}
		cum += a.hist[len(latencyBuckets)]
		fmt.Fprintf(w, "mtp_tenant_command_duration_seconds_bucket{tenant=\"%s\",le=\"+Inf\"} %d\n", l, cum)
		fmt.Fprintf(w, "mtp_tenant_command_duration_seconds_sum{tenant=\"%s\"} %g\n", l, float64(a.sumNs)/1e9)
		fmt.Fprintf(w, "mtp_tenant_command_duration_seconds_count{tenant=\"%s\"} %d\n", l, a.count)
	})
}

// Handler serves /metrics and /healthz.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.write(w)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	return mux
}

// ---- tenant label bounding --------------------------------------------------

type labeler struct {
	mode    string
	topN    int
	buckets int
	mu      sync.Mutex
	assign  map[string]string
}

func newLabeler(c config.TenantLabel) *labeler {
	l := &labeler{mode: c.Mode, topN: c.TopN, buckets: c.HashBuckets, assign: map[string]string{}}
	if l.mode == "" {
		l.mode = "top"
	}
	if l.topN <= 0 {
		l.topN = 50
	}
	if l.buckets <= 0 {
		l.buckets = 32
	}
	return l
}

func (l *labeler) pin(ids []string) {
	if l.mode != "top" {
		return
	}
	l.mu.Lock()
	for _, id := range ids {
		if _, ok := l.assign[id]; !ok && len(l.assign) < l.topN {
			l.assign[id] = id
		}
	}
	l.mu.Unlock()
}

func (l *labeler) label(id string) string {
	switch l.mode {
	case "all":
		return id
	case "hash":
		h := fnv.New32a()
		h.Write([]byte(id))
		return fmt.Sprintf("b%02d", h.Sum32()%uint32(l.buckets))
	}
	if id == Unauthenticated || id == "other" {
		return id
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if v, ok := l.assign[id]; ok {
		return v
	}
	if len(l.assign) < l.topN {
		l.assign[id] = id
		return id
	}
	l.assign[id] = "other"
	return "other"
}
