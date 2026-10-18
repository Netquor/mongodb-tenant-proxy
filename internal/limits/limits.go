// Package limits enforces per-tenant quotas: request rate, bandwidth, open
// cursors, created indexes, in-flight operations and server-side JavaScript.
package limits

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// Reasons reported for rejections (also used as metric labels).
const (
	ReasonOps      = "ops_rate"
	ReasonBytes    = "bytes_rate"
	ReasonCursors  = "open_cursors"
	ReasonIndexes  = "indexes"
	ReasonInFlight = "in_flight"
	ReasonCommand  = "command_size"
	ReasonResult   = "result_size"
	ReasonJSDenied = "js_disabled"
	ReasonJSRate   = "js_rate"
)

// Error is a quota rejection.
type Error struct {
	Reason string
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func exceeded(reason, format string, a ...any) *Error {
	return &Error{Reason: reason, Msg: "tenant proxy: quota exceeded: " + fmt.Sprintf(format, a...)}
}

// bucket is a token bucket. Spend may drive it negative ("debt") so that a
// single large request is admitted once, then the tenant must wait it out.
type bucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate, burst float64, now time.Time) *bucket {
	if burst < 1 {
		burst = rate
	}
	if burst < 1 {
		burst = 1
	}
	return &bucket{rate: rate, burst: burst, tokens: burst, last: now}
}

func (b *bucket) refill(now time.Time) {
	if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens += dt * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
}

// take removes n tokens if any are available (tokens > 0), returning false
// when the bucket is empty or in debt.
func (b *bucket) take(n float64, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(now)
	if b.tokens <= 0 {
		return false
	}
	b.tokens -= n
	return true
}

// debit records usage without rejecting.
func (b *bucket) debit(n float64, now time.Time) {
	b.mu.Lock()
	b.refill(now)
	b.tokens -= n
	b.mu.Unlock()
}

// Tenant holds one tenant's quota state.
type Tenant struct {
	ID string
	L  config.Limits

	now func() time.Time

	ops, bytes, js *bucket

	inflight atomic.Int64
	cursors  atomic.Int64

	mu      sync.Mutex
	indexes map[string]struct{}
}

func newTenant(id string, l config.Limits, now func() time.Time) *Tenant {
	t := &Tenant{ID: id, L: l, now: now, indexes: map[string]struct{}{}}
	n := now()
	if l.OpsPerSec > 0 {
		t.ops = newBucket(l.OpsPerSec, float64(l.OpsBurst), n)
	}
	if l.BytesPerSec > 0 {
		t.bytes = newBucket(float64(l.BytesPerSec), float64(l.BytesBurst), n)
	}
	if l.JSPerSec > 0 {
		t.js = newBucket(l.JSPerSec, 0, n)
	}
	return t
}

// Admit is called for every command before it is executed. cmdBytes is the
// size of the request message. The returned release function must be called
// when the command has finished (it is never nil when err is nil).
func (t *Tenant) Admit(cmdBytes int, countsInFlight bool) (release func(), err *Error) {
	l := t.L
	if l.MaxCommandBytes > 0 && cmdBytes > l.MaxCommandBytes {
		return nil, exceeded(ReasonCommand, "command of %d bytes exceeds the limit of %d", cmdBytes, l.MaxCommandBytes)
	}
	now := t.now()
	if t.ops != nil && !t.ops.take(1, now) {
		return nil, exceeded(ReasonOps, "more than %g operations per second", l.OpsPerSec)
	}
	if t.bytes != nil && !t.bytes.take(float64(cmdBytes), now) {
		return nil, exceeded(ReasonBytes, "more than %d bytes per second", l.BytesPerSec)
	}
	if !countsInFlight || l.MaxInFlight <= 0 {
		return func() {}, nil
	}
	if n := t.inflight.Add(1); n > int64(l.MaxInFlight) {
		t.inflight.Add(-1)
		return nil, exceeded(ReasonInFlight, "more than %d concurrent operations", l.MaxInFlight)
	}
	return func() { t.inflight.Add(-1) }, nil
}

// CountReply charges reply bytes to the bandwidth bucket.
func (t *Tenant) CountReply(n int) {
	if t.bytes != nil {
		t.bytes.debit(float64(n), t.now())
	}
}

// CheckResult rejects replies larger than MaxResultBytes.
func (t *Tenant) CheckResult(n int) *Error {
	if m := t.L.MaxResultBytes; m > 0 && n > m {
		return exceeded(ReasonResult, "result of %d bytes exceeds the limit of %d; use a smaller batchSize or projection", n, m)
	}
	return nil
}

// CheckCursor reports whether the tenant may open another cursor.
func (t *Tenant) CheckCursor() *Error {
	if m := t.L.MaxOpenCursors; m > 0 && t.cursors.Load() >= int64(m) {
		return exceeded(ReasonCursors, "more than %d open cursors", m)
	}
	return nil
}

// AddCursors adjusts the open-cursor count (negative to release).
func (t *Tenant) AddCursors(n int) { t.cursors.Add(int64(n)) }

// OpenCursors returns the current count.
func (t *Tenant) OpenCursors() int64 { return t.cursors.Load() }

// CheckIndexes registers index identifiers (db.coll#name) the tenant is about
// to create and rejects the request if that would exceed MaxIndexes.
func (t *Tenant) CheckIndexes(ids []string) *Error {
	if t.L.MaxIndexes <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	add := 0
	for _, id := range ids {
		if _, ok := t.indexes[id]; !ok {
			add++
		}
	}
	if len(t.indexes)+add > t.L.MaxIndexes {
		return exceeded(ReasonIndexes, "more than %d indexes", t.L.MaxIndexes)
	}
	for _, id := range ids {
		t.indexes[id] = struct{}{}
	}
	return nil
}

// ForgetIndex drops an index from the tenant's count.
func (t *Tenant) ForgetIndex(id string) {
	t.mu.Lock()
	delete(t.indexes, id)
	t.mu.Unlock()
}

// CheckJS is called for commands that run server-side JavaScript.
func (t *Tenant) CheckJS() *Error {
	if t.L.DisableJS {
		return exceeded(ReasonJSDenied, "server-side JavaScript is disabled for this tenant")
	}
	if t.js != nil && !t.js.take(1, t.now()) {
		return exceeded(ReasonJSRate, "more than %g JavaScript operations per second", t.L.JSPerSec)
	}
	return nil
}

// Manager hands out per-tenant state.
type Manager struct {
	cfg *config.Config
	now func() time.Time
	m   sync.Map // tenant id -> *Tenant
}

// NewManager builds a Manager. A nil clock means time.Now.
func NewManager(cfg *config.Config, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{cfg: cfg, now: now}
}

// For returns the tenant's quota state.
func (m *Manager) For(id string) *Tenant {
	if v, ok := m.m.Load(id); ok {
		return v.(*Tenant)
	}
	v, _ := m.m.LoadOrStore(id, newTenant(id, m.cfg.LimitsFor(id), m.now))
	return v.(*Tenant)
}
