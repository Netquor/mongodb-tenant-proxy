package proxy

import (
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Logical session ownership.
//
// A logical session id (lsid.id, a UUID) is a bearer token: whoever presents
// it can continue its transactions, retryable writes and cursors on the
// upstream server, which authenticates the proxy rather than the tenant. The
// proxy therefore binds every lsid to the tenant that first used it and
// rejects any other tenant that presents it.
//
// Bindings live for logicalSessionTimeoutMinutes plus a grace period (mongod
// only reaps expired sessions periodically), and are refreshed on every use.

const (
	sessionGrace         = 10 * time.Minute
	maxSessionsPerTenant = 100000
)

type sessionBinding struct {
	tenant  string
	expires time.Time
}

type sessionTable struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	m        map[[16]byte]sessionBinding
	perTen   map[string]int
	nextScan time.Time
}

func newSessionTable(timeoutMinutes int32, now func() time.Time) *sessionTable {
	if timeoutMinutes <= 0 {
		timeoutMinutes = 30
	}
	if now == nil {
		now = time.Now
	}
	return &sessionTable{
		ttl:    time.Duration(timeoutMinutes)*time.Minute + sessionGrace,
		now:    now,
		m:      map[[16]byte]sessionBinding{},
		perTen: map[string]int{},
	}
}

// bind claims id for tenant (or refreshes the claim). It returns false when
// the session belongs to another tenant or the tenant has too many sessions.
func (t *sessionTable) bind(tenant string, id [16]byte) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
	b, ok := t.m[id]
	if ok && now.Before(b.expires) {
		if b.tenant != tenant {
			return false
		}
	} else {
		if ok { // expired binding of an earlier owner
			t.perTen[b.tenant]--
		}
		if t.perTen[tenant] >= maxSessionsPerTenant {
			return false
		}
		t.perTen[tenant]++
	}
	t.m[id] = sessionBinding{tenant: tenant, expires: now.Add(t.ttl)}
	return true
}

// sweepLocked drops expired bindings, at most once a minute.
func (t *sessionTable) sweepLocked(now time.Time) {
	if now.Before(t.nextScan) {
		return
	}
	t.nextScan = now.Add(time.Minute)
	for id, b := range t.m {
		if !now.Before(b.expires) {
			delete(t.m, id)
			if t.perTen[b.tenant]--; t.perTen[b.tenant] <= 0 {
				delete(t.perTen, b.tenant)
			}
		}
	}
}

func (t *sessionTable) size() int { t.mu.Lock(); defer t.mu.Unlock(); return len(t.m) }

// sessionID extracts the 16-byte UUID from an {id: <UUID>} document.
func sessionID(d bsoncore.Document) ([16]byte, bool) {
	var out [16]byte
	sub, data, ok := d.Lookup("id").BinaryOK()
	if !ok || sub != 4 || len(data) != 16 {
		return out, false
	}
	copy(out[:], data)
	return out, true
}

// check validates every logical session id a command refers to and
// binds new ones. It returns a client-facing error message, or "" if fine.
func (t *sessionTable) check(tenant, cmd string, body bsoncore.Document) string {
	const bad = "tenant proxy: session is not accessible"
	if v := body.Lookup("lsid"); v.Type != 0 {
		d, ok := v.DocumentOK()
		if !ok {
			return "tenant proxy: malformed lsid"
		}
		id, ok := sessionID(d)
		if !ok {
			return "tenant proxy: malformed lsid"
		}
		if !t.bind(tenant, id) {
			return bad
		}
	}
	switch cmd {
	case "endSessions", "refreshSessions", "killSessions":
		arr, ok := body.Index(0).Value().ArrayOK()
		if !ok {
			return "tenant proxy: " + cmd + " requires an array of sessions"
		}
		vals, err := arr.Values()
		if err != nil {
			return "tenant proxy: malformed " + cmd
		}
		ids := make([][16]byte, 0, len(vals))
		for _, v := range vals {
			d, ok := v.DocumentOK()
			if !ok {
				return "tenant proxy: malformed " + cmd
			}
			id, ok := sessionID(d)
			if !ok {
				return "tenant proxy: malformed " + cmd
			}
			ids = append(ids, id)
		}
		// Reject the whole request if any session is foreign, before binding
		// anything, so a mixed list has no partial effect.
		for _, id := range ids {
			if !t.owned(tenant, id) {
				return bad
			}
		}
		for _, id := range ids {
			if !t.bind(tenant, id) {
				return bad
			}
		}
	}
	return ""
}

// owned reports whether id is unbound or bound to tenant.
func (t *sessionTable) owned(tenant string, id [16]byte) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.m[id]
	return !ok || !now.Before(b.expires) || b.tenant == tenant
}
