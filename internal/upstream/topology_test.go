package upstream

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func testTopo(t *testing.T, hosts ...string) *topology {
	t.Helper()
	var hs []config.Host
	for _, h := range hosts {
		hs = append(hs, config.Host{Addr: h})
	}
	d := &Dialer{cfg: config.Upstream{Hosts: hs, ReplicaSet: "rs0"}, hosts: map[string]*hostTLS{}}
	return newTopology(d)
}

func hello(t *testing.T, m bson.M) bsoncore.Document {
	t.Helper()
	b, err := bson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func descOf(t *testing.T, m bson.M) ServerDesc {
	d := parseHello(hello(t, m))
	d.LastUpdate = time.Now()
	return d
}

func TestParseHelloTypes(t *testing.T) {
	cases := []struct {
		name string
		h    bson.M
		want ServerType
	}{
		{"primary", bson.M{"setName": "rs0", "isWritablePrimary": true}, RSPrimary},
		{"secondary", bson.M{"setName": "rs0", "secondary": true}, RSSecondary},
		{"hidden", bson.M{"setName": "rs0", "secondary": true, "hidden": true}, RSOther},
		{"arbiter", bson.M{"setName": "rs0", "arbiterOnly": true}, RSArbiter},
		{"standalone", bson.M{"isWritablePrimary": true}, Standalone},
		{"mongos", bson.M{"isWritablePrimary": true, "msg": "isdbgrid"}, Mongos},
		{"ghost", bson.M{"isreplicaset": true}, RSGhost},
	}
	for _, c := range cases {
		if got := descOf(t, c.h).Type; got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func setMember(tp *topology, addr string, d ServerDesc) {
	tp.mu.Lock()
	tp.members[addr].desc = d
	tp.mu.Unlock()
}

func pick(t *testing.T, tp *topology, s Selector) string {
	t.Helper()
	tp.mu.Lock()
	defer tp.mu.Unlock()
	m, err := tp.pickLocked(s)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		return ""
	}
	return m.addr
}

func TestSelectionModes(t *testing.T) {
	tp := testTopo(t, "p:1", "s1:1", "s2:1")
	p := descOf(t, bson.M{"setName": "rs0", "isWritablePrimary": true})
	s1 := descOf(t, bson.M{"setName": "rs0", "secondary": true, "tags": bson.M{"dc": "east"}})
	s2 := descOf(t, bson.M{"setName": "rs0", "secondary": true, "tags": bson.M{"dc": "west"}})
	setMember(tp, "p:1", p)
	setMember(tp, "s1:1", s1)
	setMember(tp, "s2:1", s2)

	if got := pick(t, tp, Selector{Mode: Primary}); got != "p:1" {
		t.Fatalf("primary: %s", got)
	}
	for i := 0; i < 20; i++ {
		if got := pick(t, tp, Selector{Mode: Secondary}); got == "p:1" || got == "" {
			t.Fatalf("secondary picked %q", got)
		}
	}
	if got := pick(t, tp, Selector{Mode: Secondary, Tags: []map[string]string{{"dc": "west"}}}); got != "s2:1" {
		t.Fatalf("tags: %q", got)
	}
	// First matching tag set wins; empty set matches anything.
	if got := pick(t, tp, Selector{Mode: Secondary, Tags: []map[string]string{{"dc": "mars"}, {"dc": "east"}}}); got != "s1:1" {
		t.Fatalf("tag fallback: %q", got)
	}
	if got := pick(t, tp, Selector{Mode: Secondary, Tags: []map[string]string{{"dc": "mars"}}}); got != "" {
		t.Fatalf("unmatched tags should wait, got %q", got)
	}
	if got := pick(t, tp, Selector{Mode: SecondaryPreferred, Tags: []map[string]string{{"dc": "mars"}}}); got != "p:1" {
		t.Fatalf("secondaryPreferred falls back to primary: %q", got)
	}
	// Without a primary: primary waits, primaryPreferred uses a secondary.
	setMember(tp, "p:1", ServerDesc{Type: Unknown})
	if got := pick(t, tp, Selector{Mode: Primary}); got != "" {
		t.Fatalf("no primary: %q", got)
	}
	if got := pick(t, tp, Selector{Mode: PrimaryPreferred}); got == "" || got == "p:1" {
		t.Fatalf("primaryPreferred: %q", got)
	}
	// Cursor affinity addresses one member exactly, and only if it is known.
	if got := pick(t, tp, Selector{Addr: "s2:1"}); got != "s2:1" {
		t.Fatalf("affinity: %q", got)
	}
	if got := pick(t, tp, Selector{Addr: "p:1"}); got != "" {
		t.Fatalf("affinity to unknown member should wait: %q", got)
	}
	tp.mu.Lock()
	_, err := tp.pickLocked(Selector{Addr: "gone:1"})
	tp.mu.Unlock()
	if err != errNoMember {
		t.Fatalf("affinity to removed member: %v", err)
	}
}

func TestMaxStaleness(t *testing.T) {
	tp := testTopo(t, "p:1", "fresh:1", "stale:1")
	now := time.Now()
	mk := func(m bson.M, lag time.Duration) ServerDesc {
		d := descOf(t, m)
		d.LastUpdate = now
		d.LastWrite = now.Add(-lag)
		return d
	}
	setMember(tp, "p:1", mk(bson.M{"setName": "rs0", "isWritablePrimary": true}, 0))
	setMember(tp, "fresh:1", mk(bson.M{"setName": "rs0", "secondary": true}, 5*time.Second))
	setMember(tp, "stale:1", mk(bson.M{"setName": "rs0", "secondary": true}, 10*time.Minute))
	for i := 0; i < 20; i++ {
		if got := pick(t, tp, Selector{Mode: Secondary, MaxStaleness: 120 * time.Second}); got != "fresh:1" {
			t.Fatalf("got %q", got)
		}
	}
	// Staleness is measured against the newest member when there is no primary.
	setMember(tp, "p:1", ServerDesc{Type: Unknown})
	if got := pick(t, tp, Selector{Mode: Secondary, MaxStaleness: 120 * time.Second}); got != "fresh:1" {
		t.Fatalf("no primary: %q", got)
	}
}

func TestDirectModeIgnoresRoles(t *testing.T) {
	d := &Dialer{cfg: config.Upstream{Hosts: []config.Host{{Addr: "only:1"}}}, hosts: map[string]*hostTLS{}}
	tp := newTopology(d)
	if !tp.direct {
		t.Fatal("single host should be direct")
	}
	setMember(tp, "only:1", descOf(t, bson.M{"setName": "rs0", "secondary": true}))
	if got := pick(t, tp, Selector{Mode: Primary}); got != "only:1" {
		t.Fatalf("got %q", got)
	}
}

func TestSDAMUpdates(t *testing.T) {
	tp := testTopo(t, "a:1")
	tp.d.started.Store(false)
	a := tp.members["a:1"]

	prim := func(set int64, elect byte, hosts ...string) ServerDesc {
		d := descOf(t, bson.M{"setName": "rs0", "isWritablePrimary": true})
		d.SetVersion, d.HasElection = set, true
		d.ElectionID[0] = elect
		d.Hosts = hosts
		return d
	}
	if !tp.update(a, prim(1, 5, "a:1", "b:1", "c:1")) {
		t.Fatal("update dropped member")
	}
	// Hosts advertised by the primary are discovered.
	if len(tp.members) != 3 {
		t.Fatalf("discovery: %d members", len(tp.members))
	}
	// A new primary demotes the old one.
	b := tp.members["b:1"]
	tp.update(b, prim(1, 6, "a:1", "b:1", "c:1"))
	if tp.members["a:1"].desc.Type != Unknown || tp.members["b:1"].desc.Type != RSPrimary {
		t.Fatalf("a=%s b=%s", tp.members["a:1"].desc.Type, tp.members["b:1"].desc.Type)
	}
	// A primary with an older election is stale and ignored.
	c := tp.members["c:1"]
	tp.update(c, prim(1, 4, "a:1", "b:1", "c:1"))
	if tp.members["c:1"].desc.Type != Unknown {
		t.Fatalf("stale primary accepted: %s", tp.members["c:1"].desc.Type)
	}
	// Members the primary no longer lists are removed.
	tp.update(b, prim(1, 6, "a:1", "b:1"))
	if _, ok := tp.members["c:1"]; ok {
		t.Fatal("removed member still tracked")
	}
	// A member of another replica set is dropped.
	tp.update(a, descOf(t, bson.M{"setName": "other", "secondary": true}))
	if _, ok := tp.members["a:1"]; ok {
		t.Fatal("foreign member kept")
	}
}

func TestParseReadPref(t *testing.T) {
	doc := func(m bson.M) bsoncore.Document { return hello(t, m) }
	s, err := ParseReadPref(doc(bson.M{"mode": "secondaryPreferred", "maxStalenessSeconds": 120, "tags": bson.A{bson.M{"dc": "east"}, bson.M{}}}))
	if err != nil || s.Mode != SecondaryPreferred || s.MaxStaleness != 120*time.Second || len(s.Tags) != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, bad := range []bson.M{
		{"mode": "sideways"},
		{"mode": "secondary", "maxStalenessSeconds": 10},
		{"mode": "primary", "tags": bson.A{bson.M{"a": "b"}}},
		{},
	} {
		if _, err := ParseReadPref(doc(bad)); err == nil {
			t.Errorf("%v: expected error", bad)
		}
	}
}

func TestAddLabelsAndStatus(t *testing.T) {
	d := hello(t, bson.M{"ok": 0, "code": 10107, "errmsg": "x", "errorLabels": bson.A{"Other"}})
	st := Status(d)
	if st.OK || st.Code != 10107 || !IsNotPrimary(st.Code) || !st.HasLabel("Other") {
		t.Fatalf("%+v", st)
	}
	d2 := AddLabels(d, LabelRetryableWrite, "Other")
	st = Status(d2)
	if !st.HasLabel(LabelRetryableWrite) || len(st.Labels) != 2 {
		t.Fatalf("%+v", st)
	}
	wc := hello(t, bson.M{"ok": 1, "writeConcernError": bson.M{"code": 11602}})
	if st := Status(wc); !st.OK || st.Code != 11602 {
		t.Fatalf("%+v", st)
	}
}
