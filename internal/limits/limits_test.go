package limits

import (
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestOpsRateLimit(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	m := NewManager(&config.Config{Tenant: config.Tenant{Limits: config.Limits{OpsPerSec: 10, OpsBurst: 5}}}, c.now)
	ten := m.For("a")
	for i := 0; i < 5; i++ {
		rel, err := ten.Admit(10, true)
		if err != nil {
			t.Fatalf("op %d rejected: %v", i, err)
		}
		rel()
	}
	if _, err := ten.Admit(10, true); err == nil || err.Reason != ReasonOps {
		t.Fatalf("expected ops_rate rejection, got %v", err)
	}
	// Another tenant is unaffected.
	if _, err := m.For("b").Admit(10, true); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(300 * time.Millisecond) // 3 tokens
	for i := 0; i < 3; i++ {
		if _, err := ten.Admit(10, true); err != nil {
			t.Fatalf("after refill op %d: %v", i, err)
		}
	}
	if _, err := ten.Admit(10, true); err == nil {
		t.Fatal("bucket should be empty again")
	}
}

func TestBytesInFlightCursorsIndexesJS(t *testing.T) {
	c := &clock{time.Unix(1000, 0)}
	cfg := &config.Config{Tenant: config.Tenant{
		Limits:    config.Limits{BytesPerSec: 1000, MaxInFlight: 2, MaxOpenCursors: 2, MaxIndexes: 2, MaxCommandBytes: 500, JSPerSec: 1},
		Overrides: map[string]config.Limits{"big": {MaxInFlight: 5, DisableJS: true}},
	}}
	m := NewManager(cfg, c.now)
	ten := m.For("a")

	if _, err := ten.Admit(501, true); err == nil || err.Reason != ReasonCommand {
		t.Fatalf("command size: %v", err)
	}
	r1, err := ten.Admit(100, true)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := ten.Admit(100, true)
	if _, err := ten.Admit(100, true); err == nil || err.Reason != ReasonInFlight {
		t.Fatalf("in flight: %v", err)
	}
	r1()
	r2()
	if _, err := ten.Admit(100, true); err != nil {
		t.Fatal(err)
	}

	ten.CountReply(5000) // debt: next request must wait
	if _, err := ten.Admit(1, false); err == nil || err.Reason != ReasonBytes {
		t.Fatalf("bytes: %v", err)
	}

	ten.AddCursors(2)
	if err := ten.CheckCursor(); err == nil {
		t.Fatal("cursor cap not enforced")
	}
	ten.AddCursors(-1)
	if err := ten.CheckCursor(); err != nil {
		t.Fatal(err)
	}

	if err := ten.CheckIndexes([]string{"d.c#a", "d.c#b"}); err != nil {
		t.Fatal(err)
	}
	if err := ten.CheckIndexes([]string{"d.c#a"}); err != nil {
		t.Fatal("re-creating an existing index must not count")
	}
	if err := ten.CheckIndexes([]string{"d.c#c"}); err == nil {
		t.Fatal("index cap not enforced")
	}
	ten.ForgetIndex("d.c#a")
	if err := ten.CheckIndexes([]string{"d.c#c"}); err != nil {
		t.Fatal(err)
	}

	if err := ten.CheckJS(); err != nil {
		t.Fatal(err)
	}
	if err := ten.CheckJS(); err == nil || err.Reason != ReasonJSRate {
		t.Fatalf("js rate: %v", err)
	}
	big := m.For("big")
	if big.L.MaxInFlight != 5 || big.L.MaxOpenCursors != 2 {
		t.Fatalf("override merge wrong: %+v", big.L)
	}
	if err := big.CheckJS(); err == nil || err.Reason != ReasonJSDenied {
		t.Fatalf("js disabled: %v", err)
	}
	if err := ten.CheckResult(1); err != nil {
		t.Fatal(err)
	}
}
