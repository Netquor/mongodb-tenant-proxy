package config

import "testing"

func TestLimitsForMergesOverrides(t *testing.T) {
	c := &Config{Tenant: Tenant{
		Limits:    Limits{OpsPerSec: 100, MaxOpenCursors: 10, MaxTimeMSCap: 5000},
		Overrides: map[string]Limits{"big": {OpsPerSec: 1000, DisableJS: true}},
	}}
	if got := c.LimitsFor("small"); got.OpsPerSec != 100 || got.DisableJS {
		t.Fatalf("defaults: %+v", got)
	}
	got := c.LimitsFor("big")
	if got.OpsPerSec != 1000 || got.MaxOpenCursors != 10 || got.MaxTimeMSCap != 5000 || !got.DisableJS {
		t.Fatalf("override merge: %+v", got)
	}
}

func TestIDPolicyValidation(t *testing.T) {
	base := func() *Config { return &Config{Auth: Auth{Mode: "static", StaticTenant: "t"}} }
	for _, p := range []string{"", "native", "require-generated"} {
		c := base()
		c.Tenant.IDPolicy = p
		if err := c.finish(); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	c := base()
	c.Tenant.IDPolicy = "namespace"
	if err := c.finish(); err == nil {
		t.Error("namespace without the experimental flag must fail")
	}
	c.Tenant.ExperimentalNamespace = true
	if err := c.finish(); err != nil || !c.ChangeStreams.Disabled || !c.DisableViews {
		t.Errorf("namespace: err=%v cs-disabled=%v views-disabled=%v", err, c.ChangeStreams.Disabled, c.DisableViews)
	}
	c = base()
	c.Tenant.IDPolicy = "nonsense"
	if err := c.finish(); err == nil {
		t.Error("unknown policy accepted")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load("../../proxy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant.IDPolicy != "require-generated" || c.LimitsFor("acme").OpsPerSec != 5000 || c.LimitsFor("x").OpsPerSec != 500 {
		t.Fatalf("unexpected example config: %+v", c.Tenant)
	}
}
