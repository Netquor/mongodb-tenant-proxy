package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func load(t *testing.T, js string) (*Config, error) {
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(js), 0o600)
	return Load(p)
}

const scramUser = `{"username":"a","tenantId":"t","salt":"c2FsdA==","iterations":4096,"storedKey":"a2V5","serverKey":"a2V5"}`

func TestModeAcceptsStringOrList(t *testing.T) {
	c, err := load(t, `{"auth":{"mode":"scram","users":[`+scramUser+`]}}`)
	if err != nil || !c.Auth.Mode.Has("scram") || len(c.Auth.Mode.List()) != 1 {
		t.Fatalf("string form: %v %v", c, err)
	}
	c, err = load(t, `{"clientTLS":{"certFile":"c","keyFile":"k","clientCAFile":"ca"},"auth":{"mode":["scram","x509"],
		"users":[`+scramUser+`],"x509":[{"subject":"CN=a","tenantId":"t"}]}}`)
	if err != nil || !c.Auth.Mode.Has("scram") || !c.Auth.Mode.Has("x509") {
		t.Fatalf("list form: %v", err)
	}
	b, _ := json.Marshal(c.Auth.Mode)
	if string(b) != `["scram","x509"]` {
		t.Fatalf("marshal = %s", b)
	}
}

func TestAuthValidation(t *testing.T) {
	tls := `"clientTLS":{"certFile":"c","keyFile":"k","clientCAFile":"ca"},`
	for name, tc := range map[string]struct{ js, want string }{
		"unknown mode":        {`{"auth":{"mode":"kerberos"}}`, "auth.mode"},
		"no mode":             {`{"auth":{}}`, "auth.mode"},
		"scram without users": {`{"auth":{"mode":"scram"}}`, "requires auth.users"},
		"sha1 without sha1":   {`{"auth":{"mode":"scram-sha-1","users":[` + scramUser + `]}}`, "sha1"},
		"appname combined":    {`{"auth":{"mode":["appname","scram"]}}`, "cannot be combined"},
		"x509 without rules":  {`{` + tls + `"auth":{"mode":"x509"}}`, "x509 rules"},
		"x509 without CA":     {`{"clientTLS":{"certFile":"c","keyFile":"k"},"auth":{"mode":"x509","x509":[{"subject":"CN=a","tenantId":"t"}]}}`, "clientCAFile"},
		"x509 without TLS":    {`{"auth":{"mode":"x509","x509":[{"subject":"CN=a","tenantId":"t"}]}}`, "clientCAFile"},
		"x509 rule empty":     {`{` + tls + `"auth":{"mode":"x509","x509":[{"tenantId":"t"}]}}`, "subject or san"},
		"oidc missing":        {`{"auth":{"mode":"oidc"}}`, "auth.oidc"},
		"oidc both jwks":      {`{"auth":{"mode":"oidc","oidc":{"issuer":"i","audience":"a","jwksFile":"f","jwksUri":"u"}}}`, "exactly one"},
		"bad compressor":      {`{"compressors":["lz4"],"auth":{"mode":"static","staticTenant":"t"}}`, "lz4"},
		"bad upstream comp":   {`{"upstream":{"compressors":["gzip"]},"auth":{"mode":"static","staticTenant":"t"}}`, "gzip"},
		"x509 upstream":       {`{"upstream":{"authMechanism":"MONGODB-X509","tls":true},"auth":{"mode":"static","staticTenant":"t"}}`, "certFile"},
		"bad upstream mech":   {`{"upstream":{"authMechanism":"PLAIN","username":"u"},"auth":{"mode":"static","staticTenant":"t"}}`, "unsupported"},
		"mech needs user":     {`{"upstream":{"authMechanism":"SCRAM-SHA-1"},"auth":{"mode":"static","staticTenant":"t"}}`, "username"},
	} {
		_, err := load(t, tc.js)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, tc.want)
		}
	}
	good := `{"upstream":{"uri":"mongodb://u:p@h:1/?authMechanism=SCRAM-SHA-1&compressors=zstd,snappy"},"compressors":["zstd"],"auth":{"mode":"static","staticTenant":"t"}}`
	c, err := load(t, good)
	if err != nil || c.Upstream.Mechanism() != "SCRAM-SHA-1" || len(c.Upstream.Compressors) != 2 {
		t.Fatalf("uri options not parsed: %+v %v", c, err)
	}
}
