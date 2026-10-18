package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) (*Config, error) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestOpsConfigValidation(t *testing.T) {
	ok := `{"auth":{"mode":"static","staticTenant":"t"},"adminAddr":":9103","store":{"type":"file","path":"x.json"},
	"metrics":{"tenantLabel":{"mode":"hash","hashBuckets":8}},"audit":{"enabled":true,"sink":"file","path":"a.log","sampleReads":0.5},
	"tenants":[{"id":"t","maxConns":2}],"logLevel":"warn"}`
	c, err := load(t, ok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Path == "" || c.AdminAddr != ":9103" || c.SlogLevel().String() != "WARN" {
		t.Fatalf("%+v", c)
	}
	for name, body := range map[string]string{
		"bad store":     `{"auth":{"mode":"static","staticTenant":"t"},"store":{"type":"redis"}}`,
		"bad label":     `{"auth":{"mode":"static","staticTenant":"t"},"metrics":{"tenantLabel":{"mode":"x"}}}`,
		"bad sink":      `{"auth":{"mode":"static","staticTenant":"t"},"audit":{"enabled":true,"sink":"x"}}`,
		"file no path":  `{"auth":{"mode":"static","staticTenant":"t"},"audit":{"enabled":true,"sink":"file"}}`,
		"bad sample":    `{"auth":{"mode":"static","staticTenant":"t"},"audit":{"enabled":true,"sink":"stdout","sampleReads":2}}`,
		"dup tenant":    `{"auth":{"mode":"static","staticTenant":"t"},"tenants":[{"id":"a"},{"id":"a"}]}`,
		"bad log level": `{"auth":{"mode":"static","staticTenant":"t"},"logLevel":"loud"}`,
		"bad refresh":   `{"auth":{"mode":"static","staticTenant":"t"},"store":{"refreshInterval":"soon"}}`,
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: empty error", name)
		}
	}
}
