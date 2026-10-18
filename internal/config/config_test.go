package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func load(t *testing.T, js string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMultiHostURI(t *testing.T) {
	c := load(t, `{"auth":{"mode":"appname"},"upstream":{"uri":"mongodb://u:p%40ss@a:1,b,[::1]:3/?replicaSet=rs0&authSource=x&tls=true&heartbeatFrequencyMS=250&maxPoolSize=7&directConnection=false"}}`)
	u := c.Upstream
	if len(u.Hosts) != 3 || u.Hosts[0].Addr != "a:1" || u.Hosts[1].Addr != "b:27017" || u.Hosts[2].Addr != "[::1]:3" {
		t.Fatalf("hosts %+v", u.Hosts)
	}
	if u.Username != "u" || u.Password != "p@ss" || u.AuthSource != "x" || !u.TLS || u.ReplicaSet != "rs0" {
		t.Fatalf("%+v", u)
	}
	if u.Heartbeat() != 250*time.Millisecond || u.PoolMaxSize() != 7 || u.Direct() {
		t.Fatalf("heartbeat %s pool %d direct %v", u.Heartbeat(), u.PoolMaxSize(), u.Direct())
	}
}

func TestDirectDefaults(t *testing.T) {
	c := load(t, `{"auth":{"mode":"appname"},"upstream":{"addr":"h:1"}}`)
	if !c.Upstream.Direct() || !c.Upstream.Pooled() || c.Upstream.PoolMaxSize() != 100 {
		t.Fatalf("%+v", c.Upstream)
	}
	c = load(t, `{"auth":{"mode":"appname"},"upstream":{"hosts":["a:1","b:2"]}}`)
	if c.Upstream.Direct() {
		t.Fatal("two hosts must not be direct")
	}
	c = load(t, `{"auth":{"mode":"appname"},"upstream":{"pool":{"mode":"dedicated"}}}`)
	if c.Upstream.Pooled() || c.Upstream.Hosts[0].Addr != "localhost:27017" {
		t.Fatalf("%+v", c.Upstream)
	}
}

func TestHostObjects(t *testing.T) {
	c := load(t, `{"auth":{"mode":"appname"},"upstream":{"hosts":["a:1",{"addr":"b:2","tls":true,"caFile":"/ca.pem","serverName":"b.internal"}]}}`)
	h := c.Upstream.Hosts
	if h[0].Addr != "a:1" || h[1].Addr != "b:2" || h[1].TLS == nil || !*h[1].TLS || h[1].ServerName != "b.internal" {
		t.Fatalf("%+v", h)
	}
}

func TestBadPoolMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(`{"auth":{"mode":"appname"},"upstream":{"pool":{"mode":"sideways"}}}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error")
	}
}
