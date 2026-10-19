package test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// A proxy that fails to start (upstream unreachable, as in a crash-looping
// deployment) must give back everything it opened: dialer goroutines, the
// audit file, the tenant store. Regression test for proxy.New leaking them.
func TestStressFailedStartDoesNotLeak(t *testing.T) {
	defer stresstest.Watchdog(t, 3*time.Minute)()
	t.Cleanup(stresstest.NoLeak(t, 2))
	dir := t.TempDir()
	port := freePort(t) // nothing listens here once freePort has released it
	for i := 0; i < stresstest.N(10, 100); i++ {
		cfg := &config.Config{
			Listen:   "127.0.0.1:0",
			Upstream: config.Upstream{Addr: "127.0.0.1:" + itoa(port), ServerSelectionTimeout: "200ms", DialTimeout: "200ms"},
			Auth:     config.Auth{Mode: "appname"},
			Tenant:   config.Tenant{Field: "tenantId"},
			Audit:    config.Audit{Enabled: true, Sink: "http", URL: "http://127.0.0.1:1/audit"}, // the sink runs a shipper goroutine
			Store:    config.Store{Type: "file", Path: filepath.Join(dir, "tenants.json")},
		}
		if _, err := proxy.New(cfg, testLogger(t)); err == nil {
			t.Fatal("proxy.New succeeded against a closed port")
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
