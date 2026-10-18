package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/admin"
	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
)

type opsEnv struct {
	*env
	srv     *proxy.Server
	cfg     *config.Config
	cfgPath string
}

// setupOps starts mongod and a scram proxy whose config lives in a file, so
// that reloads can be exercised.
func setupOps(t *testing.T, mutate func(*config.Config)) *opsEnv {
	t.Helper()
	up := startMongod(t, false)
	dir := t.TempDir()
	cfg := &config.Config{
		Listen:          "127.0.0.1:0",
		Upstream:        config.Upstream{Addr: up},
		Auth:            config.Auth{Mode: "scram"},
		Tenant:          config.Tenant{Field: "tenantId"},
		MaxMessageBytes: 48 << 20,
		Store:           config.Store{Type: "file", Path: filepath.Join(dir, "tenants.json")},
		AdminAddr:       "127.0.0.1:0",
	}
	if mutate != nil {
		mutate(cfg)
	}
	cfg.Upstream.Addr = up
	cfg.Path = filepath.Join(dir, "proxy.json")
	writeCfg(t, cfg)
	loaded, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := proxy.New(loaded, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	e := &env{upstreamAddr: up, proxyAddr: ln.Addr().String()}
	e.direct = connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", up))
	t.Cleanup(func() { e.direct.Disconnect(context.Background()) })
	return &opsEnv{env: e, srv: srv, cfg: cfg, cfgPath: cfg.Path}
}

func writeCfg(t *testing.T, cfg *config.Config) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// scramClient returns a single-connection client for user/password.
func (e *opsEnv) scramClient(t *testing.T, user, pw string) *mongo.Client {
	t.Helper()
	uri := fmt.Sprintf("mongodb://%s:%s@%s/?authMechanism=SCRAM-SHA-256&authSource=admin", user, pw, e.proxyAddr)
	c, err := mongo.Connect(options.Client().ApplyURI(uri).SetMaxPoolSize(1).SetMinPoolSize(1).SetServerSelectionTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Disconnect(context.Background()) })
	return c
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	dl := time.Now().Add(10 * time.Second)
	for time.Now().Before(dl) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func connIDs(s *proxy.Server, tenant string) map[int64]bool {
	out := map[int64]bool{}
	for _, c := range s.Connections(tenant) {
		out[c.ID] = true
	}
	return out
}

func TestHotReload(t *testing.T) {
	ua, _ := auth.NewUser("alice", "tenant-a", "alice-pw")
	ub, _ := auth.NewUser("bob", "tenant-b", "bob-pw")
	e := setupOps(t, func(c *config.Config) { c.Auth.Users = []config.User{ua}; c.LogLevel = "info" })

	var lastLevel atomic.Value
	e.srv.OnReload(func(c *config.Config) { lastLevel.Store(c.LogLevel) })

	alice := e.scramClient(t, "alice", "alice-pw")
	coll := alice.Database("s").Collection("c")
	_, err := coll.InsertOne(ctx(t), bson.M{"n": 1})
	must(t, err)
	before := connIDs(e.srv, "tenant-a")
	if len(before) != 1 {
		t.Fatalf("expected 1 live connection, got %v", before)
	}

	// 1. new user appears without touching alice's connection; log level hook runs.
	e.cfg.Auth.Users = []config.User{ua, ub}
	e.cfg.LogLevel = "debug"
	writeCfg(t, e.cfg)
	if _, err := e.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	if lastLevel.Load() != "debug" {
		t.Fatal("log level hook not called")
	}
	bob := e.scramClient(t, "bob", "bob-pw")
	_, err = bob.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"n": 2})
	must(t, err)
	_, err = coll.InsertOne(ctx(t), bson.M{"n": 3})
	must(t, err)
	after := connIDs(e.srv, "tenant-a")
	for id := range before {
		if !after[id] {
			t.Fatal("alice's connection was dropped by reload")
		}
	}

	// 2. an invalid file is rejected and the previous config stays in force.
	must(t, os.WriteFile(e.cfgPath, []byte(`{"auth":{"mode":"bogus"}`), 0o600))
	if _, err := e.srv.Reload(); err == nil {
		t.Fatal("invalid config accepted")
	}
	_, err = bob.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"n": 4})
	must(t, err)

	// 3. deny list and databases apply to live connections.
	e.cfg.DenyCommands = []string{"insert"}
	writeCfg(t, e.cfg)
	if _, err := e.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	_, err = coll.InsertOne(ctx(t), bson.M{"n": 5})
	mustFail(t, err, "insert after denyCommands reload")
	if n := count(t, coll, bson.M{}); n != 2 {
		t.Fatalf("reads must keep working, saw %d docs", n)
	}

	// 4. a tenant disabled in the file is disconnected, and cannot log back in.
	e.cfg.DenyCommands = nil
	e.cfg.Tenants = []config.TenantEntry{{ID: "tenant-a", Disabled: true}}
	writeCfg(t, e.cfg)
	res, err := e.srv.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RestartRequired) != 0 {
		t.Fatalf("unexpected restart-required: %v", res.RestartRequired)
	}
	waitFor(t, "tenant-a connections to be dropped", func() bool { return len(e.srv.Connections("tenant-a")) == 0 })
	bad := connectTimeout(t, fmt.Sprintf("mongodb://alice:alice-pw@%s/?authMechanism=SCRAM-SHA-256&authSource=admin", e.proxyAddr), 3*time.Second)
	_, err = bad.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"x": 1})
	bad.Disconnect(context.Background())
	mustFail(t, err, "login to disabled tenant")
	_, err = bob.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"n": 6})
	must(t, err) // other tenants unaffected

	// 5. re-enable and non-reloadable settings are reported, not applied.
	e.cfg.Tenants = nil
	e.cfg.Listen = "127.0.0.1:9"
	writeCfg(t, e.cfg)
	res, err = e.srv.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RestartRequired) != 1 || res.RestartRequired[0] != "listen" {
		t.Fatalf("restartRequired = %v", res.RestartRequired)
	}
	alice2 := e.scramClient(t, "alice", "alice-pw")
	_, err = alice2.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"n": 7})
	must(t, err)
}

func TestAdminAPIAuditAndMetrics(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	seed, _ := auth.NewUser("seed", "seed-tenant", "seed-pw")
	e := setupOps(t, func(c *config.Config) {
		c.Auth.Users = []config.User{seed}
		c.Audit = config.Audit{Enabled: true, Sink: "file", Path: auditPath, SampleReads: 1}
		c.Admin = config.Admin{Token: "0123456789abcdef-token"}
	})
	adm, err := admin.New(e.srv, e.cfg.Admin)
	must(t, err)
	hs := httptest.NewServer(adm.Handler())
	defer hs.Close()

	call := func(method, path, body string, want int) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(method, hs.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer 0123456789abcdef-token")
		resp, err := http.DefaultClient.Do(req)
		must(t, err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, resp.StatusCode, want, b)
		}
		out := map[string]any{}
		json.Unmarshal(b, &out)
		return out
	}

	call("POST", "/v1/tenants", `{"id":"dyn","maxConns":10}`, 201)
	cr := call("POST", "/v1/tenants/dyn/users", `{"username":"dora"}`, 201)
	pw, _ := cr["password"].(string)
	if pw == "" {
		t.Fatalf("no generated password: %v", cr)
	}

	dora := e.scramClient(t, "dora", pw)
	coll := dora.Database("s").Collection("c")
	_, err = coll.InsertOne(ctx(t), bson.M{"note": "SECRET_VALUE_42"})
	must(t, err)
	if n := count(t, coll, bson.M{"note": "SECRET_VALUE_42"}); n != 1 {
		t.Fatalf("count %d", n)
	}
	_, err = coll.Database().Client().Database("admin").Collection("x").InsertOne(ctx(t), bson.M{"a": 1})
	mustFail(t, err, "admin db is denied")
	_, _ = coll.Database().RunCommand(ctx(t), bson.D{{Key: "dropDatabase", Value: 1}}).Raw()
	_, _ = coll.Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "note", Value: 1}}})

	conns := call("GET", "/v1/tenants/dyn/connections", "", 200)["connections"].([]any)
	if len(conns) != 1 {
		t.Fatalf("connections: %v", conns)
	}
	st := call("GET", "/v1/tenants/dyn/stats", "", 200)
	if st["connections"].(float64) != 1 || st["denials"].(float64) < 1 {
		t.Fatalf("stats: %v", st)
	}

	// metrics carry the tenant label and keep the legacy series
	rec := httptest.NewRecorder()
	e.srv.M.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	m := rec.Body.String()
	for _, want := range []string{`mtp_tenant_commands_total{tenant="dyn",command="insert",outcome="ok"} 1`, `mtp_tenant_connections_active{tenant="dyn"} 1`, `mtp_commands_total{command="insert",outcome="ok"}`, "mtp_tenant_command_duration_seconds_count{tenant=\"dyn\"}"} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	// kill the single connection through the API; the driver reconnects.
	id := int64(conns[0].(map[string]any)["id"].(float64))
	call("DELETE", fmt.Sprintf("/v1/connections/%d", id), "", 204)
	waitFor(t, "killed connection to go away", func() bool { return !connIDs(e.srv, "dyn")[id] })

	// disabling the tenant disconnects it and blocks new logins
	call("POST", "/v1/tenants/dyn/disable", "", 200)
	waitFor(t, "disable to drop connections", func() bool { return len(e.srv.Connections("dyn")) == 0 })
	bad := connectTimeout(t, fmt.Sprintf("mongodb://dora:%s@%s/?authMechanism=SCRAM-SHA-256&authSource=admin", pw, e.proxyAddr), 3*time.Second)
	_, err = bad.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"x": 1})
	bad.Disconnect(context.Background())
	mustFail(t, err, "login to disabled tenant")
	call("POST", "/v1/tenants/dyn/enable", "", 200)
	again := e.scramClient(t, "dora", pw)
	_, err = again.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"n": 2})
	must(t, err)

	// deleting the user disconnects it
	call("DELETE", "/v1/tenants/dyn/users/dora", "", 204)
	waitFor(t, "user removal to drop connections", func() bool { return len(e.srv.Connections("dyn")) == 0 })

	e.srv.Audit().Close()
	raw, err := os.ReadFile(auditPath)
	must(t, err)
	log := string(raw)
	if strings.Contains(log, "SECRET_VALUE_42") || strings.Contains(log, pw) {
		t.Fatal("audit log leaks document values or passwords")
	}
	types := map[string]int{}
	corr := true
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		types[ev["type"].(string)]++
		if strings.HasPrefix(ev["type"].(string), "command.") && ev["corr"] == nil {
			corr = false
		}
	}
	for _, want := range []string{"connect", "disconnect", "auth.success", "auth.failure", "command.write", "command.read", "command.denied", "command.ddl", "admin.action", "connection.killed"} {
		if types[want] == 0 {
			t.Errorf("audit log has no %q events (got %v)", want, types)
		}
	}
	if !corr {
		t.Error("command event without correlation id")
	}
}

func TestAdminAuthRequired(t *testing.T) {
	e := setupOps(t, func(c *config.Config) {
		u, _ := auth.NewUser("u", "t", "p")
		c.Auth.Users = []config.User{u}
		c.Admin = config.Admin{Token: "0123456789abcdef-token"}
	})
	adm, err := admin.New(e.srv, e.cfg.Admin)
	must(t, err)
	hs := httptest.NewServer(adm.Handler())
	defer hs.Close()
	for _, h := range []string{"", "Bearer wrong", "Basic 0123456789abcdef-token"} {
		req, _ := http.NewRequest("GET", hs.URL+"/v1/tenants", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		resp, err := http.DefaultClient.Do(req)
		must(t, err)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("auth %q = %d", h, resp.StatusCode)
		}
	}
	if _, err := admin.New(e.srv, config.Admin{}); err == nil {
		t.Fatal("admin without credentials must be refused")
	}
}
