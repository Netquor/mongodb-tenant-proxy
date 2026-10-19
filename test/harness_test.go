package test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
)

// env is a real single-node replica set plus an in-process proxy in front of it.
type env struct {
	upstreamAddr string
	proxyAddr    string
	direct       *mongo.Client // bypasses the proxy
	srv          *proxy.Server
	rs           []string // replica-set members (setupRS only)
	stop         func()   // shuts the proxy down and waits for it (setupRS only)
}

func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startMongod launches a throwaway replica-set member.
func startMongod(t testing.TB, withAuth bool) (addr string) {
	t.Helper()
	// MTP_MONGOD_URI points at an already-running, initiated single-node
	// replica set (e.g. a CI service container) as host:port or mongodb://host:port.
	if u := os.Getenv("MTP_MONGOD_URI"); u != "" {
		if withAuth {
			t.Skip("auth-enabled upstream not supported with MTP_MONGOD_URI")
		}
		addr = strings.TrimSuffix(strings.TrimPrefix(u, "mongodb://"), "/")
		resetUpstream(t, addr)
		return addr
	}
	// MTP_MONGOD_BIN overrides the mongod binary looked up in PATH.
	binName := "mongod"
	if v := os.Getenv("MTP_MONGOD_BIN"); v != "" {
		binName = v
	}
	bin, err := exec.LookPath(binName)
	if err != nil {
		t.Skip(binName + " not found")
	}
	dir := t.TempDir()
	port := freePort(t)
	args := []string{"--dbpath", dir, "--port", fmt.Sprint(port), "--bind_ip", "127.0.0.1",
		"--replSet", "rs0", "--logpath", filepath.Join(dir, "mongod.log"), "--quiet"}
	if withAuth {
		kf := filepath.Join(dir, "keyfile")
		if err := os.WriteFile(kf, []byte("testkeyfilecontents0123456789AB"), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--auth", "--keyFile", kf)
	}
	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr = fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", addr))
	defer c.Disconnect(context.Background())
	for {
		if err := c.Ping(ctx, nil); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("mongod did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	cfg := bson.D{{Key: "replSetInitiate", Value: bson.D{
		{Key: "_id", Value: "rs0"},
		{Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: addr}}}},
	}}}
	if err := c.Database("admin").RunCommand(ctx, cfg).Err(); err != nil {
		t.Fatal(err)
	}
	for {
		var res bson.M
		if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&res); err == nil && res["isWritablePrimary"] == true {
			if withAuth {
				err := c.Database("admin").RunCommand(ctx, bson.D{
					{Key: "createUser", Value: "proxy"}, {Key: "pwd", Value: upstreamPassword},
					{Key: "roles", Value: bson.A{"root"}},
				}).Err()
				if err != nil {
					t.Fatal(err)
				}
			}
			return addr
		}
		if ctx.Err() != nil {
			t.Fatal("replica set never elected a primary")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func connect(t testing.TB, uri string) *mongo.Client { return connectTimeout(t, uri, 20*time.Second) }

func connectTimeout(t testing.TB, uri string, d time.Duration) *mongo.Client {
	t.Helper()
	o := options.Client().ApplyURI(uri).SetServerSelectionTimeout(d)
	c, err := mongo.Connect(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setup starts mongod and a proxy (appName auth) and returns the environment.
func setup(t testing.TB, mutate func(*config.Config)) *env { return setupWith(t, false, mutate) }

const upstreamPassword = "upstream-pw-1"

func setupWith(t testing.TB, withAuth bool, mutate func(*config.Config)) *env {
	t.Helper()
	up := startMongod(t, withAuth)
	if strings.Contains(t.Name(), "ChangeStream") && upstreamWireVersion(t, up) < 17 {
		t.Skip("change streams need MongoDB 6.0+ (collection pre/post images)")
	}
	cfg := &config.Config{
		Listen:   "127.0.0.1:0",
		Upstream: config.Upstream{Addr: up},
		Auth:     config.Auth{Mode: "appname"},
		Tenant:   config.Tenant{Field: "tenantId"},
	}
	// MTP_TEST_POOL_MODE=dedicated runs the whole suite in dedicated mode.
	cfg.Upstream.Pool.Mode = os.Getenv("MTP_TEST_POOL_MODE")
	if mutate != nil {
		mutate(cfg)
	}
	cfg.Upstream.Addr = up
	directURI := fmt.Sprintf("mongodb://%s/?directConnection=true", up)
	if withAuth {
		cfg.Upstream.Username, cfg.Upstream.Password = "proxy", upstreamPassword
		directURI = fmt.Sprintf("mongodb://proxy:%s@%s/?directConnection=true&authSource=admin", upstreamPassword, up)
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 48 << 20
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("MTP_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv, err := proxy.New(cfg, log)
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

	e := &env{upstreamAddr: up, proxyAddr: ln.Addr().String(), srv: srv}
	e.direct = connect(t, directURI)
	t.Cleanup(func() { e.direct.Disconnect(context.Background()) })
	return e
}

// tenant returns a client whose connections are bound to the tenant.
func (e *env) tenant(t testing.TB, id string) *mongo.Client {
	t.Helper()
	c := connect(t, fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, id))
	t.Cleanup(func() { c.Disconnect(context.Background()) })
	return c
}

// ---- three-node replica set -------------------------------------------------

// rsTags are the member tags of the replica set started by startReplSet.
var rsTags = []string{"a", "b", "c"}

// startMongodAt launches one replica-set member on a fixed port. The returned
// stop function kills it.
func startMongodAt(t testing.TB, set string, port int) (stop func()) {
	t.Helper()
	bin, err := exec.LookPath("mongod")
	if err != nil {
		t.Skip("mongod not found in PATH")
	}
	dir := t.TempDir()
	cmd := exec.Command(bin, "--dbpath", dir, "--port", fmt.Sprint(port), "--bind_ip", "127.0.0.1",
		"--replSet", set, "--logpath", filepath.Join(dir, "mongod.log"), "--quiet")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() { once.Do(func() { cmd.Process.Kill(); cmd.Wait() }) }
	t.Cleanup(stop)
	return stop
}

// startReplSet starts a 3-member replica set "rs0" (member 0 has the highest
// priority so it is the initial primary) and returns the member addresses.
func startReplSet(t testing.TB) []string {
	t.Helper()
	var addrs []string
	var members bson.A
	for i := 0; i < 3; i++ {
		port := freePort(t)
		startMongodAt(t, "rs0", port)
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		addrs = append(addrs, addr)
		prio := 1
		if i == 0 {
			prio = 2
		}
		members = append(members, bson.D{{Key: "_id", Value: i}, {Key: "host", Value: addr}, {Key: "priority", Value: prio},
			{Key: "tags", Value: bson.D{{Key: "dc", Value: rsTags[i]}}}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, a := range addrs { // wait until each mongod is listening
		for {
			if nc, err := net.DialTimeout("tcp", a, time.Second); err == nil {
				nc.Close()
				break
			}
			if ctx.Err() != nil {
				t.Fatal("mongod did not start")
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	c := connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", addrs[0]))
	defer c.Disconnect(context.Background())
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetInitiate", Value: bson.D{
		{Key: "_id", Value: "rs0"}, {Key: "members", Value: members}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	// Wait for a primary and two caught-up secondaries.
	for {
		var st struct {
			Members []struct {
				StateStr string `bson:"stateStr"`
			} `bson:"members"`
		}
		if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&st); err == nil && len(st.Members) == 3 {
			p, s := 0, 0
			for _, m := range st.Members {
				switch m.StateStr {
				case "PRIMARY":
					p++
				case "SECONDARY":
					s++
				}
			}
			if p == 1 && s == 2 {
				return addrs
			}
		}
		if ctx.Err() != nil {
			t.Fatal("replica set did not become healthy")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// setupRS starts a 3-node replica set and a proxy that discovers it from all
// three members.
//lint:ignore U1000 kept for the HA suites on sibling branches
func setupRS(t testing.TB, mutate func(*config.Config)) *env {
	t.Helper()
	return attachProxy(t, startReplSet(t), mutate)
}

// attachProxy starts a proxy in front of an existing replica set. env.stop
// shuts it down (and waits); it also runs at test cleanup.
func attachProxy(t testing.TB, addrs []string, mutate func(*config.Config)) *env {
	t.Helper()
	cfg := &config.Config{
		Listen: "127.0.0.1:0",
		Auth:   config.Auth{Mode: "appname"},
		Tenant: config.Tenant{Field: "tenantId"},
		Upstream: config.Upstream{
			ReplicaSet:        "rs0",
			HeartbeatInterval: "300ms",
		},
		MaxMessageBytes: 48 << 20,
	}
	for _, a := range addrs {
		cfg.Upstream.Hosts = append(cfg.Upstream.Hosts, config.Host{Addr: a})
	}
	if mutate != nil {
		mutate(cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("MTP_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv, err := proxy.New(cfg, log)
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
	var once sync.Once
	e := &env{upstreamAddr: addrs[0], proxyAddr: ln.Addr().String(), srv: srv, rs: addrs}
	e.stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(e.stop)
	e.direct = connect(t, fmt.Sprintf("mongodb://%s/?replicaSet=rs0", joinAddrs(addrs)))
	t.Cleanup(func() { e.direct.Disconnect(context.Background()) })
	return e
}

func joinAddrs(a []string) string {
	out := ""
	for i, s := range a {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// member connects straight to one replica-set member.
func (e *env) member(t testing.TB, i int) *mongo.Client {
	t.Helper()
	c := connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", e.rs[i]))
	t.Cleanup(func() { c.Disconnect(context.Background()) })
	return c
}

// profileOn turns on full profiling of db on a member so tests can count
// exactly which member served which operation.
func profileOn(t testing.TB, c *mongo.Client, db string) {
	t.Helper()
	if err := c.Database(db).RunCommand(context.Background(), bson.D{{Key: "profile", Value: 2}}).Err(); err != nil {
		t.Fatal(err)
	}
}

// profiled counts profiled operations of the given kind ("query", "getmore",
// "command", ...) on ns.
func profiled(t testing.TB, c *mongo.Client, db, ns, op string) int64 {
	t.Helper()
	n, err := c.Database(db).Collection("system.profile").CountDocuments(context.Background(), bson.M{"ns": ns, "op": op})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// primaryIndex returns the index in e.rs of the current primary.
func (e *env) primaryIndex(t testing.TB) int {
	t.Helper()
	for i := range e.rs {
		c := e.member(t, i)
		var h bson.M
		if err := c.Database("admin").RunCommand(context.Background(), bson.D{{Key: "hello", Value: 1}}).Decode(&h); err == nil && h["isWritablePrimary"] == true {
			return i
		}
	}
	return -1
}

// resetUpstream drops every non-system database so tests sharing a long-lived
// mongod (MTP_MONGOD_URI) start from a clean slate.
func resetUpstream(t testing.TB, addr string) {
	t.Helper()
	c := connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", addr))
	defer c.Disconnect(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	names, err := c.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		switch n {
		case "admin", "local", "config":
			continue
		}
		if err := c.Database(n).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func upstreamWireVersion(t testing.TB, addr string) int32 {
	t.Helper()
	c := connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", addr))
	defer c.Disconnect(context.Background())
	var res struct {
		MaxWireVersion int32 `bson:"maxWireVersion"`
	}
	if err := c.Database("admin").RunCommand(context.Background(), bson.D{{Key: "hello", Value: 1}}).Decode(&res); err != nil {
		t.Fatal(err)
	}
	return res.MaxWireVersion
}
