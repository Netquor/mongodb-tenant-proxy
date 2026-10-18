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

	e := &env{upstreamAddr: up, proxyAddr: ln.Addr().String()}
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
