package test

// Shared plumbing for the attack_*_test.go files: a proxy whose logs are
// captured (so a recovered panic fails the test), raw wire clients, and a
// heap sampler for "does not allocate unboundedly" assertions.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// atkLog collects everything the proxy logs.
type atkLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *atkLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *atkLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// atkEnv is a proxy plus its captured log.
type atkEnv struct {
	*env
	log *atkLog
	cfg *config.Config
}

// atkSetup starts mongod and a proxy with a captured debug log. wrapLn may
// replace the listener (to inject accept errors).
func atkSetup(t *testing.T, mutate func(*config.Config), wrapLn func(net.Listener) net.Listener) *atkEnv {
	t.Helper()
	return atkSetupAuth(t, false, mutate, wrapLn)
}

// atkSetupAuth is atkSetup with an optionally auth-enabled upstream (the
// proxy then logs in with upstreamPassword).
func atkSetupAuth(t *testing.T, withAuth bool, mutate func(*config.Config), wrapLn func(net.Listener) net.Listener) *atkEnv {
	t.Helper()
	up := startMongod(t, withAuth)
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
	lg := &atkLog{}
	log := slog.New(slog.NewTextHandler(lg, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := proxy.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if wrapLn != nil {
		ln = wrapLn(ln)
	}
	c, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(c, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	e := &env{upstreamAddr: up, proxyAddr: addr, srv: srv}
	e.direct = connect(t, directURI)
	t.Cleanup(func() { e.direct.Disconnect(context.Background()) })
	return &atkEnv{env: e, log: lg, cfg: cfg}
}

// noPanics fails the test if a request handler panicked (the proxy recovers
// those, but a panic on hostile input is still a bug).
func (e *atkEnv) noPanics(t *testing.T) {
	t.Helper()
	if s := e.log.String(); strings.Contains(s, "panic while handling request") {
		i := strings.Index(s, "panic while handling request")
		t.Fatalf("proxy recovered from a panic:\n%s", s[i:min(len(s), i+2000)])
	}
}

// alive proves the proxy still serves a well-behaved tenant.
func (e *atkEnv) alive(t *testing.T, tenant string) {
	t.Helper()
	cl := e.tenant(t, tenant)
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := cl.Database("atk").Collection("alive").InsertOne(c, bson.M{"t": time.Now().UnixNano()}); err != nil {
		t.Fatalf("proxy stopped serving %s: %v", tenant, err)
	}
	e.noPanics(t)
}

// ---- raw wire client ----------------------------------------------------------

type atkRaw struct {
	t  testing.TB
	nc net.Conn
	br *bufio.Reader
	id int32
}

func (e *env) atkDial(t testing.TB) *atkRaw {
	t.Helper()
	nc, err := net.Dial("tcp", e.proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	return &atkRaw{t: t, nc: nc, br: bufio.NewReader(nc)}
}

// atkDialTenant dials and completes the appName hello.
func (e *env) atkDialTenant(t testing.TB, tenant string) *atkRaw {
	t.Helper()
	r := e.atkDial(t)
	res := r.cmd("admin", bson.D{{Key: "hello", Value: 1}, {Key: "client", Value: bson.M{"application": bson.M{"name": tenant}}}})
	if !isOK(res) {
		t.Fatalf("hello as %q: %v", tenant, res)
	}
	return r
}

func atkFrame(length int32, reqID, respTo, op int32, body []byte) []byte {
	b := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(b[0:], uint32(length))
	binary.LittleEndian.PutUint32(b[4:], uint32(reqID))
	binary.LittleEndian.PutUint32(b[8:], uint32(respTo))
	binary.LittleEndian.PutUint32(b[12:], uint32(op))
	return append(b, body...)
}

func atkMsgFrame(flags uint32, sections ...[]byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, flags)
	for _, s := range sections {
		body = append(body, s...)
	}
	return atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body)
}

func atkKind0(d bson.D) []byte {
	b, _ := bson.Marshal(d)
	return append([]byte{0}, b...)
}

func atkCmdDoc(db string, cmd bson.D) bson.D { return append(cmd, bson.E{Key: "$db", Value: db}) }

func (r *atkRaw) write(b []byte) {
	r.t.Helper()
	r.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := r.nc.Write(b); err != nil {
		r.t.Fatalf("write: %v", err)
	}
}

// readMsg reads one reply and decodes its body document.
func (r *atkRaw) readMsg() (wire.Header, bson.M, error) {
	r.nc.SetReadDeadline(time.Now().Add(20 * time.Second))
	h, rb, err := wire.ReadFrame(r.br, 64<<20)
	if err != nil {
		return h, nil, err
	}
	if h.OpCode == wire.OpCompressed {
		var op int32
		op, _, rb, err = wire.Decompress(rb, 64<<20)
		if err != nil {
			return h, nil, err
		}
		h.OpCode = op
	}
	if h.OpCode == wire.OpReply {
		var out bson.M
		err = bson.Unmarshal(rb[20:], &out)
		return h, out, err
	}
	m, err := wire.ParseMsg(rb)
	if err != nil {
		return h, nil, err
	}
	var out bson.M
	err = bson.Unmarshal(m.Body, &out)
	return h, out, err
}

func (r *atkRaw) cmd(db string, cmd bson.D) bson.M {
	r.t.Helper()
	r.id++
	body := (&wire.Msg{Body: mustBSON(r.t, atkCmdDoc(db, cmd))}).Encode()
	r.write(atkFrame(int32(16+len(body)), r.id, 0, wire.OpMsg, body))
	h, out, err := r.readMsg()
	if err != nil {
		r.t.Fatalf("reply to %v: %v", cmd[0].Key, err)
	}
	if h.ResponseTo != r.id {
		r.t.Fatalf("responseTo = %d, want %d", h.ResponseTo, r.id)
	}
	return out
}

func mustBSON(t testing.TB, v any) bsoncore.Document {
	b, err := bson.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// closedWithin reports whether the peer closes the connection (EOF or reset)
// within d, discarding anything it sends first.
func (r *atkRaw) closedWithin(d time.Duration) bool {
	deadline := time.Now().Add(d)
	buf := make([]byte, 4096)
	for {
		r.nc.SetReadDeadline(deadline)
		_, err := r.nc.Read(buf)
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false
		}
		return true
	}
}

func atkCRC(frame []byte) []byte {
	return binary.LittleEndian.AppendUint32(nil, crc32.Checksum(frame, crc32.MakeTable(crc32.Castagnoli)))
}

// ---- memory ---------------------------------------------------------------------

// atkHeap samples HeapInuse while the test attacks, so a transient spike is
// caught as well as a leak.
type atkHeap struct {
	base uint64
	peak atomic.Uint64
	stop chan struct{}
	done chan struct{}
}

func atkWatchHeap() *atkHeap {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	h := &atkHeap{base: ms.HeapInuse, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(h.done)
		for {
			select {
			case <-h.stop:
				return
			case <-time.After(10 * time.Millisecond):
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapInuse > h.peak.Load() {
					h.peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	return h
}

// growth stops sampling and returns the largest growth over the baseline.
func (h *atkHeap) growth() uint64 {
	close(h.stop)
	<-h.done
	if p := h.peak.Load(); p > h.base {
		return p - h.base
	}
	return 0
}

func atkIsErr(res bson.M) bool { return !isOK(res) }

var _ = mongo.ErrNoDocuments
var _ = io.EOF
