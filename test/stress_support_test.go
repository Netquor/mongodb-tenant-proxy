package test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// panicGuard wraps the proxy logger. conn.safely recovers handler panics and
// closes the connection, which would otherwise show up only as a dropped
// client; any test using testLogger fails if that log line ever appears, and
// so do error-level records the proxy emits for internal failures.
type panicGuard struct {
	inner  slog.Handler
	panics *atomic.Int64
	first  *sync.Once
	msg    *atomic.Value
}

func (g panicGuard) Enabled(ctx context.Context, l slog.Level) bool { return g.inner.Enabled(ctx, l) }
func (g panicGuard) Handle(ctx context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "panic while handling request") {
		g.panics.Add(1)
		g.first.Do(func() {
			var sb strings.Builder
			r.Attrs(func(a slog.Attr) bool { sb.WriteString(a.Key + "=" + a.Value.String() + "\n"); return true })
			g.msg.Store(sb.String())
		})
	}
	return g.inner.Handle(ctx, r)
}
func (g panicGuard) WithAttrs(a []slog.Attr) slog.Handler {
	return panicGuard{g.inner.WithAttrs(a), g.panics, g.first, g.msg}
}
func (g panicGuard) WithGroup(n string) slog.Handler {
	return panicGuard{g.inner.WithGroup(n), g.panics, g.first, g.msg}
}

// testLogger returns the proxy's logger for a test: discarded (or printed with
// MTP_TEST_LOG), with a cleanup check that the "panic while handling request"
// line was never logged.
func testLogger(t testing.TB) *slog.Logger {
	var inner slog.Handler = slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})
	if os.Getenv("MTP_TEST_LOG") != "" {
		inner = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	}
	g := panicGuard{inner, new(atomic.Int64), new(sync.Once), new(atomic.Value)}
	t.Cleanup(func() {
		if n := g.panics.Load(); n > 0 {
			m, _ := g.msg.Load().(string)
			t.Errorf("proxy recovered %d handler panic(s) (conn.safely masked them); first:\n%s", n, m)
		}
	})
	return slog.New(g)
}

func eventually(t testing.TB, d time.Duration, what string, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !ok() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---- lightweight raw client (goroutine-safe error returns, no t.Fatal) -------

// sc speaks OP_MSG to the proxy. Unlike rawConn it never calls t.Fatal, so it
// can be used from worker goroutines, and it can be dropped abruptly.
type sc struct {
	nc net.Conn
	br *bufio.Reader
	id int32
}

func dialSC(addr, tenant string) (*sc, error) {
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c := &sc{nc: nc, br: bufio.NewReader(nc)}
	res, err := c.run("admin", bson.D{{Key: "hello", Value: 1},
		{Key: "client", Value: bson.M{"application": bson.M{"name": tenant}}}})
	if err != nil || !isOK(res) {
		nc.Close()
		if err == nil {
			err = fmt.Errorf("hello: %v", res)
		}
		return nil, err
	}
	return c, nil
}

func (c *sc) close() { c.nc.Close() }

// run sends one command and returns the reply. A command error (ok:0) is
// returned as a normal document; only transport/protocol failures are errors.
func (c *sc) run(db string, cmd bson.D) (bson.M, error) {
	c.nc.SetDeadline(time.Now().Add(30 * time.Second))
	body, err := bson.Marshal(append(append(bson.D{}, cmd...), bson.E{Key: "$db", Value: db}))
	if err != nil {
		return nil, err
	}
	c.id++
	if err := wire.WriteFrame(c.nc, c.id, 0, wire.OpMsg, (&wire.Msg{Body: body}).Encode()); err != nil {
		return nil, err
	}
	_, rb, err := wire.ReadFrame(c.br, 48<<20)
	if err != nil {
		return nil, err
	}
	m, err := wire.ParseMsg(rb)
	if err != nil {
		return nil, err
	}
	var out bson.M
	dec := bson.NewDecoder(bson.NewDocumentReader(bytes.NewReader(m.Body)))
	dec.DefaultDocumentM() // nested documents as bson.M, not bson.D
	return out, dec.Decode(&out)
}

// cursorOf extracts (id, firstBatch/nextBatch) from a cursor reply.
func cursorOf(res bson.M) (id int64, batch []bson.M, ok bool) {
	cur, isDoc := res["cursor"].(bson.M)
	if !isDoc {
		return 0, nil, false
	}
	id, _ = cur["id"].(int64)
	for _, k := range []string{"firstBatch", "nextBatch"} {
		if a, isArr := cur[k].(bson.A); isArr {
			for _, d := range a {
				if m, isM := d.(bson.M); isM {
					batch = append(batch, m)
				}
			}
		}
	}
	return id, batch, true
}

// workers runs n copies of f concurrently and waits for them.
func workers(n int, f func(i int)) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); f(i) }(i)
	}
	wg.Wait()
}

// serverStatus reads a few upstream counters through the direct client.
func upstreamGauges(t testing.TB, direct *mongo.Client) (conns, cursors int64) {
	t.Helper()
	var ss struct {
		Connections struct {
			Current int64 `bson:"current"`
		} `bson:"connections"`
		Metrics struct {
			Cursor struct {
				Open struct {
					Total int64 `bson:"total"`
				} `bson:"open"`
			} `bson:"cursor"`
		} `bson:"metrics"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := direct.Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&ss); err != nil {
		t.Fatal(err)
	}
	return ss.Connections.Current, ss.Metrics.Cursor.Open.Total
}
