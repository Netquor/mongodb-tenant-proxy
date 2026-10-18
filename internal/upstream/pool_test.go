package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// fakeMongod answers every command with ok:1 (hello as a standalone).
type fakeMongod struct {
	ln       net.Listener
	accepted atomic.Int64
	live     atomic.Int64
	mu       sync.Mutex
	conns    []net.Conn
}

func startFake(t *testing.T) *fakeMongod { return startFakeTLS(t, nil) }

func startFakeTLS(t *testing.T, tc *tls.Config) *fakeMongod {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMongod{ln: ln}
	if tc != nil {
		ln = tls.NewListener(ln, tc)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			f.live.Add(1)
			f.mu.Lock()
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			go func() {
				defer f.live.Add(-1)
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					h, _, err := wire.ReadFrame(r, 1<<20)
					if err != nil {
						return
					}
					body := bsoncore.BuildDocument(nil,
						bsoncore.AppendBooleanElement(nil, "isWritablePrimary", true),
						bsoncore.AppendInt32Element(nil, "maxWireVersion", 17),
						bsoncore.AppendInt32Element(nil, "ok", 1))
					m := wire.Msg{Body: body}
					if wire.WriteFrame(c, 1, h.RequestID, wire.OpMsg, m.Encode()) != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeMongod) killAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns {
		c.Close()
	}
}

func newTestDialer(t *testing.T, f *fakeMongod, mut func(*config.Config)) *Dialer {
	t.Helper()
	cfg := &config.Config{Upstream: config.Upstream{
		Hosts:             []config.Host{{Addr: f.ln.Addr().String()}},
		HeartbeatInterval: "200ms",
		Pool:              config.Pool{MaxSize: 2, WaitTimeout: "300ms"},
	}}
	cfg.MaxMessageBytes = 1 << 20
	if mut != nil {
		mut(cfg)
	}
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func TestPoolBoundsAndReuse(t *testing.T) {
	f := startFake(t)
	d := newTestDialer(t, f, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := d.Select(ctx, Selector{Mode: Primary})
	if err != nil {
		t.Fatal(err)
	}
	c1, err := d.Checkout(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := d.Checkout(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	// The pool is full: a third checkout waits and times out.
	if _, err := d.Checkout(ctx, addr); err != ErrPoolTimeout {
		t.Fatalf("expected pool timeout, got %v", err)
	}
	// A release unblocks a waiter and the connection is reused, not redialed.
	got := make(chan *Conn, 1)
	go func() {
		c, _ := d.Checkout(ctx, addr)
		got <- c
	}()
	time.Sleep(50 * time.Millisecond)
	d.Release(c1)
	c3 := <-got
	if c3 != c1 {
		t.Fatal("expected the released connection to be reused")
	}
	d.Release(c2)
	d.Release(c3)
	if st := d.Stats(); st.PoolConnsOpened != 2 || st.Members[0].InUse != 0 || st.Members[0].Idle != 2 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPoolDiscardsDeadAndIdle(t *testing.T) {
	f := startFake(t)
	d := newTestDialer(t, f, func(c *config.Config) { c.Upstream.Pool.IdleTimeout = "300ms" })
	ctx := context.Background()
	addr, _ := d.Select(ctx, Selector{Mode: Primary})
	c, err := d.Checkout(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	d.Release(c)
	// Idle connections are reaped.
	deadline := time.Now().Add(3 * time.Second)
	for d.Stats().Members[0].Idle != 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle connection never reaped")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// A connection the server dropped while idle is detected at checkout.
	c, err = d.Checkout(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	d.Release(c)
	c.pool.mu.Lock()
	c.lastUsed = time.Now().Add(-2 * time.Second)
	c.pool.mu.Unlock()
	f.killAll()
	time.Sleep(100 * time.Millisecond)
	c2, err := d.Checkout(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if c2 == c {
		t.Fatal("dead connection was handed out")
	}
	if _, err := d.RunCommand(c2, "admin", bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "ping", 1))); err != nil {
		t.Fatalf("fresh connection unusable: %v", err)
	}
	d.Release(c2)
}

func TestNoConnectionLeakAfterClose(t *testing.T) {
	f := startFake(t)
	d := newTestDialer(t, f, func(c *config.Config) { c.Upstream.Pool.MaxSize = 8 })
	ctx := context.Background()
	addr, _ := d.Select(ctx, Selector{Mode: Primary})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c, err := d.Checkout(ctx, addr)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := d.RunCommand(c, "admin", bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "ping", 1))); err != nil {
					t.Error(err)
				}
				d.Release(c)
			}
		}()
	}
	wg.Wait()
	if st := d.Stats(); st.PoolConnsOpened > 8 || st.Members[0].InUse != 0 {
		t.Fatalf("pool exceeded its bound or leaked: %+v", st)
	}
	d.Close()
	deadline := time.Now().Add(3 * time.Second)
	for f.live.Load() != 0 || d.Stats().OpenConns != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("connections left open: server sees %d, dialer %d", f.live.Load(), d.Stats().OpenConns)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFailedMemberFlushesPool(t *testing.T) {
	f := startFake(t)
	d := newTestDialer(t, f, nil)
	ctx := context.Background()
	addr, _ := d.Select(ctx, Selector{Mode: Primary})
	c, _ := d.Checkout(ctx, addr)
	d.Release(c)
	d.NetworkError(addr, net.ErrClosed)
	if st := d.Stats(); st.Members[0].Idle != 0 {
		t.Fatalf("pool not flushed: %+v", st)
	}
	// The monitor recovers the member on its own.
	if _, err := d.Select(ctx, Selector{Mode: Primary}); err != nil {
		t.Fatal(err)
	}
}
