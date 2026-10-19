package test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Slow, idle, half-open and flooding clients.

func TestAttackSlowloris(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.ConnLimits = config.ConnLimits{HandshakeTimeout: "1s", FrameTimeout: "1s"}
		c.IdleTimeout = "2s"
	}, nil)

	t.Run("silent connection is dropped at the handshake deadline", func(t *testing.T) {
		r := e.atkDial(t)
		start := time.Now()
		if !r.closedWithin(4 * time.Second) {
			t.Fatal("silent connection still open")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("took %v to drop a silent connection (handshakeTimeout 1s)", d)
		}
	})
	t.Run("partial header then silence", func(t *testing.T) {
		r := e.atkDial(t)
		r.write([]byte{0x30, 0, 0, 0, 1, 0})
		if !r.closedWithin(4 * time.Second) {
			t.Fatal("half-open connection still open")
		}
	})
	t.Run("header then body trickled byte by byte", func(t *testing.T) {
		r := e.atkDial(t)
		r.write(atkFrame(16+4096, 1, 0, wire.OpMsg, nil))
		done := make(chan bool, 1)
		go func() { done <- r.closedWithin(5 * time.Second) }()
		for i := 0; i < 20; i++ {
			if _, err := r.nc.Write([]byte{0}); err != nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if !<-done {
			t.Fatal("trickled frame kept the connection open past frameTimeout")
		}
	})
	t.Run("authenticated connection trickling a body", func(t *testing.T) {
		r := e.atkDialTenant(t, "tenant-a")
		r.write(atkFrame(16+4096, 1, 0, wire.OpMsg, nil))
		start := time.Now()
		for i := 0; i < 30 && time.Since(start) < 6*time.Second; i++ {
			if _, err := r.nc.Write([]byte{0}); err != nil {
				return // dropped: good
			}
			time.Sleep(300 * time.Millisecond)
		}
		if !r.closedWithin(time.Second) {
			t.Fatal("authenticated slow sender never dropped")
		}
	})
	t.Run("authenticated idle connection obeys idleTimeout", func(t *testing.T) {
		r := e.atkDialTenant(t, "tenant-a")
		if !r.closedWithin(5 * time.Second) {
			t.Fatal("idle connection survived idleTimeout")
		}
	})
	t.Run("pings do not keep an unauthenticated connection alive", func(t *testing.T) {
		r := e.atkDial(t)
		start := time.Now()
		for time.Since(start) < 4*time.Second {
			body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("admin", bson.D{{Key: "ping", Value: 1}}))}).Encode()
			if _, err := r.nc.Write(atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body)); err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !r.closedWithin(time.Second) {
			t.Fatal("unauthenticated pinger held its connection past the handshake deadline")
		}
	})
	e.alive(t, "tenant-good")
	e.noPanics(t)
}

// A client that sends a request and never reads the reply must not hold the
// proxy (and an upstream connection) for longer than the write timeout.
func TestAttackNeverReadsReply(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.ConnLimits = config.ConnLimits{WriteTimeout: "1s"}
		c.Upstream.Pool.MaxSize = 2
	}, nil)
	pad := make([]byte, 1<<20)
	for i := range pad {
		pad[i] = 'y'
	}
	var docs []any
	for i := 0; i < 30; i++ {
		docs = append(docs, bson.M{"i": i, "pad": string(pad)})
	}
	_, err := e.tenant(t, "tenant-a").Database("atk").Collection("slow").InsertMany(ctx(t), docs)
	must(t, err)

	// Four stalled readers on a pool of two: if they held upstream
	// connections indefinitely, the honest client below would starve.
	var stalled []*atkRaw
	for i := 0; i < 4; i++ {
		r := e.atkDialTenant(t, "tenant-a")
		if tc, ok := r.nc.(*net.TCPConn); ok {
			tc.SetReadBuffer(4096)
		}
		body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("atk", bson.D{{Key: "find", Value: "slow"}, {Key: "batchSize", Value: 30}}))}).Encode()
		r.write(atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body))
		stalled = append(stalled, r) // never read
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	e.alive(t, "tenant-b")
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("honest client waited %v behind stalled readers", d)
	}
	for _, r := range stalled {
		if !r.closedWithin(10 * time.Second) {
			t.Fatal("stalled reader never dropped")
		}
	}
}

func TestAttackConnectionCaps(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.ConnLimits = config.ConnLimits{MaxPreAuthPerIP: 5, MaxConnsPerIP: 12, HandshakeTimeout: "2s"}
		c.MaxConnsPerTenant = 3
	}, nil)

	t.Run("pre-auth flood from one address is capped", func(t *testing.T) {
		var held []*atkRaw
		rejected := 0
		for i := 0; i < 40; i++ {
			r := e.atkDial(t)
			held = append(held, r)
			time.Sleep(5 * time.Millisecond)
		}
		for _, r := range held {
			if r.closedWithin(100 * time.Millisecond) {
				rejected++
			}
		}
		if rejected < 30 {
			t.Fatalf("only %d of 40 flood connections were refused; want at least 30 (cap 5)", rejected)
		}
		// The handshake deadline then clears the survivors and the slots free up.
		for _, r := range held {
			r.closedWithin(4 * time.Second)
		}
		e.alive(t, "tenant-good")
	})

	t.Run("authenticated connections are not charged to the pre-auth cap", func(t *testing.T) {
		var conns []*atkRaw
		for i := 0; i < 3; i++ {
			conns = append(conns, e.atkDialTenant(t, "tenant-p"))
		}
		// More authenticated connections than the pre-auth cap (5) still fit.
		for i := 0; i < 5; i++ {
			conns = append(conns, e.atkDialTenant(t, "tenant-q"+string(rune('a'+i))))
		}
		if len(conns) != 8 {
			t.Fatal("setup")
		}
	})

	t.Run("per-tenant cap does not starve other tenants", func(t *testing.T) {
		var held []*atkRaw
		for i := 0; i < 3; i++ {
			held = append(held, e.atkDialTenant(t, "tenant-capped"))
		}
		r := e.atkDial(t)
		res := r.cmd("admin", bson.D{{Key: "hello", Value: 1}, {Key: "client", Value: bson.M{"application": bson.M{"name": "tenant-capped"}}}})
		if isOK(res) {
			t.Fatal("tenant exceeded maxConnsPerTenant")
		}
		e.alive(t, "tenant-other")
		for _, h := range held {
			h.nc.Close()
		}
		// Capacity returns once the tenant's connections close.
		deadline := time.Now().Add(5 * time.Second)
		for {
			r := e.atkDial(t)
			res := r.cmd("admin", bson.D{{Key: "hello", Value: 1}, {Key: "client", Value: bson.M{"application": bson.M{"name": "tenant-capped"}}}})
			if isOK(res) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("tenant slots never came back")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	t.Run("total per-address cap", func(t *testing.T) {
		var held []*atkRaw
		for i := 0; i < 12; i++ {
			held = append(held, e.atkDialTenant(t, "tenant-ip-"+string(rune('a'+i))))
		}
		r := e.atkDial(t)
		if !r.closedWithin(time.Second) {
			t.Fatal("connection beyond maxConnsPerIP was accepted")
		}
		for _, h := range held {
			h.nc.Close()
		}
	})
	e.noPanics(t)
}

// Memory cost of a connection flood: each connection announces a huge message
// and never delivers it.
func TestAttackFloodMemory(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.ConnLimits = config.ConnLimits{MaxPreAuthPerIP: -1, MaxPreAuthConns: -1, HandshakeTimeout: "3s"}
	}, nil)
	heap := atkWatchHeap()
	var wg sync.WaitGroup
	var opened atomic.Int64
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nc, err := net.Dial("tcp", e.proxyAddr)
			if err != nil {
				return
			}
			defer nc.Close()
			opened.Add(1)
			// Authenticated-sized claim: 40 MiB, delivering nothing (pre-auth
			// the proxy refuses it outright; the body must never be allocated
			// either way).
			nc.Write(atkFrame(40<<20, 1, 0, wire.OpMsg, nil))
			time.Sleep(1500 * time.Millisecond)
		}()
	}
	wg.Wait()
	g := heap.growth()
	if g > 96<<20 {
		t.Fatalf("heap grew %d MiB under %d idle 40 MiB-claim connections (a 40 MiB buffer each would be %d MiB)", g>>20, opened.Load(), opened.Load()*40)
	}
	e.noPanics(t)
	e.alive(t, "tenant-good")

	// The same through authenticated connections, which may claim large messages.
	heap = atkWatchHeap()
	var conns []*atkRaw
	for i := 0; i < 100; i++ {
		r := e.atkDialTenant(t, "tenant-flood")
		r.write(atkFrame(40<<20, 1, 0, wire.OpMsg, []byte("x")))
		conns = append(conns, r)
	}
	time.Sleep(500 * time.Millisecond)
	g = heap.growth()
	if g > 96<<20 {
		t.Fatalf("heap grew %d MiB under 100 authenticated 40 MiB-claim connections", g>>20)
	}
	for _, c := range conns {
		c.nc.Close()
	}
	e.alive(t, "tenant-good")
}

type flakyListener struct {
	net.Listener
	fail atomic.Int32
}

type tempErr struct{}

func (tempErr) Error() string   { return "accept: too many open files" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fail.Add(-1) >= 0 {
		return nil, tempErr{}
	}
	return l.Listener.Accept()
}

// EMFILE during a connection flood used to end Serve, i.e. take down every
// tenant. It must retry instead.
func TestAttackAcceptErrorsDoNotStopServing(t *testing.T) {
	var fl *flakyListener
	e := atkSetup(t, nil, func(ln net.Listener) net.Listener {
		fl = &flakyListener{Listener: ln}
		fl.fail.Store(5)
		return fl
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cl := e.tenant(t, "tenant-a")
		_, err := cl.Database("atk").Collection("accept").InsertOne(c, bson.M{"x": 1})
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy never recovered from accept errors: %v", err)
		}
	}
	if fl.fail.Load() > 0 {
		t.Fatal("test did not exercise the failing accepts")
	}
	_ = errors.New
}
