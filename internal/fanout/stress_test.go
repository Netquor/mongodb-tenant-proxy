package fanout

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// These tests drive the hub machinery without an upstream: events are fed
// straight into hub.dispatch (what hub.stream does with each batch) while
// subscribers come and go and idle hubs shut down.

func newTestManager(grace time.Duration) *Manager {
	m := NewManager(nil, "tenantId", false, 1<<20, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.idleGrace = grace
	return m
}

func tkey(tenant string) string {
	return TenantKey(bsoncore.TypeString, bsoncore.AppendString(nil, tenant))
}

var tsCounter atomic.Uint32

func event(tenant string, seq int64, op string) bsoncore.Document {
	ts := tsCounter.Add(1)
	d := []byte{}
	d = bsoncore.AppendDocumentElement(d, "_id", bsoncore.BuildDocument(nil, bsoncore.AppendInt64Element(nil, "_data", int64(ts))))
	d = bsoncore.AppendStringElement(d, "operationType", op)
	d = bsoncore.AppendTimestampElement(d, "clusterTime", ts, 1)
	d = bsoncore.AppendDocumentElement(d, "fullDocument", bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "tenantId", tenant),
		bsoncore.AppendInt64Element(nil, "seq", seq)))
	return bsoncore.BuildDocument(nil, d)
}

func batch(evs ...bsoncore.Document) bsoncore.Array {
	vals := make([]bsoncore.Value, len(evs))
	for i, e := range evs {
		vals[i] = bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: e}
	}
	return bsoncore.BuildArray(nil, vals...)
}

func evTenantSeq(t *testing.T, ev bsoncore.Document) (string, int64) {
	t.Helper()
	fd, _ := ev.Lookup("fullDocument").DocumentOK()
	ten, _ := fd.Lookup("tenantId").StringValueOK()
	seq, _ := fd.Lookup("seq").AsInt64OK()
	return ten, seq
}

func TestMain(m *testing.M) {
	// goleak-equivalent check for the whole package: every hub, timer and
	// subscriber goroutine started by the tests must be gone at the end.
	stresstest.RunMain(m)
}

// Collection- and database-level hubs, many tenants, subscribers that join,
// read and leave at random while one dispatcher per hub feeds events. A
// subscriber must only ever see its own tenant's events, in order, and the
// hubs must all be gone once everyone has left.
func TestStressDispatchVsSubscribe(t *testing.T) {
	defer stresstest.Watchdog(t, 2*time.Minute)()
	m := newTestManager(2 * time.Millisecond) // hubs idle-close constantly
	tenants := []string{"t0", "t1", "t2", "t3"}
	targets := []struct{ db, coll string }{{"d", "c1"}, {"d", "c2"}, {"d", ""}}
	dur := stresstest.D(1500*time.Millisecond, 20*time.Second)
	stop := make(chan struct{})

	var dispatchers sync.WaitGroup
	var produced atomic.Int64
	for _, tg := range targets {
		dispatchers.Add(1)
		go func() {
			defer dispatchers.Done()
			seq := map[string]int64{}
			rng := rand.New(rand.NewSource(int64(len(tg.coll))))
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Look the hub up the way the real run loop holds one: it may
				// be closed under us by idle shutdown, which dispatch must tolerate.
				m.mu.Lock()
				h := m.hubs[tg.db+"."+tg.coll]
				m.mu.Unlock()
				if h == nil {
					time.Sleep(50 * time.Microsecond)
					continue
				}
				var evs []bsoncore.Document
				for i := 0; i < 1+rng.Intn(4); i++ {
					ten := tenants[rng.Intn(len(tenants))]
					seq[ten]++
					evs = append(evs, event(ten, seq[ten], "insert"))
				}
				var tok bsoncore.Document
				h.dispatch(batch(evs...), nil, &tok)
				produced.Add(int64(len(evs)))
			}
		}()
	}

	var subs sync.WaitGroup
	var received atomic.Int64
	for w := 0; w < 12; w++ {
		subs.Add(1)
		go func(w int) {
			defer subs.Done()
			rng := rand.New(rand.NewSource(int64(w)))
			end := time.Now().Add(dur)
			for time.Now().Before(end) {
				tg := targets[rng.Intn(len(targets))]
				me := tenants[rng.Intn(len(tenants))]
				s := m.Subscribe(tg.db, tg.coll, tkey(me), Options{})
				last := int64(0)
				for i, n := 0, rng.Intn(6); i < n; i++ {
					evs, _, _, err := s.Next(50, time.Millisecond)
					if err != nil {
						t.Errorf("unexpected sub error: %v", err)
						break
					}
					for _, ev := range evs {
						ten, seq := evTenantSeq(t, ev)
						if ten != me {
							t.Errorf("tenant %s received tenant %s's event", me, ten)
						}
						if seq <= last {
							t.Errorf("tenant %s: out-of-order seq %d after %d", me, seq, last)
						}
						last = seq
						received.Add(1)
					}
				}
				s.Close()
				s.Close() // double close must be harmless
			}
		}(w)
	}
	subs.Wait()
	close(stop)
	dispatchers.Wait()

	// Everything unsubscribed: every hub idles out and is removed.
	if n := stresstest.Settle(5*time.Second, 0, m.ActiveHubs); n != 0 {
		t.Fatalf("%d hubs still registered after all subscribers left", n)
	}
	t.Logf("produced=%d received=%d", produced.Load(), received.Load())
}

// A slow subscriber is cut off with ErrOverflow without affecting others, and
// its queue memory is released.
func TestStressOverflow(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	m := newTestManager(time.Hour)
	slow := m.Subscribe("d", "c", tkey("a"), Options{})
	fast := m.Subscribe("d", "c", tkey("a"), Options{})
	other := m.Subscribe("d", "c", tkey("b"), Options{})
	m.mu.Lock()
	h := m.hubs["d.c"]
	m.mu.Unlock()

	var got atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for got.Load() < int64(maxQueue)+500 {
			evs, _, _, err := fast.Next(1000, 20*time.Millisecond)
			if err != nil {
				t.Errorf("fast subscriber: %v", err)
				return
			}
			got.Add(int64(len(evs)))
		}
	}()
	var tok bsoncore.Document
	for i := 0; i < maxQueue+500; i += 100 {
		var evs []bsoncore.Document
		for j := 0; j < 100; j++ {
			evs = append(evs, event("a", int64(i+j+1), "insert"))
		}
		h.dispatch(batch(evs...), nil, &tok)
		for got.Load() < int64(i+100)-5000 { // keep `fast` within its queue
			time.Sleep(time.Millisecond)
		}
	}
	<-done
	if _, _, _, err := slow.Next(10, time.Millisecond); !errors.Is(err, ErrOverflow) {
		t.Fatalf("slow subscriber: want ErrOverflow, got %v", err)
	}
	if evs, _, _, err := other.Next(10, time.Millisecond); err != nil || len(evs) != 0 {
		t.Fatalf("other tenant got %d events / err %v", len(evs), err)
	}
	slow.mu.Lock()
	q := len(slow.queue)
	slow.mu.Unlock()
	if q != 0 {
		t.Fatalf("overflowed subscriber still holds %d queued events", q)
	}
	slow.Close()
	fast.Close()
	other.Close()
}

// Lifecycle events (drop/invalidate) reach every watcher; failAll races with
// dispatch and Close without deadlock.
func TestStressFailAllVsDispatch(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	m := newTestManager(time.Millisecond)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := m.Subscribe("d", "c", tkey(fmt.Sprint("t", i%2)), Options{})
				s.Next(10, 100*time.Microsecond)
				s.Close()
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var tok bsoncore.Document
		for i := int64(1); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			m.mu.Lock()
			h := m.hubs["d.c"]
			m.mu.Unlock()
			if h == nil {
				continue
			}
			h.dispatch(batch(event("t0", i, "insert"), event("t1", i, "drop"), event("t1", i, "invalidate")), nil, &tok)
			if i%7 == 0 {
				h.failAll(ErrOverflow)
			}
		}
	}()
	time.Sleep(stresstest.D(800*time.Millisecond, 10*time.Second))
	close(stop)
	wg.Wait()
	if n := stresstest.Settle(3*time.Second, 0, m.ActiveHubs); n != 0 {
		t.Fatalf("%d hubs leaked", n)
	}
	_ = bytes.MinRead
}
