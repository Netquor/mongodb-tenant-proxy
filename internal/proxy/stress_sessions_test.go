package proxy

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

func uid(n uint32) [16]byte {
	var id [16]byte
	binary.BigEndian.PutUint32(id[:], n)
	return id
}

func lsidCmd(cmd string, ids ...[16]byte) bsoncore.Document {
	vals := make([]bsoncore.Value, len(ids))
	for i, id := range ids {
		vals[i] = bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: bsoncore.BuildDocument(nil,
			bsoncore.AppendBinaryElement(nil, "id", 4, id[:]))}
	}
	switch cmd {
	case "endSessions", "refreshSessions", "killSessions":
		return bsoncore.BuildDocument(nil, bsoncore.AppendArrayElement(nil, cmd, bsoncore.BuildArray(nil, vals...)))
	}
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, cmd, "c"),
		bsoncore.AppendValueElement(nil, "lsid", vals[0]))
}

// Session bind/expire/endSessions from many goroutines on a fast-moving clock.
// Invariants: a live session is never usable by two tenants; perTen always
// equals the real per-tenant count (checked at quiescence).
func TestStressSessionTable(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	st := newSessionTable(1, now) // 1 min ttl + grace, so advancing the clock expires bindings

	const tenants = 6
	const space = 64 // small id space => constant contention and re-binding
	iters := stresstest.N(20000, 400000)
	var wg sync.WaitGroup
	var ticker atomic.Bool
	wg.Add(1)
	go func() { // clock mover: forces expiry and the periodic sweep
		defer wg.Done()
		for !ticker.Load() {
			clock.Add(int64(3 * time.Minute))
			time.Sleep(200 * time.Microsecond)
		}
	}()
	var workers sync.WaitGroup
	for w := 0; w < tenants; w++ {
		workers.Add(1)
		go func(w int) {
			defer workers.Done()
			ten := fmt.Sprint("t", w)
			for i := 0; i < iters; i++ {
				id := uid(uint32((i*7 + w*13) % space))
				switch i % 5 {
				case 0:
					st.check(ten, "endSessions", lsidCmd("endSessions", id, uid(uint32(i%space))))
				case 1:
					st.check(ten, "find", lsidCmd("find", id))
				case 2:
					st.owned(ten, id)
				default:
					st.check(ten, "insert", lsidCmd("insert", id))
				}
			}
		}(w)
	}
	workers.Wait()
	ticker.Store(true)
	wg.Wait()

	st.mu.Lock()
	defer st.mu.Unlock()
	counts := map[string]int{}
	for _, b := range st.m {
		counts[b.tenant]++
	}
	for ten, n := range counts {
		if st.perTen[ten] != n {
			t.Errorf("tenant %s: perTen=%d but %d bindings", ten, st.perTen[ten], n)
		}
	}
	for ten, n := range st.perTen {
		if n != counts[ten] {
			t.Errorf("tenant %s: perTen=%d but %d bindings", ten, n, counts[ten])
		}
	}
}

// Exclusive ownership under contention without clock movement: exactly one
// tenant may win each id.
func TestStressSessionExclusive(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	st := newSessionTable(30, nil)
	const ids = 500
	wins := make([]atomic.Int32, ids)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ten := fmt.Sprint("t", w)
			for i := 0; i < ids; i++ {
				if st.bind(ten, uid(uint32(i))) {
					wins[i].Add(1)
					if !st.bind(ten, uid(uint32(i))) {
						t.Errorf("owner lost its own session")
					}
				}
			}
		}(w)
	}
	wg.Wait()
	for i := range wins {
		if n := wins[i].Load(); n != 1 {
			t.Fatalf("session %d claimed by %d tenants", i, n)
		}
	}
}
