package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Many connection goroutines log through the shared Logger while the sample
// rate is changed (hot reload). Every event is delivered whole and exactly
// once to a rotating file (lines never interleave or tear), and every event
// handed to the HTTP shipper is either received or counted as dropped.
func TestStressLoggerFile(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	path := filepath.Join(t.TempDir(), "audit.log")
	f, err := NewRotatingFile(path, 1<<20, -1) // no backups: rotation just truncates; only count when it can't
	if err != nil {
		t.Fatal(err)
	}
	// A big maxSize so nothing rotates away: this checks tearing and loss.
	f.maxSize = 1 << 40
	l := NewLogger(f, 1)
	const workers = 12
	n := stresstest.N(2000, 40000)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				l.Log(Event{Type: CmdWrite, Tenant: fmt.Sprint("t", w), Corr: fmt.Sprint(i), Reason: "x"})
				if i%97 == 0 {
					l.SetSampleReads(float64(i%3) / 2)
					l.SampleRead()
				}
			}
		}(w)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	lines := 0
	for sc.Scan() {
		lines++
		if l := sc.Bytes(); len(l) == 0 || l[0] != '{' || l[len(l)-1] != '}' {
			t.Fatalf("torn audit line: %q", l)
		}
	}
	if lines != workers*n {
		t.Fatalf("%d lines written, want %d", lines, workers*n)
	}
}

func TestStressLoggerHTTP(t *testing.T) {
	defer stresstest.Watchdog(t, time.Minute)()
	var got atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc := bufio.NewScanner(r.Body)
		sc.Buffer(nil, 4<<20)
		for sc.Scan() {
			got.Add(1)
		}
	}))
	defer srv.Close()
	sink := NewHTTPSink(srv.URL, nil)
	l := NewLogger(sink, 1)
	const workers = 8
	n := stresstest.N(3000, 50000)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				l.Log(Event{Type: CmdWrite, Tenant: fmt.Sprint("t", w), Corr: fmt.Sprint(i)})
			}
		}(w)
	}
	wg.Wait()
	l.Close() // flushes
	if sum := got.Load() + sink.Dropped(); sum != int64(workers*n) {
		t.Fatalf("received %d + dropped %d != sent %d", got.Load(), sink.Dropped(), workers*n)
	}
}

func TestHTTPSinkDoubleClose(t *testing.T) {
	s := NewHTTPSink("http://127.0.0.1:1/", nil)
	s.Close()
	s.Close() // used to panic: close of closed channel
}
