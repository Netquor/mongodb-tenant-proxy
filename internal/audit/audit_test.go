package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

type memSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (m *memSink) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}
func (m *memSink) Close() error { return nil }
func (m *memSink) lines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Split(strings.TrimSpace(m.buf.String()), "\n")
}

func TestLogEmitsJSONAndScrubsReason(t *testing.T) {
	ms := &memSink{}
	l := NewLogger(ms, 0)
	l.Log(Event{Type: CmdDenied, Tenant: "acme", Command: "find", Reason: `operator "$where" with value 'secret-123' is not allowed`})
	var e map[string]any
	if err := json.Unmarshal([]byte(ms.lines()[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e["type"] != "command.denied" || e["tenant"] != "acme" || e["ts"] == nil {
		t.Fatalf("event: %v", e)
	}
	if strings.Contains(ms.buf.String(), "secret-123") || strings.Contains(ms.buf.String(), "$where") {
		t.Fatalf("literal leaked: %s", ms.buf.String())
	}
	long := Scrub(strings.Repeat("x", 1000))
	if len(long) > 210 {
		t.Fatalf("reason not bounded: %d", len(long))
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var l *Logger
	l.Log(Event{Type: Connect})
	l.SetSampleReads(1)
	if l.SampleRead() || l.Enabled() || l.Close() != nil {
		t.Fatal("nil logger must be inert")
	}
}

func TestSampling(t *testing.T) {
	l := NewLogger(&memSink{}, 0)
	for i := 0; i < 100; i++ {
		if l.SampleRead() {
			t.Fatal("rate 0 sampled")
		}
	}
	l.SetSampleReads(1)
	for i := 0; i < 100; i++ {
		if !l.SampleRead() {
			t.Fatal("rate 1 skipped")
		}
	}
	l.SetSampleReads(0.25)
	n := 0
	for i := 0; i < 20000; i++ {
		if l.SampleRead() {
			n++
		}
	}
	if n < 3500 || n > 6500 {
		t.Fatalf("sampled %d/20000 at 0.25", n)
	}
}

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	f, err := NewRotatingFile(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("a", 59) + "\n" // 60 bytes: two lines exceed 100
	for i := 0; i < 7; i++ {
		if _, err := f.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	for _, n := range []string{"audit.log", "audit.log.1", "audit.log.2"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("missing %s: %v", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.3")); err == nil {
		t.Fatal("kept more backups than configured")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// reopen appends rather than truncates
	f2, _ := NewRotatingFile(p, 1000, 2)
	f2.Write([]byte("tail\n"))
	f2.Close()
	fh, _ := os.Open(p)
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	var last string
	for sc.Scan() {
		last = sc.Text()
	}
	if last != "tail" {
		t.Fatalf("last line %q", last)
	}
}

func TestHTTPSinkShipsBatches(t *testing.T) {
	got := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		got <- string(b)
	}))
	defer srv.Close()
	l, err := New(config.Audit{Enabled: true, Sink: "http", URL: srv.URL, Header: map[string]string{"X-Key": "k"}})
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Event{Type: Connect, Tenant: "a"})
	l.Log(Event{Type: Disconnect, Tenant: "a"})
	l.Close() // flushes
	body := <-got
	if strings.Count(body, "\n") != 2 {
		t.Fatalf("body %q", body)
	}
}
