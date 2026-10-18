// Package metrics exposes a minimal Prometheus-format endpoint without any
// third-party dependency.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing value.
type Counter struct{ v atomic.Int64 }

// Add increments the counter.
func (c *Counter) Add(n int64) { c.v.Add(n) }

// Load returns the current value.
func (c *Counter) Load() int64 { return c.v.Load() }

// Gauge is a value that can go up and down.
type Gauge struct{ v atomic.Int64 }

// Add adjusts the gauge.
func (g *Gauge) Add(n int64) { g.v.Add(n) }

// Registry holds all proxy metrics.
type Registry struct {
	ConnsTotal  Counter
	ConnsActive Gauge
	BytesIn     Counter
	BytesOut    Counter
	// StreamedReplies counts upstream replies relayed in chunks;
	// UpstreamRetries counts commands repeated on another connection or member.
	StreamedReplies Counter
	UpstreamRetries Counter
	// Collectors append extra Prometheus text (upstream topology and pools).
	Collectors []func(io.Writer)

	mu       sync.Mutex
	commands map[string]*Counter // "command|outcome"
}

// New returns an empty registry.
func New() *Registry { return &Registry{commands: map[string]*Counter{}} }

// Command counts a command by name and outcome ("ok", "denied", "error").
func (r *Registry) Command(name, outcome string) {
	k := name + "|" + outcome
	r.mu.Lock()
	c := r.commands[k]
	if c == nil {
		c = &Counter{}
		r.commands[k] = c
	}
	r.mu.Unlock()
	c.Add(1)
}

func (r *Registry) write(w io.Writer) {
	fmt.Fprintf(w, "# TYPE mtp_connections_total counter\nmtp_connections_total %d\n", r.ConnsTotal.v.Load())
	fmt.Fprintf(w, "# TYPE mtp_connections_active gauge\nmtp_connections_active %d\n", r.ConnsActive.v.Load())
	fmt.Fprintf(w, "# TYPE mtp_client_bytes_total counter\nmtp_client_bytes_total{direction=\"in\"} %d\nmtp_client_bytes_total{direction=\"out\"} %d\n",
		r.BytesIn.v.Load(), r.BytesOut.v.Load())
	fmt.Fprintf(w, "# TYPE mtp_streamed_replies_total counter\nmtp_streamed_replies_total %d\n", r.StreamedReplies.v.Load())
	fmt.Fprintf(w, "# TYPE mtp_upstream_retries_total counter\nmtp_upstream_retries_total %d\n", r.UpstreamRetries.v.Load())
	for _, f := range r.Collectors {
		f(w)
	}
	r.mu.Lock()
	keys := make([]string, 0, len(r.commands))
	for k := range r.commands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# TYPE mtp_commands_total counter\n")
	for _, k := range keys {
		var name, outcome string
		for i := 0; i < len(k); i++ {
			if k[i] == '|' {
				name, outcome = k[:i], k[i+1:]
			}
		}
		fmt.Fprintf(w, "mtp_commands_total{command=%q,outcome=%q} %d\n", name, outcome, r.commands[k].v.Load())
	}
	r.mu.Unlock()
}

// Handler serves /metrics and /healthz.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.write(w)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	return mux
}
