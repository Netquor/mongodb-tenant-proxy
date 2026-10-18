// Package audit writes a structured, append-only JSON audit trail.
//
// Events never contain document contents, filter values or passwords: only
// metadata (who, from where, which command on which namespace, and why it was
// denied). Free-text reasons are length-limited and have quoted fragments
// scrubbed so that a rejected query cannot leak its literals into the log.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// Event types.
const (
	Connect      = "connect"
	Disconnect   = "disconnect"
	AuthSuccess  = "auth.success"
	AuthFailure  = "auth.failure"
	CmdDenied    = "command.denied"
	CmdError     = "command.error"
	CmdDDL       = "command.ddl"
	CmdWrite     = "command.write"
	CmdRead      = "command.read"
	AdminAction  = "admin.action"
	ConfigReload = "config.reload"
	ConnKilled   = "connection.killed"
)

// Event is one audit record, serialised as a single JSON line.
type Event struct {
	Time      time.Time `json:"ts"`
	Type      string    `json:"type"`
	Corr      string    `json:"corr,omitempty"`    // correlation id: <session>-<seq> for commands, request id for admin
	Session   string    `json:"session,omitempty"` // random id of the client connection
	ConnID    int64     `json:"connId,omitempty"`
	Tenant    string    `json:"tenant,omitempty"`
	User      string    `json:"user,omitempty"`
	Remote    string    `json:"remote,omitempty"`
	DB        string    `json:"db,omitempty"`
	Command   string    `json:"command,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Actor     string    `json:"actor,omitempty"`  // admin API caller
	Action    string    `json:"action,omitempty"` // admin API action, e.g. "tenant.disable"
	Target    string    `json:"target,omitempty"`
	LatencyMs float64   `json:"latencyMs,omitempty"`
}

// Sink receives encoded events (one JSON object per call, newline-terminated).
type Sink interface {
	io.Writer
	Close() error
}

// Logger encodes and dispatches events. A nil *Logger is a valid no-op.
type Logger struct {
	sink   Sink
	mu     sync.Mutex
	sample atomic.Uint64 // math.Float64bits of the read sampling rate
	rng    atomic.Uint64
}

// New builds a Logger from config; it returns nil (no-op) when disabled.
func New(cfg config.Audit) (*Logger, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	var s Sink
	var err error
	switch cfg.Sink {
	case "stdout":
		s = nopCloser{os.Stdout}
	case "stderr":
		s = nopCloser{os.Stderr}
	case "file":
		s, err = NewRotatingFile(cfg.Path, int64(cfg.MaxSizeMB)<<20, cfg.MaxBackups)
	case "syslog":
		s, err = newSyslog(cfg.Syslog)
	case "http":
		s = NewHTTPSink(cfg.URL, cfg.Header)
	}
	if err != nil {
		return nil, err
	}
	return NewLogger(s, cfg.SampleReads), nil
}

// NewLogger wraps a sink.
func NewLogger(s Sink, sampleReads float64) *Logger {
	l := &Logger{sink: s}
	l.SetSampleReads(sampleReads)
	var seed [8]byte
	rand.Read(seed[:])
	l.rng.Store(uint64(seed[0]) | uint64(seed[1])<<8 | uint64(seed[2])<<16 | uint64(seed[3])<<24 | uint64(seed[4])<<32 | 1)
	return l
}

// SetSampleReads changes the fraction of allowed reads that are logged.
func (l *Logger) SetSampleReads(f float64) {
	if l == nil {
		return
	}
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	l.sample.Store(math.Float64bits(f))
}

// Enabled reports whether events are being recorded.
func (l *Logger) Enabled() bool { return l != nil }

// SampleRead reports whether an allowed read should be logged now.
func (l *Logger) SampleRead() bool {
	if l == nil {
		return false
	}
	f := math.Float64frombits(l.sample.Load())
	switch {
	case f <= 0:
		return false
	case f >= 1:
		return true
	}
	// xorshift; races only perturb the sequence, which is fine for sampling.
	x := l.rng.Load()
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	l.rng.Store(x)
	return float64(x>>11)/float64(1<<53) < f
}

// NewID returns a random 64-bit hex id for sessions/requests.
func NewID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Log records an event.
func (l *Logger) Log(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Reason = Scrub(e.Reason)
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	_, _ = l.sink.Write(b) // an unwritable audit sink must never fail the request being audited
	l.mu.Unlock()
}

// Close flushes and closes the sink.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	return l.sink.Close()
}

var quoted = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// Scrub bounds a free-text reason and removes quoted literals, which may be
// document values.
func Scrub(s string) string {
	if s == "" {
		return s
	}
	s = quoted.ReplaceAllString(s, `"…"`)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
