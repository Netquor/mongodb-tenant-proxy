// Package trace defines the span hook the proxy calls around every command.
//
// The default is a no-op. To export spans, install a Tracer at start-up
// (trace.Set); for OpenTelemetry, wrap otel's Tracer in a few lines behind your
// own build tag. This repo keeps OTel out of go.mod so the default binary has no
// extra dependencies.
package trace

import "sync/atomic"

// Span is one in-flight command.
type Span interface {
	// End finishes the span; outcome is "ok", "denied" or "error".
	End(outcome string)
}

// Tracer starts spans. Attributes are metadata only (never document values).
type Tracer interface {
	Start(name string, attrs Attrs) Span
}

// Attrs describes the command.
type Attrs struct {
	Tenant, User, DB, Command, Session, Corr string
}

type noopSpan struct{}

func (noopSpan) End(string) {}

type noopTracer struct{}

func (noopTracer) Start(string, Attrs) Span { return noopSpan{} }

var cur atomic.Pointer[Tracer]

func init() { var t Tracer = noopTracer{}; cur.Store(&t) }

// Set installs the process-wide tracer (nil restores the no-op).
func Set(t Tracer) {
	if t == nil {
		t = noopTracer{}
	}
	cur.Store(&t)
}

// Start begins a span on the installed tracer.
func Start(name string, a Attrs) Span { return (*cur.Load()).Start(name, a) }
