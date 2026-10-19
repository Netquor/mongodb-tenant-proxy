// Package stresstest holds helpers shared by the concurrency stress suites:
// the short/long mode switch, a watchdog that dumps every goroutine when a
// scenario deadlocks, and goroutine/file-descriptor leak checks.
//
// Short mode (default) is sized for CI. Set MTP_STRESS=long for the soak
// variant, or MTP_STRESS_SCALE=<n> to multiply iteration counts.
package stresstest

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// Long reports whether the long soak mode was requested.
func Long() bool { return os.Getenv("MTP_STRESS") == "long" }

// N scales an iteration count: short is used by default, long in soak mode,
// and MTP_STRESS_SCALE multiplies either.
func N(short, long int) int {
	n := short
	if Long() {
		n = long
	}
	if v, err := strconv.Atoi(os.Getenv("MTP_STRESS_SCALE")); err == nil && v > 1 {
		n *= v
	}
	return n
}

// D scales a duration the same way as N.
func D(short, long time.Duration) time.Duration {
	if Long() {
		return long
	}
	return short
}

// Watchdog fails the test, with a full goroutine dump, if the returned stop
// function has not been called within d. A deadlocked scenario would
// otherwise only surface as the generic `go test` timeout panic.
func Watchdog(t testing.TB, d time.Duration) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
		case <-time.After(d):
			var sb strings.Builder
			pprof.Lookup("goroutine").WriteTo(&sb, 2)
			fmt.Fprintf(os.Stderr, "=== DEADLOCK? %s still running after %s ===\n%s\n", t.Name(), d, sb.String())
			// t.Fatal is not allowed off the test goroutine, and the stuck
			// goroutine may never return: abort the process with the dump.
			os.Exit(2)
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// Goroutines returns the current goroutine count after letting finished
// goroutines unwind.
func Goroutines() int {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	return runtime.NumGoroutine()
}

// OpenFDs returns the number of open file descriptors of this process, or -1
// where it cannot be determined.
func OpenFDs() int {
	for _, dir := range []string{"/dev/fd", "/proc/self/fd"} {
		if ents, err := os.ReadDir(dir); err == nil {
			return len(ents)
		}
	}
	return -1
}

// Settle polls until f() <= want or the deadline passes, returning the last
// observed value. Used for "eventually back to baseline" checks.
func Settle(d time.Duration, want int, f func() int) int {
	deadline := time.Now().Add(d)
	for {
		n := f()
		if n <= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// NoLeak records the goroutine and fd baselines and, when the returned func
// runs, fails t if either has not returned to (baseline + slack) within
// settle. Call it before starting the system under test and run the returned
// function after everything has been shut down.
func NoLeak(t testing.TB, slack int) func() {
	t.Helper()
	g0, f0 := Goroutines(), OpenFDs()
	return func() {
		t.Helper()
		g := Settle(10*time.Second, g0+slack, Goroutines)
		if g > g0+slack {
			var sb strings.Builder
			pprof.Lookup("goroutine").WriteTo(&sb, 1)
			t.Errorf("goroutine leak: %d before, %d after (slack %d)\n%s", g0, g, slack, sb.String())
		}
		// Slack hides small leaks; our own code must not leave anything running
		// at all (hub streams, monitors, reapers, per-connection goroutines).
		if left := Settle(10*time.Second, 0, ownGoroutines); left > 0 {
			var sb strings.Builder
			pprof.Lookup("goroutine").WriteTo(&sb, 2)
			t.Errorf("%d goroutine(s) of this module still running after shutdown:\n%s", left, ownStacks(sb.String()))
		}
		if f0 >= 0 {
			f := Settle(5*time.Second, f0+slack, OpenFDs)
			if f > f0+slack {
				t.Errorf("file descriptor leak: %d before, %d after (slack %d)", f0, f, slack)
			}
		}
	}
}

// RunMain runs a package's tests and then verifies no goroutines leaked
// (go.uber.org/goleak, ignoring the runtime's own and test-framework ones).
// Use it from TestMain in packages whose tests start background goroutines.
func RunMain(m *testing.M) {
	base := goleak.IgnoreCurrent()
	code := m.Run()
	if code == 0 {
		if err := goleak.Find(base); err != nil {
			fmt.Fprintf(os.Stderr, "goroutine leak detected:\n%v\n", err)
			code = 1
		}
	}
	os.Exit(code)
}

var dumped sync.Once

// DumpOnce writes every goroutine's stack to stderr, at most once per
// process. Call it when a scenario observes a stall so the failure carries
// the evidence of where everything was blocked.
func DumpOnce(why string) {
	dumped.Do(func() {
		var sb strings.Builder
		pprof.Lookup("goroutine").WriteTo(&sb, 2)
		fmt.Fprintf(os.Stderr, "=== goroutine dump: %s ===\n%s\n", why, sb.String())
	})
}

// ownStacks keeps the goroutine stacks that have a frame in this module's
// internal packages (other than this helper and test code).
func ownStacks(dump string) string {
	var out []string
	for _, g := range strings.Split(dump, "\n\n") {
		if !strings.Contains(g, "mongodb-tenant-proxy/internal/") {
			continue
		}
		if strings.Contains(g, "internal/stresstest.") || strings.Contains(g, "testing.tRunner") || strings.Contains(g, "testing.(*T).Run") {
			continue
		}
		out = append(out, g)
	}
	return strings.Join(out, "\n\n")
}

func ownGoroutines() int {
	var sb strings.Builder
	pprof.Lookup("goroutine").WriteTo(&sb, 2)
	s := ownStacks(sb.String())
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n\n") + 1
}
