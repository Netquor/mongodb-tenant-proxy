package auth

import (
	"sync"
	"time"
)

// Throttle counts authentication failures per key (a client address, a user
// name) and locks a key out once it fails too often within a window. Each
// consecutive lockout doubles the lock time up to maxLockout, so a patient
// guesser slows to a crawl while an honest typo costs one short pause.
//
// A success deliberately does not reset a key: otherwise an attacker holding
// one valid account could interleave logins to it with guesses at others.
type Throttle struct {
	max     int
	window  time.Duration
	lockout time.Duration
	cap     int
	now     func() time.Time

	mu sync.Mutex
	m  map[string]*throttleEntry
}

type throttleEntry struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
	strikes     int // lockouts so far (doubles the next one)
	last        time.Time
}

const (
	// maxThrottleEntries bounds the table so rotating keys cannot exhaust
	// memory; when full, expired entries are swept and, failing that, new keys
	// are simply not tracked.
	maxThrottleEntries = 100000
	maxLockout         = 15 * time.Minute
)

// NewThrottle builds a Throttle. A non-positive max disables it (nil is a
// valid, always-allowing Throttle).
func NewThrottle(max int, window, lockout time.Duration) *Throttle {
	if max <= 0 {
		return nil
	}
	if window <= 0 {
		window = time.Minute
	}
	if lockout <= 0 {
		lockout = time.Minute
	}
	return &Throttle{max: max, window: window, lockout: lockout, cap: maxThrottleEntries, now: time.Now, m: map[string]*throttleEntry{}}
}

// Allowed reports whether key may attempt to authenticate, and for how long it
// is locked out otherwise.
func (t *Throttle) Allowed(key string) (bool, time.Duration) {
	if t == nil || key == "" {
		return true, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.m[key]; e != nil {
		if now := t.now(); now.Before(e.lockedUntil) {
			return false, e.lockedUntil.Sub(now)
		}
	}
	return true, 0
}

// Fail records a failed attempt.
func (t *Throttle) Fail(key string) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e := t.m[key]
	if e == nil {
		if len(t.m) >= t.cap {
			t.sweep(now)
			if len(t.m) >= t.cap {
				return
			}
		}
		e = &throttleEntry{first: now}
		t.m[key] = e
	}
	e.last = now
	if now.Before(e.lockedUntil) {
		return // already locked; late failures do not extend it
	}
	if now.Sub(e.first) > t.window {
		e.fails, e.first = 0, now
	}
	if e.fails++; e.fails >= t.max {
		d := t.lockout << min(e.strikes, 10)
		if d > maxLockout || d <= 0 {
			d = maxLockout
		}
		e.lockedUntil = now.Add(d)
		e.strikes++
		e.fails, e.first = 0, now
	}
}

// sweep drops entries that are neither locked nor recent enough to matter.
func (t *Throttle) sweep(now time.Time) {
	for k, e := range t.m {
		if now.After(e.lockedUntil) && now.Sub(e.last) > t.window+maxLockout {
			delete(t.m, k)
		}
	}
}

// Len returns the number of tracked keys (for tests and metrics).
func (t *Throttle) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// SetClock replaces the time source (tests).
func (t *Throttle) SetClock(now func() time.Time) {
	if t != nil {
		t.mu.Lock()
		t.now = now
		t.mu.Unlock()
	}
}
