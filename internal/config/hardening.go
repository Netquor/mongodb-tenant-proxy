package config

import (
	"fmt"
	"net/url"
	"time"
)

// ConnLimits bounds what the client listener accepts before and after
// authentication. Every field is optional; the zero value gives the defaults
// noted on each.
type ConnLimits struct {
	// MaxConns caps all open client connections (0 = unlimited).
	MaxConns int `json:"maxConns,omitempty"`
	// MaxConnsPerIP caps open connections from one client address (0 = unlimited).
	MaxConnsPerIP int `json:"maxConnsPerIP,omitempty"`
	// MaxPreAuthConns caps connections that have not yet bound to a tenant
	// (default 4096, negative = unlimited); MaxPreAuthPerIP does so per client
	// address (default 256). They bound what a connection flood can hold.
	MaxPreAuthConns int `json:"maxPreAuthConns,omitempty"`
	MaxPreAuthPerIP int `json:"maxPreAuthPerIP,omitempty"`
	// HandshakeTimeout is how long a connection may stay unauthenticated
	// (default 30s, "0s" = no limit).
	HandshakeTimeout string `json:"handshakeTimeout,omitempty"`
	// FrameTimeout is how long a message may take to arrive once its first
	// byte has (default 2m, "0s" = no limit): slow-loris protection after
	// authentication, where idleTimeout does not apply mid-message.
	FrameTimeout string `json:"frameTimeout,omitempty"`
	// WriteTimeout is how long one write to a client may block (default 2m,
	// "0s" = no limit): a client that stops reading cannot hold the proxy.
	WriteTimeout string `json:"writeTimeout,omitempty"`
	// PreAuthMaxBytes caps the size of a message from a connection that has
	// not authenticated (default 256 KiB, negative = maxMessageBytes).
	PreAuthMaxBytes int `json:"preAuthMaxBytes,omitempty"`
}

func dur(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return def
	}
	return d
}

// Handshake returns the effective handshake timeout (0 = none).
func (l ConnLimits) Handshake() time.Duration { return dur(l.HandshakeTimeout, 30*time.Second) }

// Frame returns the effective message-completion timeout (0 = none).
func (l ConnLimits) Frame() time.Duration { return dur(l.FrameTimeout, 2*time.Minute) }

// Write returns the effective client write timeout (0 = none).
func (l ConnLimits) Write() time.Duration { return dur(l.WriteTimeout, 2*time.Minute) }

// PreAuthBytes returns the effective pre-authentication message cap (0 = none).
func (l ConnLimits) PreAuthBytes() int {
	switch {
	case l.PreAuthMaxBytes < 0:
		return 0
	case l.PreAuthMaxBytes == 0:
		return 256 * 1024
	}
	return l.PreAuthMaxBytes
}

// PreAuth returns the effective pre-authentication connection caps (0 = none).
func (l ConnLimits) PreAuth() (total, perIP int) {
	total, perIP = l.MaxPreAuthConns, l.MaxPreAuthPerIP
	if total == 0 {
		total = 4096
	}
	if perIP == 0 {
		perIP = 256
	}
	return max(total, 0), max(perIP, 0)
}

// BruteForce configures lockout after repeated authentication failures.
type BruteForce struct {
	// MaxFailures is how many failures one client address may make within
	// Window before it is locked out (default 10, negative disables).
	MaxFailures int `json:"maxFailures,omitempty"`
	// MaxFailuresPerUser does the same per user name regardless of address,
	// to slow distributed guessing (default 0 = off: enabling it lets an
	// attacker lock a known user out).
	MaxFailuresPerUser int `json:"maxFailuresPerUser,omitempty"`
	// Window is the counting window (default 1m); Lockout the first lock
	// time (default 1m), doubling for each repeat up to 15m.
	Window  string `json:"window,omitempty"`
	Lockout string `json:"lockout,omitempty"`
}

// Effective returns the parameters with defaults applied. max < 0 means off.
func (b BruteForce) Effective() (max, perUser int, window, lockout time.Duration) {
	max = b.MaxFailures
	if max == 0 {
		max = 10
	}
	return max, b.MaxFailuresPerUser, dur(b.Window, time.Minute), dur(b.Lockout, time.Minute)
}

func (c *Config) finishHardening() error {
	for name, d := range map[string]string{
		"connLimits.handshakeTimeout": c.ConnLimits.HandshakeTimeout,
		"connLimits.frameTimeout":     c.ConnLimits.FrameTimeout,
		"connLimits.writeTimeout":     c.ConnLimits.WriteTimeout,
		"auth.bruteForce.window":      c.Auth.BruteForce.Window,
		"auth.bruteForce.lockout":     c.Auth.BruteForce.Lockout,
	} {
		if d != "" {
			if v, err := time.ParseDuration(d); err != nil || v < 0 {
				return fmt.Errorf("%s: invalid duration %q", name, d)
			}
		}
	}
	if c.ConnLimits.MaxConns < 0 || c.ConnLimits.MaxConnsPerIP < 0 {
		return fmt.Errorf("connLimits.maxConns and maxConnsPerIP must be >= 0")
	}
	if o := c.Auth.OIDC; o != nil && o.JWKSURI != "" {
		u, err := url.Parse(o.JWKSURI)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("auth.oidc.jwksUri must be an http(s) URL")
		}
	}
	return nil
}
