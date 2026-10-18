package config

import (
	"testing"
	"time"
)

func TestConnLimitsDefaultsAndValidation(t *testing.T) {
	var l ConnLimits
	if l.Handshake() != 30*time.Second || l.Frame() != 2*time.Minute || l.Write() != 2*time.Minute {
		t.Fatalf("defaults: %v %v %v", l.Handshake(), l.Frame(), l.Write())
	}
	if l.PreAuthBytes() != 256*1024 {
		t.Fatalf("pre-auth cap default %d", l.PreAuthBytes())
	}
	if total, per := l.PreAuth(); total != 4096 || per != 256 {
		t.Fatalf("pre-auth caps %d/%d", total, per)
	}
	// Explicit zero durations switch a timeout off; negatives/garbage fall back.
	l = ConnLimits{HandshakeTimeout: "0s", FrameTimeout: "5s", WriteTimeout: "bogus", PreAuthMaxBytes: -1, MaxPreAuthConns: -1, MaxPreAuthPerIP: 7}
	if l.Handshake() != 0 || l.Frame() != 5*time.Second || l.Write() != 2*time.Minute || l.PreAuthBytes() != 0 {
		t.Fatalf("overrides: %v %v %v %d", l.Handshake(), l.Frame(), l.Write(), l.PreAuthBytes())
	}
	if total, per := l.PreAuth(); total != 0 || per != 7 {
		t.Fatalf("pre-auth overrides %d/%d", total, per)
	}

	base := func() *Config {
		return &Config{Upstream: Upstream{Addr: "x:1"}, Auth: Auth{Mode: "static", StaticTenant: "t"}}
	}
	for name, mut := range map[string]func(*Config){
		"bad handshake":  func(c *Config) { c.ConnLimits.HandshakeTimeout = "soon" },
		"negative frame": func(c *Config) { c.ConnLimits.FrameTimeout = "-5s" },
		"bad lockout":    func(c *Config) { c.Auth.BruteForce.Lockout = "x" },
		"negative cap":   func(c *Config) { c.ConnLimits.MaxConnsPerIP = -1 },
		"file jwks uri": func(c *Config) {
			c.Auth = Auth{Mode: "oidc", OIDC: &OIDC{Issuer: "i", Audience: "a", JWKSURI: "file:///etc/passwd"}}
		},
		"gopher jwks uri": func(c *Config) {
			c.Auth = Auth{Mode: "oidc", OIDC: &OIDC{Issuer: "i", Audience: "a", JWKSURI: "gopher://x/"}}
		},
	} {
		c := base()
		mut(c)
		if err := Validate(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base()
	c.ConnLimits = ConnLimits{HandshakeTimeout: "5s", MaxConns: 10}
	c.Auth.BruteForce = BruteForce{MaxFailures: 3, Window: "30s", Lockout: "1m"}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}

func TestBruteForceEffective(t *testing.T) {
	max, perUser, w, l := BruteForce{}.Effective()
	if max != 10 || perUser != 0 || w != time.Minute || l != time.Minute {
		t.Fatalf("defaults: %d %d %v %v", max, perUser, w, l)
	}
	if max, _, _, _ := (BruteForce{MaxFailures: -1}).Effective(); max > 0 {
		t.Fatal("negative must disable")
	}
}
