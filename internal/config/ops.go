package config

import (
	"fmt"
	"log/slog"
	"time"
)

// TenantEntry declares a tenant in the config file. Tenants are otherwise
// implicit (created by having users); declare one to disable it or give it its
// own connection cap. Config tenants are read-only through the admin API.
type TenantEntry struct {
	ID       string `json:"id"`
	Disabled bool   `json:"disabled,omitempty"`
	// MaxConns overrides maxConnsPerTenant for this tenant (0 = default).
	MaxConns int `json:"maxConns,omitempty"`
}

// Admin configures the tenant admin API. It is served on its own listener
// (adminAddr) and is disabled when adminAddr is empty.
type Admin struct {
	// Token is a static bearer token. Prefer TokenFile or $MTP_ADMIN_TOKEN.
	Token     string `json:"token,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
	// TLS serves the admin API over TLS. With ClientCAFile set, clients must
	// present a certificate signed by that CA (mTLS); a valid client
	// certificate is sufficient authentication on its own.
	TLS *AdminTLS `json:"tls,omitempty"`
	// RatePerSec limits authenticated requests per second across all
	// callers (default 50, negative = unlimited); failed authentications
	// are throttled per client address separately.
	RatePerSec float64 `json:"ratePerSec,omitempty"`
}

// AdminTLS is the admin listener's TLS configuration.
type AdminTLS struct {
	CertFile     string `json:"certFile"`
	KeyFile      string `json:"keyFile"`
	ClientCAFile string `json:"clientCAFile,omitempty"`
}

// Store selects where dynamic tenants and users (created through the admin
// API) are persisted.
type Store struct {
	// Type is "file" (default) or "mongo".
	Type string `json:"type,omitempty"`
	// Path is the JSON file for the file store.
	Path string `json:"path,omitempty"`
	// Mongo settings for type "mongo". URI defaults to the upstream.
	URI        string `json:"uri,omitempty"`
	Database   string `json:"database,omitempty"`
	Collection string `json:"collection,omitempty"` // prefix: <c>_tenants, <c>_users
	// RefreshInterval is how often the store is re-read to pick up changes
	// made by other proxy replicas (default 30s; "0s" disables polling).
	RefreshInterval string `json:"refreshInterval,omitempty"`
}

// MetricsOptions tunes the metrics endpoint.
type MetricsOptions struct {
	// TenantLabel bounds the cardinality of the per-tenant "tenant" label.
	TenantLabel TenantLabel `json:"tenantLabel,omitempty"`
}

// TenantLabel controls the tenant label on mtp_tenant_* series.
//
//	top  (default) - the first TopN tenants seen (declared tenants first) get
//	                 their own label value; the rest are folded into "other".
//	hash           - tenants are hashed into HashBuckets label values "b00".."bNN".
//	all            - one label value per tenant (unbounded; use with care).
//	off            - no per-tenant series.
type TenantLabel struct {
	Mode        string `json:"mode,omitempty"`
	TopN        int    `json:"topN,omitempty"`
	HashBuckets int    `json:"hashBuckets,omitempty"`
}

// Audit configures the audit log.
type Audit struct {
	Enabled bool `json:"enabled,omitempty"`
	// Sink is "stdout", "stderr", "file", "syslog" or "http".
	Sink string `json:"sink,omitempty"`
	// File sink.
	Path       string `json:"path,omitempty"`
	MaxSizeMB  int    `json:"maxSizeMB,omitempty"` // rotate at this size (default 100)
	MaxBackups int    `json:"maxBackups,omitempty"`
	// Syslog sink: "" (local), or network+address like "udp://logs:514".
	Syslog string `json:"syslog,omitempty"`
	// HTTP sink: events are POSTed as newline-delimited JSON batches.
	URL    string            `json:"url,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	// SampleReads is the fraction (0..1) of allowed read commands to log.
	// Writes, DDL, denials, auth and admin events are always logged.
	SampleReads float64 `json:"sampleReads,omitempty"`
}

// Tracing configures span hooks (see internal/trace).
type Tracing struct {
	Enabled bool `json:"enabled,omitempty"`
}

func (c *Config) finishOps() error {
	seen := map[string]bool{}
	for _, t := range c.Tenants {
		if t.ID == "" {
			return fmt.Errorf("tenants[].id is required")
		}
		if seen[t.ID] {
			return fmt.Errorf("duplicate tenant %q", t.ID)
		}
		seen[t.ID] = true
		if t.MaxConns < 0 {
			return fmt.Errorf("tenant %q: maxConns must be >= 0", t.ID)
		}
	}
	switch c.Store.Type {
	case "", "file", "mongo":
	default:
		return fmt.Errorf("store.type must be file or mongo")
	}
	if c.Store.RefreshInterval != "" {
		if _, err := time.ParseDuration(c.Store.RefreshInterval); err != nil {
			return fmt.Errorf("store.refreshInterval: %w", err)
		}
	}
	switch c.Metrics.TenantLabel.Mode {
	case "", "top", "hash", "all", "off":
	default:
		return fmt.Errorf("metrics.tenantLabel.mode must be top, hash, all or off")
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logLevel must be debug, info, warn or error")
	}
	if a := c.Audit; a.Enabled {
		switch a.Sink {
		case "stdout", "stderr", "syslog":
		case "file":
			if a.Path == "" {
				return fmt.Errorf("audit.path is required for the file sink")
			}
		case "http":
			if a.URL == "" {
				return fmt.Errorf("audit.url is required for the http sink")
			}
		default:
			return fmt.Errorf("audit.sink must be stdout, stderr, file, syslog or http")
		}
		if a.SampleReads < 0 || a.SampleReads > 1 {
			return fmt.Errorf("audit.sampleReads must be between 0 and 1")
		}
	}
	return nil
}

// RefreshDuration returns the store refresh interval (default 30s).
func (s Store) RefreshDuration() time.Duration {
	if s.RefreshInterval == "" {
		return 30 * time.Second
	}
	d, _ := time.ParseDuration(s.RefreshInterval)
	return d
}

// SlogLevel maps logLevel to a slog level.
func (c *Config) SlogLevel() slog.Level {
	switch c.LogLevel {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
