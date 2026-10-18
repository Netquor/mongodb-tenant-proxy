// Package config loads and validates the proxy configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
)

// Config is the proxy configuration (JSON).
type Config struct {
	// Listen is the client-facing address, e.g. ":27018".
	Listen string `json:"listen"`
	// ClientTLS enables TLS for client connections.
	ClientTLS *ClientTLS `json:"clientTLS,omitempty"`

	Upstream Upstream `json:"upstream"`
	Tenant   Tenant   `json:"tenant"`
	Auth     Auth     `json:"auth"`

	// Databases tenants may access. Empty means everything but admin/local/config.
	Databases []string `json:"databases,omitempty"`
	// DenyCommands disables individual supported commands.
	DenyCommands []string `json:"denyCommands,omitempty"`
	// AllowJS permits $where/$function/$accumulator.
	AllowJS bool `json:"allowJS,omitempty"`

	MaxMessageBytes   int    `json:"maxMessageBytes,omitempty"`
	MaxConnsPerTenant int    `json:"maxConnsPerTenant,omitempty"`
	IdleTimeout       string `json:"idleTimeout,omitempty"`
	MetricsAddr       string `json:"metricsAddr,omitempty"`
	LogLevel          string `json:"logLevel,omitempty"`
}

// ClientTLS configures the listener's TLS.
type ClientTLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Upstream describes the real MongoDB deployment.
type Upstream struct {
	// URI is a convenience form: mongodb://user:pass@host:port/?authSource=admin&tls=true
	URI                string `json:"uri,omitempty"`
	Addr               string `json:"addr,omitempty"`
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	AuthSource         string `json:"authSource,omitempty"`
	TLS                bool   `json:"tls,omitempty"`
	CAFile             string `json:"caFile,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	DialTimeout        string `json:"dialTimeout,omitempty"`
}

// Tenant describes how tenant ownership is stored in documents.
type Tenant struct {
	// Field is the top-level document field holding the tenant id.
	Field string `json:"field,omitempty"`
	// IDType is "string" (default), "objectId" or "int".
	IDType string `json:"idType,omitempty"`
}

// Auth selects how a connection learns its tenant.
//
//	scram    - clients authenticate with SCRAM-SHA-256; each user maps to a tenant.
//	appname  - tenant is the driver's appName ("<tenant>" or "<tenant>.<hmac>").
//	static   - every connection belongs to StaticTenant (run one proxy per tenant).
type Auth struct {
	Mode          string `json:"mode"`
	StaticTenant  string `json:"staticTenant,omitempty"`
	AppNameSecret string `json:"appNameSecret,omitempty"`
	Users         []User `json:"users,omitempty"`
}

// User is a SCRAM-SHA-256 credential bound to a tenant. Use the `hash-password`
// subcommand to generate the salted values.
type User struct {
	Username   string `json:"username"`
	TenantID   string `json:"tenantId"`
	Salt       string `json:"salt"` // base64
	Iterations int    `json:"iterations"`
	StoredKey  string `json:"storedKey"` // base64
	ServerKey  string `json:"serverKey"` // base64
}

// Load reads a config file (if path is non-empty), applies environment
// overrides and defaults, and validates the result.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytesReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if v := os.Getenv("MTP_UPSTREAM_URI"); v != "" {
		c.Upstream.URI = v
	}
	if v := os.Getenv("MTP_UPSTREAM_PASSWORD"); v != "" {
		c.Upstream.Password = v
	}
	if v := os.Getenv("MTP_APPNAME_SECRET"); v != "" {
		c.Auth.AppNameSecret = v
	}
	if err := c.finish(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) finish() error {
	if c.Listen == "" {
		c.Listen = ":27018"
	}
	if c.Tenant.Field == "" {
		c.Tenant.Field = "tenantId"
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 48 * 1024 * 1024
	}
	u := &c.Upstream
	if u.URI != "" {
		p, err := url.Parse(u.URI)
		if err != nil || (p.Scheme != "mongodb") {
			return fmt.Errorf("upstream.uri must be a single-host mongodb:// URI")
		}
		u.Addr = p.Host
		if p.User != nil {
			u.Username = p.User.Username()
			u.Password, _ = p.User.Password()
		}
		q := p.Query()
		if v := q.Get("authSource"); v != "" {
			u.AuthSource = v
		}
		if q.Get("tls") == "true" || q.Get("ssl") == "true" {
			u.TLS = true
		}
	}
	if u.Addr == "" {
		u.Addr = "localhost:27017"
	}
	if u.AuthSource == "" {
		u.AuthSource = "admin"
	}
	switch c.Auth.Mode {
	case "scram":
		if len(c.Auth.Users) == 0 {
			return fmt.Errorf("auth.mode=scram requires auth.users")
		}
	case "appname":
	case "static":
		if c.Auth.StaticTenant == "" {
			return fmt.Errorf("auth.mode=static requires auth.staticTenant")
		}
	default:
		return fmt.Errorf("auth.mode must be one of scram, appname, static")
	}
	for _, d := range []string{c.IdleTimeout, u.DialTimeout} {
		if d != "" {
			if _, err := time.ParseDuration(d); err != nil {
				return err
			}
		}
	}
	return nil
}

// IdleDuration returns the parsed idle timeout (0 = none).
func (c *Config) IdleDuration() time.Duration {
	d, _ := time.ParseDuration(c.IdleTimeout)
	return d
}

// DialDuration returns the upstream dial timeout.
func (c *Config) DialDuration() time.Duration {
	if d, err := time.ParseDuration(c.Upstream.DialTimeout); err == nil && d > 0 {
		return d
	}
	return 10 * time.Second
}
