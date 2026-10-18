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
	// DisableJS rejects server-side JavaScript ($where, $function,
	// $accumulator, mapReduce). It is allowed by default: JavaScript runs
	// inside mongod without access to other documents or collections, and
	// the tenant filter is applied around it.
	DisableJS bool `json:"disableJS,omitempty"`
	// DisableViews turns off tenant-scoped views.
	DisableViews bool `json:"disableViews,omitempty"`
	// ChangeStreams controls collection-level change streams.
	ChangeStreams ChangeStreams `json:"changeStreams,omitempty"`

	MaxMessageBytes   int    `json:"maxMessageBytes,omitempty"`
	MaxConnsPerTenant int    `json:"maxConnsPerTenant,omitempty"`
	IdleTimeout       string `json:"idleTimeout,omitempty"`
	MetricsAddr       string `json:"metricsAddr,omitempty"`
	LogLevel          string `json:"logLevel,omitempty"`
}

// ChangeStreams configures change stream support, which is on by default.
//
// Events are filtered per tenant using collection pre/post images
// (MongoDB 6.0+). Streams that start fresh with no custom stages share one
// upstream stream per collection and are routed by the proxy; everything else
// (resume tokens, custom stages) runs as a private, server-filtered stream.
type ChangeStreams struct {
	// Disabled turns change streams off entirely.
	Disabled bool `json:"disabled,omitempty"`
	// DisableAutoImages stops the proxy from enabling changeStreamPreAndPostImages
	// (with its upstream credentials) the first time a collection is watched.
	DisableAutoImages bool `json:"disableAutoImages,omitempty"`
	// DisableFanout makes every stream a private server-side stream.
	DisableFanout bool `json:"disableFanout,omitempty"`
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

	// IDPolicy controls how document _id values are kept apart between
	// tenants: "native" (default), "require-generated" or "namespace".
	IDPolicy string `json:"idPolicy,omitempty"`
	// ExperimentalNamespace must be set to use idPolicy "namespace", which has
	// documented functional limits (see README).
	ExperimentalNamespace bool `json:"experimentalNamespace,omitempty"`

	// Limits are the default per-tenant quotas; Overrides replace individual
	// fields for named tenants. All zero values mean "unlimited".
	Limits    Limits            `json:"limits,omitempty"`
	Overrides map[string]Limits `json:"overrides,omitempty"`
}

// Limits are per-tenant quotas. Zero means unlimited / not enforced.
type Limits struct {
	// OpsPerSec/OpsBurst: token bucket over commands (burst defaults to one
	// second's worth).
	OpsPerSec float64 `json:"opsPerSec,omitempty"`
	OpsBurst  int     `json:"opsBurst,omitempty"`
	// BytesPerSec/BytesBurst: token bucket over request + reply bytes.
	BytesPerSec int64 `json:"bytesPerSec,omitempty"`
	BytesBurst  int64 `json:"bytesBurst,omitempty"`
	// MaxOpenCursors caps cursors open at once across the tenant's connections.
	MaxOpenCursors int `json:"maxOpenCursors,omitempty"`
	// MaxIndexes caps distinct indexes the tenant may create via the proxy
	// (counted in memory; resets on restart).
	MaxIndexes int `json:"maxIndexes,omitempty"`
	// MaxCommandBytes caps a single command message; MaxResultBytes a single reply.
	MaxCommandBytes int `json:"maxCommandBytes,omitempty"`
	MaxResultBytes  int `json:"maxResultBytes,omitempty"`
	// MaxTimeMSCap clamps client maxTimeMS values; DefaultMaxTimeMS is applied
	// when a read command specifies none.
	MaxTimeMSCap     int64 `json:"maxTimeMSCap,omitempty"`
	DefaultMaxTimeMS int64 `json:"defaultMaxTimeMS,omitempty"`
	// MaxInFlight caps commands executing concurrently for the tenant.
	MaxInFlight int `json:"maxInFlight,omitempty"`
	// DisableJS forbids this tenant from server-side JavaScript; JSPerSec caps
	// how many JavaScript-using commands per second it may run.
	DisableJS bool    `json:"disableJS,omitempty"`
	JSPerSec  float64 `json:"jsPerSec,omitempty"`
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

// CheckIDPolicy validates tenant.idPolicy and switches off the features the
// "namespace" policy cannot support. It is idempotent.
func (c *Config) CheckIDPolicy() error {
	switch c.Tenant.IDPolicy {
	case "", "native", "require-generated":
	case "namespace":
		if !c.Tenant.ExperimentalNamespace {
			return fmt.Errorf("tenant.idPolicy=namespace is experimental; set tenant.experimentalNamespace=true to enable it")
		}
		// Unwrapping _id is not implemented for these paths, so they are off.
		c.ChangeStreams.Disabled = true
		c.DisableViews = true
	default:
		return fmt.Errorf("tenant.idPolicy must be one of native, require-generated, namespace")
	}
	return nil
}

// Validate applies defaults and checks a Config built in code (Load does the
// same for files).
func Validate(c *Config) error { return c.finish() }

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
	if err := c.CheckIDPolicy(); err != nil {
		return err
	}
	for id := range c.Tenant.Overrides {
		if id == "" {
			return fmt.Errorf("tenant.overrides: empty tenant id")
		}
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

// LimitsFor returns the effective limits of a tenant: the defaults with any
// non-zero override fields applied.
func (c *Config) LimitsFor(tenant string) Limits {
	l := c.Tenant.Limits
	o, ok := c.Tenant.Overrides[tenant]
	if !ok {
		return l
	}
	if o.OpsPerSec != 0 {
		l.OpsPerSec = o.OpsPerSec
	}
	if o.OpsBurst != 0 {
		l.OpsBurst = o.OpsBurst
	}
	if o.BytesPerSec != 0 {
		l.BytesPerSec = o.BytesPerSec
	}
	if o.BytesBurst != 0 {
		l.BytesBurst = o.BytesBurst
	}
	if o.MaxOpenCursors != 0 {
		l.MaxOpenCursors = o.MaxOpenCursors
	}
	if o.MaxIndexes != 0 {
		l.MaxIndexes = o.MaxIndexes
	}
	if o.MaxCommandBytes != 0 {
		l.MaxCommandBytes = o.MaxCommandBytes
	}
	if o.MaxResultBytes != 0 {
		l.MaxResultBytes = o.MaxResultBytes
	}
	if o.MaxTimeMSCap != 0 {
		l.MaxTimeMSCap = o.MaxTimeMSCap
	}
	if o.DefaultMaxTimeMS != 0 {
		l.DefaultMaxTimeMS = o.DefaultMaxTimeMS
	}
	if o.MaxInFlight != 0 {
		l.MaxInFlight = o.MaxInFlight
	}
	if o.DisableJS {
		l.DisableJS = true
	}
	if o.JSPerSec != 0 {
		l.JSPerSec = o.JSPerSec
	}
	return l
}
