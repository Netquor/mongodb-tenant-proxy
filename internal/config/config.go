// Package config loads and validates the proxy configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
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

	// Streaming controls how upstream replies are relayed to clients.
	Streaming Streaming `json:"streaming,omitempty"`

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

// Streaming bounds the memory used to relay upstream replies.
//
// Replies up to ThresholdBytes are read into memory (so the proxy can inspect
// them). Larger replies that need no rewriting are relayed to the client in
// chunks with constant memory. Replies that must be rewritten are buffered, but
// never beyond MaxPatchBytes: a larger one fails with an error instead of
// exhausting memory.
type Streaming struct {
	// ThresholdBytes defaults to 256 KiB. Set to -1 to always buffer.
	ThresholdBytes int `json:"thresholdBytes,omitempty"`
	// MaxPatchBytes defaults to maxMessageBytes.
	MaxPatchBytes int `json:"maxPatchBytes,omitempty"`
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

	// Hosts lists the members to connect to. Each entry is either "host:port"
	// or an object {"addr", "tls", "caFile", "insecureSkipVerify", "serverName"}
	// that overrides the global TLS settings for that member. With a
	// replicaSet (or several hosts) the proxy discovers the rest of the set and
	// follows primary changes; a single host is used as-is (like
	// directConnection=true) unless directConnection is explicitly false.
	Hosts []Host `json:"hosts,omitempty"`
	// ReplicaSet is the expected replica set name.
	ReplicaSet string `json:"replicaSet,omitempty"`
	// DirectConnection forces (true) or disables (false) direct mode. The
	// default is direct for a single host without a replicaSet.
	DirectConnection *bool `json:"directConnection,omitempty"`
	// HostMap rewrites member addresses advertised by the replica set (for
	// example container names) to addresses the proxy can reach.
	HostMap map[string]string `json:"hostMap,omitempty"`
	// HeartbeatInterval is how often each member is polled (default 5s).
	HeartbeatInterval string `json:"heartbeatInterval,omitempty"`
	// ServerSelectionTimeout bounds waiting for a suitable member (default 15s).
	ServerSelectionTimeout string `json:"serverSelectionTimeout,omitempty"`
	// LocalThreshold is the latency window for choosing among eligible
	// members (default 15ms).
	LocalThreshold string `json:"localThreshold,omitempty"`
	// Pool configures upstream connection pooling.
	Pool Pool `json:"pool,omitempty"`
}

// Host is one upstream member, optionally with its own TLS settings.
type Host struct {
	Addr               string `json:"addr"`
	TLS                *bool  `json:"tls,omitempty"`
	CAFile             string `json:"caFile,omitempty"`
	InsecureSkipVerify *bool  `json:"insecureSkipVerify,omitempty"`
	ServerName         string `json:"serverName,omitempty"`
}

// UnmarshalJSON accepts a bare "host:port" string or an object.
func (h *Host) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*h = Host{Addr: s}
		return nil
	}
	type plain Host
	return json.Unmarshal(b, (*plain)(h))
}

// Pool configures upstream connection pooling.
//
// In "pooled" mode (default) a client connection borrows an upstream
// connection only for the duration of a command, so many clients share few
// upstream connections. It keeps one while a transaction or a change-stream
// cursor is open. In "dedicated" mode every client connection owns an
// upstream connection per member it talks to, for its whole lifetime.
type Pool struct {
	Mode string `json:"mode,omitempty"` // "pooled" (default) | "dedicated"
	// MaxSize bounds connections per member (default 100).
	MaxSize int `json:"maxSize,omitempty"`
	// IdleTimeout closes connections idle this long (default 5m).
	IdleTimeout string `json:"idleTimeout,omitempty"`
	// MaxLifetime recycles connections older than this (default none).
	MaxLifetime string `json:"maxLifetime,omitempty"`
	// WaitTimeout bounds waiting for a free connection (default serverSelectionTimeout).
	WaitTimeout string `json:"waitTimeout,omitempty"`
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
		if err := u.applyURI(); err != nil {
			return err
		}
	}
	if u.Addr != "" && len(u.Hosts) == 0 {
		u.Hosts = []Host{{Addr: u.Addr}}
	}
	if len(u.Hosts) == 0 {
		u.Hosts = []Host{{Addr: "localhost:27017"}}
	}
	u.Addr = u.Hosts[0].Addr
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
	switch u.Pool.Mode {
	case "", "pooled", "dedicated":
	default:
		return fmt.Errorf("upstream.pool.mode must be pooled or dedicated")
	}
	if u.Pool.MaxSize < 0 {
		return fmt.Errorf("upstream.pool.maxSize must be positive")
	}
	if c.Streaming.MaxPatchBytes == 0 {
		c.Streaming.MaxPatchBytes = c.MaxMessageBytes
	}
	if c.Streaming.ThresholdBytes == 0 {
		c.Streaming.ThresholdBytes = 256 * 1024
	}
	for _, d := range []string{c.IdleTimeout, u.DialTimeout, u.HeartbeatInterval, u.ServerSelectionTimeout,
		u.LocalThreshold, u.Pool.IdleTimeout, u.Pool.MaxLifetime, u.Pool.WaitTimeout} {
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

// applyURI folds a mongodb:// URI (one or more hosts) into the structured fields.
func (u *Upstream) applyURI() error {
	raw := u.URI
	const pfx = "mongodb://"
	if !strings.HasPrefix(raw, pfx) {
		return fmt.Errorf("upstream.uri must be a mongodb:// URI")
	}
	rest := raw[len(pfx):]
	end := len(rest)
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		end = i
	}
	authority, tail := rest[:end], rest[end:]
	var userinfo string
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		userinfo, authority = authority[:i], authority[i+1:]
	}
	if authority == "" {
		return fmt.Errorf("upstream.uri has no host")
	}
	// Reuse net/url for credentials and the query string.
	p, err := url.Parse(pfx + userinfoPrefix(userinfo) + "x" + tail)
	if err != nil {
		return fmt.Errorf("upstream.uri: %w", err)
	}
	if p.User != nil {
		u.Username = p.User.Username()
		u.Password, _ = p.User.Password()
	}
	var hosts []Host
	for _, h := range strings.Split(authority, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, Host{Addr: withDefaultPort(h)})
		}
	}
	u.Hosts = hosts
	q := p.Query()
	if v := q.Get("authSource"); v != "" {
		u.AuthSource = v
	}
	if q.Get("tls") == "true" || q.Get("ssl") == "true" {
		u.TLS = true
	}
	if v := q.Get("replicaSet"); v != "" {
		u.ReplicaSet = v
	}
	if v := q.Get("directConnection"); v != "" {
		b := v == "true"
		u.DirectConnection = &b
	}
	if v := q.Get("heartbeatFrequencyMS"); v != "" {
		u.HeartbeatInterval = v + "ms"
	}
	if v := q.Get("serverSelectionTimeoutMS"); v != "" {
		u.ServerSelectionTimeout = v + "ms"
	}
	if v := q.Get("localThresholdMS"); v != "" {
		u.LocalThreshold = v + "ms"
	}
	if v := q.Get("maxPoolSize"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			u.Pool.MaxSize = n
		}
	}
	return nil
}

func userinfoPrefix(ui string) string {
	if ui == "" {
		return ""
	}
	return ui + "@"
}

func withDefaultPort(h string) string {
	if strings.HasPrefix(h, "[") {
		if strings.Contains(h, "]:") {
			return h
		}
		return h + ":27017"
	}
	if strings.Contains(h, ":") {
		return h
	}
	return h + ":27017"
}

func (u *Upstream) dur(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// Heartbeat returns the member polling interval.
func (u *Upstream) Heartbeat() time.Duration { return u.dur(u.HeartbeatInterval, 5*time.Second) }

// SelectionTimeout returns how long to wait for a suitable member.
func (u *Upstream) SelectionTimeout() time.Duration {
	return u.dur(u.ServerSelectionTimeout, 15*time.Second)
}

// Threshold returns the latency window.
func (u *Upstream) Threshold() time.Duration { return u.dur(u.LocalThreshold, 15*time.Millisecond) }

// Direct reports whether the proxy talks to a single fixed member.
func (u *Upstream) Direct() bool {
	if u.DirectConnection != nil {
		return *u.DirectConnection
	}
	return len(u.Hosts) == 1 && u.ReplicaSet == ""
}

// PoolMaxSize returns the per-member connection bound.
func (u *Upstream) PoolMaxSize() int {
	if u.Pool.MaxSize > 0 {
		return u.Pool.MaxSize
	}
	return 100
}

// Pooled reports whether connections are shared between clients.
func (u *Upstream) Pooled() bool { return u.Pool.Mode != "dedicated" }

// PoolIdle returns the idle timeout.
func (u *Upstream) PoolIdle() time.Duration { return u.dur(u.Pool.IdleTimeout, 5*time.Minute) }

// PoolLifetime returns the maximum connection age (0 = unlimited).
func (u *Upstream) PoolLifetime() time.Duration { return u.dur(u.Pool.MaxLifetime, 0) }

// PoolWait returns how long to wait for a free pooled connection.
func (u *Upstream) PoolWait() time.Duration { return u.dur(u.Pool.WaitTimeout, u.SelectionTimeout()) }

// HostList returns the configured members (Hosts, else Addr, else localhost).
func (u *Upstream) HostList() []Host {
	if len(u.Hosts) > 0 {
		return u.Hosts
	}
	if u.Addr != "" {
		return []Host{{Addr: u.Addr}}
	}
	return []Host{{Addr: "localhost:27017"}}
}
