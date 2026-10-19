// Package config loads and validates the proxy configuration.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

	// Compressors lists the wire compression algorithms (snappy, zlib, zstd)
	// advertised to clients in hello, in preference order. Empty disables
	// client-side compression.
	Compressors []string `json:"compressors,omitempty"`

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

	// Tenants declares tenants explicitly (optional).
	Tenants []TenantEntry `json:"tenants,omitempty"`
	// AdminAddr enables the admin API listener (e.g. "127.0.0.1:9103").
	AdminAddr string         `json:"adminAddr,omitempty"`
	Admin     Admin          `json:"admin,omitempty"`
	Store     Store          `json:"store,omitempty"`
	Metrics   MetricsOptions `json:"metrics,omitempty"`
	Audit     Audit          `json:"audit,omitempty"`
	Tracing   Tracing        `json:"tracing,omitempty"`

	// Path is the file the config was loaded from (set by Load; used by reload).
	Path string `json:"-"`

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
	// ClientCAFile is a PEM bundle of CAs that sign client certificates.
	// Required for auth mode x509; the listener then verifies client certs
	// (mandatory when x509 is the only mode, optional when combined).
	ClientCAFile string `json:"clientCAFile,omitempty"`
}

// TLSConfig builds the listener's TLS configuration. requireClientCert makes
// mutual TLS mandatory; with a ClientCAFile and no requirement, a certificate
// is verified if the client presents one.
func (t *ClientTLS) TLSConfig(requireClientCert bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if t.ClientCAFile != "" {
		pem, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("clientTLS.clientCAFile contains no certificates")
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.VerifyClientCertIfGiven
		if requireClientCert {
			tc.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return tc, nil
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
	// AuthMechanism selects how the proxy authenticates upstream:
	// SCRAM-SHA-256 (default when a username is set), SCRAM-SHA-1,
	// MONGODB-X509 (client certificate) or MONGODB-AWS.
	AuthMechanism string `json:"authMechanism,omitempty"`
	// CertFile/KeyFile is the client certificate presented to the upstream
	// (required for MONGODB-X509, optional otherwise). Requires tls.
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	// MONGODB-AWS credentials. When empty the username/password are used,
	// then the AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
	// environment variables.
	AWSAccessKeyID     string `json:"awsAccessKeyId,omitempty"`
	AWSSecretAccessKey string `json:"awsSecretAccessKey,omitempty"`
	AWSSessionToken    string `json:"awsSessionToken,omitempty"`
	// Compressors lists the wire compressors negotiated with the upstream
	// (snappy, zlib, zstd), in preference order. Empty disables compression.
	Compressors []string `json:"compressors,omitempty"`
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

// Mode names the client authentication mechanisms in use. In JSON it is
// either a string ("scram") or a list (["scram", "scram-sha-1", "x509"]).
//
//	scram        - SCRAM-SHA-256; each user maps to a tenant.
//	scram-sha-1  - SCRAM-SHA-1 with the legacy MD5 password digest.
//	x509         - MONGODB-X509: the client certificate subject/SAN maps to a tenant.
//	oidc         - MONGODB-OIDC: a JWT whose claim carries the tenant id.
//	appname      - tenant is the driver's appName ("<tenant>" or "<tenant>.<hmac>").
//	static       - every connection belongs to StaticTenant.
//
// scram, scram-sha-1, x509 and oidc can be combined; appname and static stand
// alone. Internally a list is kept comma separated.
type Mode string

// List returns the individual mode names.
func (m Mode) List() []string {
	var out []string
	for _, p := range strings.Split(string(m), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Has reports whether the mode is enabled.
func (m Mode) Has(name string) bool {
	for _, p := range m.List() {
		if p == name {
			return true
		}
	}
	return false
}

// UnmarshalJSON accepts a string or a list of strings.
func (m *Mode) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*m = Mode(one)
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("auth.mode must be a string or a list of strings")
	}
	*m = Mode(strings.Join(many, ","))
	return nil
}

// MarshalJSON emits a string for one mode and a list for several.
func (m Mode) MarshalJSON() ([]byte, error) {
	if l := m.List(); len(l) > 1 {
		return json.Marshal(l)
	}
	return json.Marshal(string(m))
}

// Auth selects how a connection learns its tenant. See Mode.
type Auth struct {
	Mode          Mode       `json:"mode"`
	StaticTenant  string     `json:"staticTenant,omitempty"`
	AppNameSecret string     `json:"appNameSecret,omitempty"`
	Users         []User     `json:"users,omitempty"`
	X509          []X509Rule `json:"x509,omitempty"`
	OIDC          *OIDC      `json:"oidc,omitempty"`
}

// User is a SCRAM credential bound to a tenant. The flat fields are the
// SCRAM-SHA-256 credential; SHA1 is the SCRAM-SHA-1 credential. Use the
// `hash-password` subcommand to generate them.
type User struct {
	Username   string `json:"username"`
	TenantID   string `json:"tenantId"`
	Salt       string `json:"salt,omitempty"` // base64
	Iterations int    `json:"iterations,omitempty"`
	StoredKey  string `json:"storedKey,omitempty"` // base64
	ServerKey  string `json:"serverKey,omitempty"` // base64

	SHA1 *SCRAMCredential `json:"sha1,omitempty"`
}

// SCRAMCredential is a stored SCRAM credential (salt and keys are base64).
type SCRAMCredential struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	StoredKey  string `json:"storedKey"`
	ServerKey  string `json:"serverKey"`
}

// X509Rule maps a client certificate to a tenant. A certificate matches when
// its subject equals Subject (RFC 2253 form, e.g. "CN=alice,O=acme") or any
// of its SANs (DNS name, e-mail, URI or IP) equals SAN.
type X509Rule struct {
	Subject  string `json:"subject,omitempty"`
	SAN      string `json:"san,omitempty"`
	TenantID string `json:"tenantId"`
}

// OIDC configures MONGODB-OIDC / JWT bearer authentication. Tokens must be
// signed with a key from the JWKS (RS256/384/512, ES256/384/512).
type OIDC struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// JWKSFile or JWKSURI supplies the verification keys.
	JWKSFile string `json:"jwksFile,omitempty"`
	JWKSURI  string `json:"jwksUri,omitempty"`
	// JWKSRefresh is how often a JWKS URI is re-fetched (default 10m).
	JWKSRefresh string `json:"jwksRefresh,omitempty"`
	// TenantClaim holds the tenant id (default "tenant").
	TenantClaim string `json:"tenantClaim,omitempty"`
	// ClockSkew tolerated for exp/nbf (default 30s).
	ClockSkew string `json:"clockSkew,omitempty"`
}

// Load reads a config file (if path is non-empty), applies environment
// overrides and defaults, and validates the result.
func Load(path string) (*Config, error) {
	c := &Config{Path: path}
	if path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- the config path is the operator's -config argument
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
	if err := c.CheckIDPolicy(); err != nil {
		return err
	}
	for id := range c.Tenant.Overrides {
		if id == "" {
			return fmt.Errorf("tenant.overrides: empty tenant id")
		}
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := validateCompressors("compressors", c.Compressors); err != nil {
		return err
	}
	if err := validateCompressors("upstream.compressors", u.Compressors); err != nil {
		return err
	}
	if err := u.validateAuth(); err != nil {
		return err
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
	return c.finishOps()
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
	if v := q.Get("authMechanism"); v != "" {
		u.AuthMechanism = v
	}
	if v := q.Get("compressors"); v != "" && len(u.Compressors) == 0 {
		u.Compressors = strings.Split(v, ",")
	}
	if v := q.Get("maxPoolSize"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			u.Pool.MaxSize = n
		}
	}
	return nil
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

func validateCompressors(field string, list []string) error {
	for _, n := range list {
		switch strings.ToLower(n) {
		case "snappy", "zlib", "zstd":
		default:
			return fmt.Errorf("%s: unknown compressor %q (want snappy, zlib or zstd)", field, n)
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

func (c *Config) validateAuth() error {
	a := &c.Auth
	modes := a.Mode.List()
	if len(modes) == 0 {
		return fmt.Errorf("auth.mode must be one of scram, scram-sha-1, x509, oidc, appname, static")
	}
	for _, m := range modes {
		switch m {
		case "scram":
			// Users may also come from the dynamic store (admin API).
			if !a.anyUser(func(u User) bool { return u.StoredKey != "" }) && c.AdminAddr == "" && len(c.Tenants) == 0 && c.Store.Type == "" {
				return fmt.Errorf("auth.mode=scram requires auth.users (or adminAddr/store for dynamic users)")
			}
		case "scram-sha-1":
			if !a.anyUser(func(u User) bool { return u.SHA1 != nil }) {
				return fmt.Errorf("auth.mode=scram-sha-1 requires auth.users with a sha1 credential (hash-password -sha1)")
			}
		case "x509":
			if len(a.X509) == 0 {
				return fmt.Errorf("auth.mode=x509 requires auth.x509 rules")
			}
			for i, r := range a.X509 {
				if r.TenantID == "" || (r.Subject == "" && r.SAN == "") {
					return fmt.Errorf("auth.x509[%d]: tenantId and subject or san are required", i)
				}
			}
			if c.ClientTLS == nil || c.ClientTLS.ClientCAFile == "" {
				return fmt.Errorf("auth.mode=x509 requires clientTLS with clientCAFile (mutual TLS)")
			}
		case "oidc":
			o := a.OIDC
			if o == nil || o.Issuer == "" || o.Audience == "" || (o.JWKSFile == "") == (o.JWKSURI == "") {
				return fmt.Errorf("auth.mode=oidc requires auth.oidc with issuer, audience and exactly one of jwksFile/jwksUri")
			}
			if o.JWKSURI != "" {
				if err := checkJWKSURI(o.JWKSURI); err != nil {
					return fmt.Errorf("auth.oidc.jwksUri: %w", err)
				}
			}
			for _, d := range []string{o.JWKSRefresh, o.ClockSkew} {
				if d != "" {
					if _, err := time.ParseDuration(d); err != nil {
						return fmt.Errorf("auth.oidc: %w", err)
					}
				}
			}
		case "appname":
			if len(modes) > 1 {
				return fmt.Errorf("auth.mode=appname cannot be combined with other modes")
			}
		case "static":
			if len(modes) > 1 {
				return fmt.Errorf("auth.mode=static cannot be combined with other modes")
			}
			if a.StaticTenant == "" {
				return fmt.Errorf("auth.mode=static requires auth.staticTenant")
			}
		default:
			return fmt.Errorf("auth.mode must be one of scram, scram-sha-1, x509, oidc, appname, static")
		}
	}
	return nil
}

func (a *Auth) anyUser(f func(User) bool) bool {
	for _, u := range a.Users {
		if f(u) {
			return true
		}
	}
	return false
}

// Mechanism returns the effective upstream authentication mechanism ("" when
// the proxy does not authenticate upstream).
func (u *Upstream) Mechanism() string {
	if u.AuthMechanism != "" {
		return strings.ToUpper(u.AuthMechanism)
	}
	if u.Username != "" {
		return "SCRAM-SHA-256"
	}
	return ""
}

func (u *Upstream) validateAuth() error {
	switch u.Mechanism() {
	case "", "SCRAM-SHA-256", "SCRAM-SHA-1":
		if u.AuthMechanism != "" && u.Username == "" {
			return fmt.Errorf("upstream.authMechanism=%s requires a username", u.AuthMechanism)
		}
	case "MONGODB-X509":
		if !u.TLS || u.CertFile == "" || u.KeyFile == "" {
			return fmt.Errorf("upstream MONGODB-X509 requires tls, certFile and keyFile")
		}
	case "MONGODB-AWS":
	default:
		return fmt.Errorf("upstream.authMechanism %q unsupported (SCRAM-SHA-256, SCRAM-SHA-1, MONGODB-X509, MONGODB-AWS)", u.AuthMechanism)
	}
	if (u.CertFile == "") != (u.KeyFile == "") {
		return fmt.Errorf("upstream.certFile and keyFile go together")
	}
	return nil
}

// ListenerTLS builds the client listener's TLS configuration (nil when
// clientTLS is unset). Mutual TLS is mandatory when x509 is the only mode.
func (c *Config) ListenerTLS() (*tls.Config, error) {
	if c.ClientTLS == nil {
		return nil, nil
	}
	return c.ClientTLS.TLSConfig(c.Auth.Mode.Has("x509") && len(c.Auth.Mode.List()) == 1)
}

// checkJWKSURI requires https (plain http only to a loopback host, for local
// identity providers and tests) and no embedded credentials, so the key set
// that decides who may authenticate cannot be fetched or tampered with in
// cleartext across a network.
func checkJWKSURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil {
		return errors.New("must be an absolute URL without userinfo")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip != nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			return nil
		}
		return errors.New("http is only allowed for loopback hosts; use https")
	}
	return errors.New("scheme must be https")
}
