// Package config loads and validates the proxy configuration.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
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
		if v := q.Get("authMechanism"); v != "" {
			u.AuthMechanism = v
		}
		if v := q.Get("compressors"); v != "" && len(u.Compressors) == 0 {
			u.Compressors = strings.Split(v, ",")
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

func (c *Config) validateAuth() error {
	a := &c.Auth
	modes := a.Mode.List()
	if len(modes) == 0 {
		return fmt.Errorf("auth.mode must be one of scram, scram-sha-1, x509, oidc, appname, static")
	}
	for _, m := range modes {
		switch m {
		case "scram":
			if !a.anyUser(func(u User) bool { return u.StoredKey != "" }) {
				return fmt.Errorf("auth.mode=scram requires auth.users")
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
