// Package auth resolves which tenant a client connection belongs to.
package auth

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- MD5 is mandated by the SCRAM-SHA-1 / MONGODB-CR password digest; see SECURITY.md
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xdg-go/scram"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// ErrAuthFailed is returned for any authentication failure.
//
//lint:ignore ST1005 the exact text (capitalised, with a full stop) is what MongoDB servers return, and drivers match it
var ErrAuthFailed = errors.New("Authentication failed.")

// SASL mechanism names.
const (
	MechSCRAM256 = "SCRAM-SHA-256"
	MechSCRAM1   = "SCRAM-SHA-1"
	MechX509     = "MONGODB-X509"
	MechOIDC     = "MONGODB-OIDC"
)

// Authenticator holds credentials and tenant-resolution rules.
type Authenticator struct {
	mode     string
	modes    config.Mode
	static   string
	secretMu sync.RWMutex
	secret   []byte
	users    atomic.Pointer[map[string]*user]
	source   atomic.Pointer[UserSource]
	sha256   *scram.Server
	sha1     *scram.Server
	x509     []config.X509Rule
	oidc     *oidcVerifier
	// decoy derives credentials for names that do not exist, so that the
	// first SCRAM round looks identical for known and unknown users.
	decoy [32]byte
}

// UserSource supplies users that are not in the config file (the tenant
// registry). It is consulted after the config users.
type UserSource interface {
	LookupUser(name string) (config.User, bool)
}

// SetSource installs the dynamic user source.
func (a *Authenticator) SetSource(s UserSource) { a.source.Store(&s) }

type user struct {
	tenant string
	sha256 *scram.StoredCredentials
	sha1   *scram.StoredCredentials
}

func storedCredentials(name, what, salt string, iters int, storedKey, serverKey string) (*scram.StoredCredentials, error) {
	s, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("user %q: %s salt: %w", name, what, err)
	}
	sk, err := base64.StdEncoding.DecodeString(storedKey)
	if err != nil {
		return nil, fmt.Errorf("user %q: %s storedKey: %w", name, what, err)
	}
	srvk, err := base64.StdEncoding.DecodeString(serverKey)
	if err != nil {
		return nil, fmt.Errorf("user %q: %s serverKey: %w", name, what, err)
	}
	if iters <= 0 || len(sk) == 0 || len(srvk) == 0 {
		return nil, fmt.Errorf("user %q: %s credential needs salt, iterations, storedKey and serverKey", name, what)
	}
	return &scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{Salt: string(s), Iters: iters},
		StoredKey:  sk,
		ServerKey:  srvk,
	}, nil
}

// New builds an Authenticator from configuration.
func New(cfg config.Auth) (*Authenticator, error) {
	a := &Authenticator{mode: string(cfg.Mode), modes: cfg.Mode, static: cfg.StaticTenant, x509: cfg.X509}
	if _, err := rand.Read(a.decoy[:]); err != nil {
		return nil, err
	}
	if cfg.AppNameSecret != "" {
		a.secret = []byte(cfg.AppNameSecret)
	}
	if err := a.SetUsers(cfg.Users); err != nil {
		return nil, err
	}
	var err error
	if cfg.Mode.Has("scram") {
		if a.sha256, err = scram.SHA256.NewServer(a.lookup(false)); err != nil {
			return nil, err
		}
	}
	if cfg.Mode.Has("scram-sha-1") {
		if a.sha1, err = scram.SHA1.NewServer(a.lookup(true)); err != nil {
			return nil, err
		}
	}
	if cfg.Mode.Has("oidc") {
		if a.oidc, err = newOIDCVerifier(cfg.OIDC); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// SetUsers atomically replaces the config-file users (used by hot reload). On
// error the previous users stay in effect.
func (a *Authenticator) SetUsers(us []config.User) error {
	m := make(map[string]*user, len(us))
	for _, u := range us {
		pu, err := parseUser(u)
		if err != nil {
			return err
		}
		m[u.Username] = pu
	}
	a.users.Store(&m)
	return nil
}

// SetAppNameSecret replaces the appName HMAC secret (hot reload).
func (a *Authenticator) SetAppNameSecret(secret string) {
	a.secretMu.Lock()
	a.secret = []byte(secret)
	if secret == "" {
		a.secret = nil
	}
	a.secretMu.Unlock()
}

func parseUser(u config.User) (*user, error) {
	if u.TenantID == "" {
		return nil, fmt.Errorf("user %q: tenantId is required", u.Username)
	}
	nu := &user{tenant: u.TenantID}
	if u.StoredKey != "" || u.Salt != "" || u.ServerKey != "" || u.Iterations != 0 {
		c, err := storedCredentials(u.Username, "SCRAM-SHA-256", u.Salt, u.Iterations, u.StoredKey, u.ServerKey)
		if err != nil {
			return nil, err
		}
		nu.sha256 = c
	}
	if u.SHA1 != nil {
		c, err := storedCredentials(u.Username, "SCRAM-SHA-1", u.SHA1.Salt, u.SHA1.Iterations, u.SHA1.StoredKey, u.SHA1.ServerKey)
		if err != nil {
			return nil, err
		}
		nu.sha1 = c
	}
	if nu.sha256 == nil && nu.sha1 == nil {
		return nil, fmt.Errorf("user %q: no credential", u.Username)
	}
	return nu, nil
}

// find resolves a user from the config users, then the dynamic source.
func (a *Authenticator) find(name string) (*user, bool) {
	if m := a.users.Load(); m != nil {
		if u, ok := (*m)[name]; ok {
			return u, true
		}
	}
	if src := a.source.Load(); src != nil {
		if cu, ok := (*src).LookupUser(name); ok {
			if u, err := parseUser(cu); err == nil {
				return u, true
			}
		}
	}
	return nil, false
}

// UserTenant reports the tenant a user is bound to ("" if the user no longer exists).
func (a *Authenticator) UserTenant(name string) string {
	if u, ok := a.find(name); ok {
		return u.tenant
	}
	return ""
}

// UserBound reports whether the named user still exists and is bound to tenant.
func (a *Authenticator) UserBound(name, tenant string) bool {
	if m := a.users.Load(); m != nil {
		if u, ok := (*m)[name]; ok {
			return u.tenant == tenant
		}
	}
	if src := a.source.Load(); src != nil {
		if cu, ok := (*src).LookupUser(name); ok {
			return cu.TenantID == tenant
		}
	}
	return false
}

// Mode reports the configured mode string (comma separated when several).
func (a *Authenticator) Mode() string { return a.mode }

// Has reports whether an auth mode ("scram", "x509", ...) is enabled.
func (a *Authenticator) Has(mode string) bool { return a.modes.Has(mode) }

// Mechanisms lists the SASL mechanisms the proxy accepts, strongest first.
func (a *Authenticator) Mechanisms() []string {
	var out []string
	if a.sha256 != nil {
		out = append(out, MechSCRAM256)
	}
	if a.sha1 != nil {
		out = append(out, MechSCRAM1)
	}
	if len(a.x509) > 0 && a.Has("x509") {
		out = append(out, MechX509)
	}
	if a.oidc != nil {
		out = append(out, MechOIDC)
	}
	return out
}

// SupportedMechs answers hello's saslSupportedMechs ("<db>.<user>"): the
// SCRAM mechanisms the user has credentials for (all enabled ones when the
// user is unknown, so existence is not revealed), plus the certificate and
// token mechanisms.
func (a *Authenticator) SupportedMechs(dbUser string) []string {
	name := dbUser
	if i := strings.IndexByte(dbUser, '.'); i >= 0 {
		name = dbUser[i+1:]
	}
	u, _ := a.find(name)
	var out []string
	for _, m := range a.Mechanisms() {
		switch {
		case m == MechSCRAM256 && u != nil && u.sha256 == nil,
			m == MechSCRAM1 && u != nil && u.sha1 == nil:
			continue
		}
		out = append(out, m)
	}
	return out
}

// StaticTenant returns the tenant for static mode.
func (a *Authenticator) StaticTenant() string { return a.static }

func (a *Authenticator) lookup(sha1 bool) scram.CredentialLookup {
	return func(name string) (scram.StoredCredentials, error) {
		// Unknown users (and users without this mechanism) get a decoy
		// credential and fail at the proof, exactly like a wrong password:
		// failing at the first message would let anyone enumerate user names.
		u, ok := a.find(name)
		if !ok {
			return a.decoyCredentials(name, sha1), nil
		}
		c := u.sha256
		if sha1 {
			c = u.sha1
		}
		if c == nil {
			return a.decoyCredentials(name, sha1), nil
		}
		return *c, nil
	}
}

// decoyCredentials returns stable, unguessable credentials for a user name.
// Nobody knows a password that produces them, so no proof can verify.
func (a *Authenticator) decoyCredentials(name string, sha1 bool) scram.StoredCredentials {
	d := func(label string) []byte {
		m := hmac.New(sha256.New, a.decoy[:])
		m.Write([]byte(label))
		m.Write([]byte{0})
		m.Write([]byte(name))
		return m.Sum(nil)
	}
	iters, salt := 15000, d("salt")
	if sha1 {
		iters, salt = 10000, salt[:16]
	}
	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{Salt: string(salt), Iters: iters},
		StoredKey:  d("stored"),
		ServerKey:  d("server"),
	}
}

// SignTenant produces the appName for a tenant when a secret is configured.
func SignTenant(secret, tenant string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(tenant))
	return tenant + "." + hex.EncodeToString(m.Sum(nil))[:32]
}

// ResolveAppName extracts the tenant from the driver's appName.
func (a *Authenticator) ResolveAppName(appName string) (string, error) {
	a.secretMu.RLock()
	secret := a.secret
	a.secretMu.RUnlock()
	if secret == nil {
		if appName == "" {
			return "", ErrAuthFailed
		}
		return appName, nil
	}
	i := strings.LastIndexByte(appName, '.')
	if i <= 0 {
		return "", ErrAuthFailed
	}
	tenant := appName[:i]
	want := SignTenant(string(secret), tenant)
	if !hmac.Equal([]byte(want), []byte(appName)) {
		return "", ErrAuthFailed
	}
	return tenant, nil
}

// ErrMechanismUnavailable is returned for a mechanism that is not enabled.
var ErrMechanismUnavailable = errors.New("authentication mechanism is not enabled")

// SASL is an in-progress SCRAM conversation with a client.
type SASL struct {
	a         *Authenticator
	conv      *scram.ServerConversation
	skipEmpty bool
	finalSent bool
	tenant    string
	username  string
}

// Username returns the authenticated user name ("" until authentication completes).
func (s *SASL) Username() string { return s.username }

// StartSASL begins a conversation from the client-first message.
func (a *Authenticator) StartSASL(mech string, clientFirst []byte, skipEmpty bool) (*SASL, []byte, error) {
	srv := a.sha256
	if mech == MechSCRAM1 {
		srv = a.sha1
	} else if mech != MechSCRAM256 {
		srv = nil
	}
	if srv == nil {
		return nil, nil, ErrMechanismUnavailable
	}
	s := &SASL{a: a, conv: srv.NewConversation(), skipEmpty: skipEmpty}
	out, err := s.conv.Step(string(clientFirst))
	if err != nil {
		return nil, nil, ErrAuthFailed
	}
	return s, []byte(out), nil
}

// Continue advances the conversation. done reports completion; Tenant is set
// once the client has been authenticated.
func (s *SASL) Continue(payload []byte) (out []byte, done bool, err error) {
	if s.finalSent {
		// Client's empty acknowledgement of the server signature.
		return nil, true, nil
	}
	resp, err := s.conv.Step(string(payload))
	if err != nil || (s.conv.Done() && !s.conv.Valid()) {
		return nil, false, ErrAuthFailed
	}
	if !s.conv.Done() {
		return []byte(resp), false, nil
	}
	s.username = s.conv.Username()
	s.tenant = s.a.UserTenant(s.username)
	if s.tenant == "" {
		return nil, false, ErrAuthFailed
	}
	s.finalSent = true
	return []byte(resp), s.skipEmpty, nil
}

// Tenant returns the authenticated tenant id ("" until authentication completes).
func (s *SASL) Tenant() string { return s.tenant }

// Authenticated reports whether the SCRAM exchange verified the client.
func (s *SASL) Authenticated() bool { return s.finalSent }

// NewUser derives the stored credentials for a password (the output of the
// `hash-password` subcommand).
func NewUser(username, tenant, password string) (config.User, error) {
	client, err := scram.SHA256.NewClient(username, password, "")
	if err != nil {
		return config.User{}, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return config.User{}, err
	}
	const iters = 15000
	cred, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: iters})
	if err != nil {
		return config.User{}, err
	}
	return config.User{
		Username:   username,
		TenantID:   tenant,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Iterations: iters,
		StoredKey:  base64.StdEncoding.EncodeToString(cred.StoredKey),
		ServerKey:  base64.StdEncoding.EncodeToString(cred.ServerKey),
	}, nil
}

// SHA1Password is the legacy MONGODB-CR style digest SCRAM-SHA-1 is computed
// from: hex(md5("<user>:mongo:<password>")).
func SHA1Password(username, password string) string {
	h := md5.Sum([]byte(username + ":mongo:" + password)) // #nosec G401 -- protocol-mandated SCRAM-SHA-1 digest (see SECURITY.md)
	return hex.EncodeToString(h[:])
}

// NewSHA1Credential derives a SCRAM-SHA-1 credential for a password.
func NewSHA1Credential(username, password string) (*config.SCRAMCredential, error) {
	client, err := scram.SHA1.NewClient(username, SHA1Password(username, password), "")
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	const iters = 10000
	cred, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: iters})
	if err != nil {
		return nil, err
	}
	return &config.SCRAMCredential{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Iterations: iters,
		StoredKey:  base64.StdEncoding.EncodeToString(cred.StoredKey),
		ServerKey:  base64.StdEncoding.EncodeToString(cred.ServerKey),
	}, nil
}
