// Package auth resolves which tenant a client connection belongs to.
package auth

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/xdg-go/scram"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// ErrAuthFailed is returned for any authentication failure.
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
	mode   string
	modes  config.Mode
	static string
	secret []byte
	users  map[string]*user
	sha256 *scram.Server
	sha1   *scram.Server
	x509   []config.X509Rule
	oidc   *oidcVerifier
}

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
	a := &Authenticator{mode: string(cfg.Mode), modes: cfg.Mode, static: cfg.StaticTenant, users: map[string]*user{}, x509: cfg.X509}
	if cfg.AppNameSecret != "" {
		a.secret = []byte(cfg.AppNameSecret)
	}
	for _, u := range cfg.Users {
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
		a.users[u.Username] = nu
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
	u := a.users[name]
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
		u, ok := a.users[name]
		if !ok {
			return scram.StoredCredentials{}, ErrAuthFailed
		}
		c := u.sha256
		if sha1 {
			c = u.sha1
		}
		if c == nil {
			return scram.StoredCredentials{}, ErrAuthFailed
		}
		return *c, nil
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
	if a.secret == nil {
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
	want := SignTenant(string(a.secret), tenant)
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
}

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
	u := s.a.users[s.conv.Username()]
	if u == nil {
		return nil, false, ErrAuthFailed
	}
	s.tenant = u.tenant
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
	h := md5.Sum([]byte(username + ":mongo:" + password))
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
