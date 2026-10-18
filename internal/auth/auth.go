// Package auth resolves which tenant a client connection belongs to.
package auth

import (
	"crypto/hmac"
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
var ErrAuthFailed = errors.New("Authentication failed.")

// Authenticator holds credentials and tenant-resolution rules.
type Authenticator struct {
	mode     string
	static   string
	secretMu sync.RWMutex
	secret   []byte
	users    atomic.Pointer[map[string]*user]
	source   atomic.Pointer[UserSource]
	server   *scram.Server
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
	cred   scram.StoredCredentials
}

// New builds an Authenticator from configuration.
func New(cfg config.Auth) (*Authenticator, error) {
	a := &Authenticator{mode: cfg.Mode, static: cfg.StaticTenant}
	if cfg.AppNameSecret != "" {
		a.secret = []byte(cfg.AppNameSecret)
	}
	if err := a.SetUsers(cfg.Users); err != nil {
		return nil, err
	}
	if cfg.Mode == "scram" {
		s, err := scram.SHA256.NewServer(a.lookup)
		if err != nil {
			return nil, err
		}
		a.server = s
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
	salt, err := base64.StdEncoding.DecodeString(u.Salt)
	if err != nil {
		return nil, fmt.Errorf("user %q: salt: %w", u.Username, err)
	}
	sk, err := base64.StdEncoding.DecodeString(u.StoredKey)
	if err != nil {
		return nil, fmt.Errorf("user %q: storedKey: %w", u.Username, err)
	}
	srvk, err := base64.StdEncoding.DecodeString(u.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("user %q: serverKey: %w", u.Username, err)
	}
	if u.TenantID == "" || u.Iterations <= 0 {
		return nil, fmt.Errorf("user %q: tenantId and iterations are required", u.Username)
	}
	return &user{tenant: u.TenantID, cred: scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{Salt: string(salt), Iters: u.Iterations},
		StoredKey:  sk,
		ServerKey:  srvk,
	}}, nil
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

// Mode reports the configured mode.
func (a *Authenticator) Mode() string { return a.mode }

// StaticTenant returns the tenant for static mode.
func (a *Authenticator) StaticTenant() string { return a.static }

func (a *Authenticator) lookup(name string) (scram.StoredCredentials, error) {
	u, ok := a.find(name)
	if !ok {
		return scram.StoredCredentials{}, ErrAuthFailed
	}
	return u.cred, nil
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

// SASL is an in-progress SCRAM-SHA-256 conversation with a client.
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
func (a *Authenticator) StartSASL(clientFirst []byte, skipEmpty bool) (*SASL, []byte, error) {
	if a.server == nil {
		return nil, nil, errors.New("SCRAM authentication is not enabled")
	}
	s := &SASL{a: a, conv: a.server.NewConversation(), skipEmpty: skipEmpty}
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
