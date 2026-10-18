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

	"github.com/xdg-go/scram"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// ErrAuthFailed is returned for any authentication failure.
var ErrAuthFailed = errors.New("Authentication failed.")

// Authenticator holds credentials and tenant-resolution rules.
type Authenticator struct {
	mode   string
	static string
	secret []byte
	users  map[string]*user
	server *scram.Server
}

type user struct {
	tenant string
	cred   scram.StoredCredentials
}

// New builds an Authenticator from configuration.
func New(cfg config.Auth) (*Authenticator, error) {
	a := &Authenticator{mode: cfg.Mode, static: cfg.StaticTenant, users: map[string]*user{}}
	if cfg.AppNameSecret != "" {
		a.secret = []byte(cfg.AppNameSecret)
	}
	for _, u := range cfg.Users {
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
		a.users[u.Username] = &user{tenant: u.TenantID, cred: scram.StoredCredentials{
			KeyFactors: scram.KeyFactors{Salt: string(salt), Iters: u.Iterations},
			StoredKey:  sk,
			ServerKey:  srvk,
		}}
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

// Mode reports the configured mode.
func (a *Authenticator) Mode() string { return a.mode }

// StaticTenant returns the tenant for static mode.
func (a *Authenticator) StaticTenant() string { return a.static }

func (a *Authenticator) lookup(name string) (scram.StoredCredentials, error) {
	u, ok := a.users[name]
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

// SASL is an in-progress SCRAM-SHA-256 conversation with a client.
type SASL struct {
	a         *Authenticator
	conv      *scram.ServerConversation
	skipEmpty bool
	finalSent bool
	tenant    string
}

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
	s.tenant = s.a.users[s.conv.Username()].tenant
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
