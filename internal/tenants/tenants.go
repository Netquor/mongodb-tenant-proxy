// Package tenants keeps the registry of tenants and SCRAM users: those declared
// in the config file (read-only) plus dynamic ones created through the admin API
// and persisted in a pluggable Store.
package tenants

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrReadOnly = errors.New("defined in the config file; edit the file and reload")
	ErrInvalid  = errors.New("invalid")
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// Source values.
const (
	SourceConfig  = "config"
	SourceDynamic = "dynamic"
)

// Tenant is a tenant record.
type Tenant struct {
	ID        string    `json:"id" bson:"_id"`
	Disabled  bool      `json:"disabled" bson:"disabled"`
	MaxConns  int       `json:"maxConns,omitempty" bson:"maxConns,omitempty"`
	Source    string    `json:"source" bson:"-"`
	CreatedAt time.Time `json:"createdAt,omitempty" bson:"createdAt"`
}

// User is a SCRAM credential bound to a tenant. Secrets are never serialised
// by the admin API (see UserInfo); the store persists them.
type User struct {
	config.User `bson:",inline"`
	Source      string    `json:"-" bson:"-"`
	CreatedAt   time.Time `json:"createdAt,omitempty" bson:"createdAt"`
}

// UserInfo is the public view of a user.
type UserInfo struct {
	Username  string    `json:"username"`
	TenantID  string    `json:"tenantId"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// Store persists dynamic tenants and users.
type Store interface {
	List(ctx context.Context) ([]Tenant, []User, error)
	PutTenant(ctx context.Context, t Tenant) error
	DeleteTenant(ctx context.Context, id string) error // also removes the tenant's users
	PutUser(ctx context.Context, u User) error
	DeleteUser(ctx context.Context, username string) error
	Close() error
}

type snapshot struct {
	tenants map[string]Tenant
	users   map[string]User
}

// Registry is the merged, in-memory view of config and stored tenants/users.
// Lookups are lock-free; mutations write through to the store.
type Registry struct {
	store Store

	mu          sync.Mutex // serialises mutations/refreshes
	staticT     map[string]Tenant
	staticU     map[string]User
	dynT        map[string]Tenant
	dynU        map[string]User
	cur         atomic.Pointer[snapshot]
	onChange    atomic.Pointer[func()]
	lastRefresh atomic.Int64
}

// NewRegistry builds a registry over store (nil = memory only) and loads it.
func NewRegistry(ctx context.Context, store Store) (*Registry, error) {
	r := &Registry{store: store, staticT: map[string]Tenant{}, staticU: map[string]User{}, dynT: map[string]Tenant{}, dynU: map[string]User{}}
	r.publish()
	if err := r.Refresh(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// OnChange registers a callback invoked (without locks held) after tenants or
// users change, e.g. to disconnect clients of a disabled tenant.
func (r *Registry) OnChange(f func()) { r.onChange.Store(&f) }

func (r *Registry) changed() {
	if f := r.onChange.Load(); f != nil {
		(*f)()
	}
}

// SetStatic installs the tenants and users declared in the config file.
func (r *Registry) SetStatic(ts []config.TenantEntry, us []config.User) {
	r.mu.Lock()
	r.staticT = map[string]Tenant{}
	r.staticU = map[string]User{}
	for _, t := range ts {
		r.staticT[t.ID] = Tenant{ID: t.ID, Disabled: t.Disabled, MaxConns: t.MaxConns, Source: SourceConfig}
	}
	for _, u := range us {
		r.staticU[u.Username] = User{User: u, Source: SourceConfig}
	}
	r.publish()
	r.mu.Unlock()
	r.changed()
}

// publish rebuilds the merged view; r.mu must be held.
func (r *Registry) publish() {
	s := &snapshot{tenants: map[string]Tenant{}, users: map[string]User{}}
	for id, t := range r.dynT {
		t.Source = SourceDynamic
		s.tenants[id] = t
	}
	for id, t := range r.staticT { // config wins
		s.tenants[id] = t
	}
	for n, u := range r.dynU {
		u.Source = SourceDynamic
		s.users[n] = u
	}
	for n, u := range r.staticU {
		s.users[n] = u
	}
	for _, u := range s.users { // users imply their tenant
		if _, ok := s.tenants[u.TenantID]; !ok {
			s.tenants[u.TenantID] = Tenant{ID: u.TenantID, Source: u.Source}
		}
	}
	r.cur.Store(s)
}

// Refresh re-reads the store (picking up changes from other replicas).
func (r *Registry) Refresh(ctx context.Context) error {
	if r.store == nil {
		return nil
	}
	ts, us, err := r.store.List(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.dynT = map[string]Tenant{}
	r.dynU = map[string]User{}
	for _, t := range ts {
		r.dynT[t.ID] = t
	}
	for _, u := range us {
		r.dynU[u.Username] = u
	}
	r.publish()
	r.mu.Unlock()
	r.lastRefresh.Store(time.Now().UnixNano())
	r.changed()
	return nil
}

// Run refreshes the store every interval until ctx ends. errf (optional)
// receives refresh errors.
func (r *Registry) Run(ctx context.Context, every time.Duration, errf func(error)) {
	if r.store == nil || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Refresh(ctx); err != nil && errf != nil {
				errf(err)
			}
		}
	}
}

// Close closes the store.
func (r *Registry) Close() error {
	if r.store != nil {
		return r.store.Close()
	}
	return nil
}

// ---- reads (lock-free) ----------------------------------------------------

// Tenant returns a tenant by id.
func (r *Registry) Tenant(id string) (Tenant, bool) { t, ok := r.cur.Load().tenants[id]; return t, ok }

// Disabled reports whether the tenant is administratively disabled.
func (r *Registry) Disabled(id string) bool { return r.cur.Load().tenants[id].Disabled }

// MaxConns returns the tenant's connection cap override (0 = none).
func (r *Registry) MaxConns(id string) int { return r.cur.Load().tenants[id].MaxConns }

// LookupUser implements auth.UserSource.
func (r *Registry) LookupUser(name string) (config.User, bool) {
	u, ok := r.cur.Load().users[name]
	return u.User, ok
}

// Tenants lists all tenants sorted by id.
func (r *Registry) Tenants() []Tenant {
	s := r.cur.Load()
	out := make([]Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Users lists a tenant's users sorted by name.
func (r *Registry) Users(tenant string) []UserInfo {
	s := r.cur.Load()
	var out []UserInfo
	for _, u := range s.users {
		if u.TenantID == tenant {
			out = append(out, UserInfo{Username: u.Username, TenantID: u.TenantID, Source: u.Source, CreatedAt: u.CreatedAt})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// ---- mutations -------------------------------------------------------------

func (r *Registry) store1(ctx context.Context, f func(Store) error) error {
	if r.store == nil {
		return nil
	}
	return f(r.store)
}

// CreateTenant adds a dynamic tenant.
func (r *Registry) CreateTenant(ctx context.Context, id string, maxConns int, disabled bool) (Tenant, error) {
	if !nameRE.MatchString(id) || maxConns < 0 {
		return Tenant{}, fmt.Errorf("%w tenant id or maxConns", ErrInvalid)
	}
	r.mu.Lock()
	if _, ok := r.cur.Load().tenants[id]; ok {
		r.mu.Unlock()
		return Tenant{}, ErrExists
	}
	t := Tenant{ID: id, MaxConns: maxConns, Disabled: disabled, Source: SourceDynamic, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if err := r.store1(ctx, func(s Store) error { return s.PutTenant(ctx, t) }); err != nil {
		r.mu.Unlock()
		return Tenant{}, err
	}
	r.dynT[id] = t
	r.publish()
	r.mu.Unlock()
	r.changed()
	return t, nil
}

// UpdateTenant changes a dynamic tenant's settings. Nil arguments are left alone.
func (r *Registry) UpdateTenant(ctx context.Context, id string, disabled *bool, maxConns *int) (Tenant, error) {
	r.mu.Lock()
	if _, ok := r.staticT[id]; ok {
		r.mu.Unlock()
		return Tenant{}, ErrReadOnly
	}
	t, ok := r.dynT[id]
	if !ok {
		if cur, implicit := r.cur.Load().tenants[id]; implicit && cur.Source == SourceDynamic {
			// implied by a dynamic user: materialise it
			t = Tenant{ID: id, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
		} else {
			r.mu.Unlock()
			return Tenant{}, ErrNotFound
		}
	}
	if disabled != nil {
		t.Disabled = *disabled
	}
	if maxConns != nil {
		if *maxConns < 0 {
			r.mu.Unlock()
			return Tenant{}, fmt.Errorf("%w maxConns", ErrInvalid)
		}
		t.MaxConns = *maxConns
	}
	if err := r.store1(ctx, func(s Store) error { return s.PutTenant(ctx, t) }); err != nil {
		r.mu.Unlock()
		return Tenant{}, err
	}
	r.dynT[id] = t
	r.publish()
	r.mu.Unlock()
	r.changed()
	t.Source = SourceDynamic
	return t, nil
}

// DeleteTenant removes a dynamic tenant and its dynamic users.
func (r *Registry) DeleteTenant(ctx context.Context, id string) error {
	r.mu.Lock()
	if _, ok := r.staticT[id]; ok {
		r.mu.Unlock()
		return ErrReadOnly
	}
	_, has := r.dynT[id]
	for _, u := range r.dynU {
		if u.TenantID == id {
			has = true
		}
	}
	if !has {
		r.mu.Unlock()
		return ErrNotFound
	}
	for _, u := range r.staticU {
		if u.TenantID == id {
			r.mu.Unlock()
			return ErrReadOnly
		}
	}
	if err := r.store1(ctx, func(s Store) error { return s.DeleteTenant(ctx, id) }); err != nil {
		r.mu.Unlock()
		return err
	}
	delete(r.dynT, id)
	for n, u := range r.dynU {
		if u.TenantID == id {
			delete(r.dynU, n)
		}
	}
	r.publish()
	r.mu.Unlock()
	r.changed()
	return nil
}

// GeneratePassword returns a random URL-safe password.
func GeneratePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SetUser creates a user (or, with replace, resets its password) for a tenant.
// An empty password generates one; the plaintext is returned once.
func (r *Registry) SetUser(ctx context.Context, tenant, username, password string, replace bool) (UserInfo, string, error) {
	if !nameRE.MatchString(username) || !nameRE.MatchString(tenant) {
		return UserInfo{}, "", fmt.Errorf("%w tenant or username", ErrInvalid)
	}
	if password == "" {
		p, err := GeneratePassword()
		if err != nil {
			return UserInfo{}, "", err
		}
		password = p
	}
	cu, err := auth.NewUser(username, tenant, password)
	if err != nil {
		return UserInfo{}, "", err
	}
	r.mu.Lock()
	if _, ok := r.staticU[username]; ok {
		r.mu.Unlock()
		return UserInfo{}, "", ErrReadOnly
	}
	old, exists := r.dynU[username]
	if exists && !replace {
		r.mu.Unlock()
		return UserInfo{}, "", ErrExists
	}
	if !exists && replace {
		r.mu.Unlock()
		return UserInfo{}, "", ErrNotFound
	}
	if exists && old.TenantID != tenant {
		r.mu.Unlock()
		return UserInfo{}, "", ErrNotFound
	}
	u := User{User: cu, Source: SourceDynamic, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if exists {
		u.CreatedAt = old.CreatedAt
	}
	if err := r.store1(ctx, func(s Store) error { return s.PutUser(ctx, u) }); err != nil {
		r.mu.Unlock()
		return UserInfo{}, "", err
	}
	r.dynU[username] = u
	r.publish()
	r.mu.Unlock()
	r.changed()
	return UserInfo{Username: username, TenantID: tenant, Source: SourceDynamic, CreatedAt: u.CreatedAt}, password, nil
}

// DeleteUser removes a dynamic user of a tenant.
func (r *Registry) DeleteUser(ctx context.Context, tenant, username string) error {
	r.mu.Lock()
	if u, ok := r.staticU[username]; ok && u.TenantID == tenant {
		r.mu.Unlock()
		return ErrReadOnly
	}
	u, ok := r.dynU[username]
	if !ok || u.TenantID != tenant {
		r.mu.Unlock()
		return ErrNotFound
	}
	if err := r.store1(ctx, func(s Store) error { return s.DeleteUser(ctx, username) }); err != nil {
		r.mu.Unlock()
		return err
	}
	delete(r.dynU, username)
	r.publish()
	r.mu.Unlock()
	r.changed()
	return nil
}
