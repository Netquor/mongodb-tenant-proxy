// Package admin implements the tenant admin API: a small JSON/HTTP service on
// its own listener, authenticated by bearer token and/or mTLS.
package admin

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/audit"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/metrics"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
	"github.com/netquor/mongodb-tenant-proxy/internal/tenants"
)

// Backend is what the API needs from the running proxy.
type Backend interface {
	Registry() *tenants.Registry
	Audit() *audit.Logger
	Connections(tenant string) []proxy.ConnInfo
	KillConnection(id int64) (proxy.ConnInfo, bool)
	KillTenant(tenant string) int
	TenantStats(tenant string) metrics.TenantStats
	Reload() (*proxy.ReloadResult, error)
}

// Server is the admin HTTP API.
type Server struct {
	b     Backend
	token []byte
	mtls  bool
	tlsc  *tls.Config
	mux   *http.ServeMux
}

// New builds the API from config. It fails if no authentication is configured.
func New(b Backend, cfg config.Admin) (*Server, error) {
	s := &Server{b: b, mux: http.NewServeMux()}
	tok := cfg.Token
	if cfg.TokenFile != "" {
		raw, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return nil, err
		}
		tok = strings.TrimSpace(string(raw))
	}
	if v := os.Getenv("MTP_ADMIN_TOKEN"); v != "" {
		tok = v
	}
	if tok != "" {
		if len(tok) < 16 {
			return nil, errors.New("admin token must be at least 16 characters")
		}
		s.token = []byte(tok)
	}
	if t := cfg.TLS; t != nil {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		s.tlsc = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if t.ClientCAFile != "" {
			pem, err := os.ReadFile(t.ClientCAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("admin.tls.clientCAFile: no certificates found")
			}
			s.tlsc.ClientCAs, s.tlsc.ClientAuth = pool, tls.VerifyClientCertIfGiven
			s.mtls = true
		}
	}
	if s.token == nil && !s.mtls {
		return nil, errors.New("admin API needs authentication: set admin.token/tokenFile/$MTP_ADMIN_TOKEN or admin.tls.clientCAFile")
	}
	s.routes()
	return s, nil
}

// Handler returns the HTTP handler (authentication included).
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

// TLSConfig returns the listener TLS config (nil for plain HTTP).
func (s *Server) TLSConfig() *tls.Config { return s.tlsc }

// Serve serves on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.tlsc != nil {
		ln = tls.NewListener(ln, s.tlsc)
	}
	hs := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sc)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type ctxKey int

const reqKey ctxKey = 0

type reqInfo struct{ actor, id string }

func (s *Server) authenticate(r *http.Request) (string, bool) {
	if s.mtls && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		return "mtls:" + r.TLS.PeerCertificates[0].Subject.CommonName, true
	}
	if s.token != nil {
		h := r.Header.Get("Authorization")
		if t, ok := strings.CutPrefix(h, "Bearer "); ok && subtle.ConstantTimeCompare([]byte(t), s.token) == 1 {
			return "token", true
		}
	}
	return "", false
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	id := audit.NewID()
	w.Header().Set("X-Correlation-Id", id)
	if r.URL.Path == "/healthz" {
		fmt.Fprintln(w, "ok")
		return
	}
	actor, ok := s.authenticate(r)
	if !ok {
		s.b.Audit().Log(audit.Event{Type: audit.AdminAction, Corr: id, Remote: r.RemoteAddr, Action: r.Method + " " + r.URL.Path, Outcome: "unauthorized"})
		w.Header().Set("WWW-Authenticate", `Bearer realm="mongodb-tenant-proxy"`)
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), reqKey, &reqInfo{actor: actor, id: id}))
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /v1/tenants", s.listTenants)
	m.HandleFunc("POST /v1/tenants", s.createTenant)
	m.HandleFunc("GET /v1/tenants/{id}", s.getTenant)
	m.HandleFunc("PATCH /v1/tenants/{id}", s.patchTenant)
	m.HandleFunc("DELETE /v1/tenants/{id}", s.deleteTenant)
	m.HandleFunc("POST /v1/tenants/{id}/enable", s.setDisabled(false))
	m.HandleFunc("POST /v1/tenants/{id}/disable", s.setDisabled(true))
	m.HandleFunc("GET /v1/tenants/{id}/users", s.listUsers)
	m.HandleFunc("POST /v1/tenants/{id}/users", s.createUser)
	m.HandleFunc("PUT /v1/tenants/{id}/users/{name}", s.resetUser)
	m.HandleFunc("DELETE /v1/tenants/{id}/users/{name}", s.deleteUser)
	m.HandleFunc("GET /v1/tenants/{id}/connections", s.tenantConns)
	m.HandleFunc("DELETE /v1/tenants/{id}/connections", s.killTenantConns)
	m.HandleFunc("GET /v1/tenants/{id}/stats", s.stats)
	m.HandleFunc("GET /v1/connections", s.allConns)
	m.HandleFunc("DELETE /v1/connections/{cid}", s.killConn)
	m.HandleFunc("POST /v1/reload", s.reload)
}

// ---- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	code := 500
	switch {
	case errors.Is(err, tenants.ErrNotFound):
		code = 404
	case errors.Is(err, tenants.ErrExists), errors.Is(err, tenants.ErrReadOnly):
		code = 409
	case errors.Is(err, tenants.ErrInvalid):
		code = 400
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w body: %v", tenants.ErrInvalid, err)
	}
	return nil
}

// record writes the audit event for a mutating call. Never include secrets.
func (s *Server) record(r *http.Request, action, target string, err error) {
	ri, _ := r.Context().Value(reqKey).(*reqInfo)
	e := audit.Event{Type: audit.AdminAction, Action: action, Target: target, Remote: r.RemoteAddr, Outcome: "ok"}
	if ri != nil {
		e.Actor, e.Corr = ri.actor, ri.id
	}
	if err != nil {
		e.Outcome, e.Reason = "error", err.Error()
	}
	s.b.Audit().Log(e)
}

// ---- tenants -----------------------------------------------------------------

type tenantView struct {
	tenants.Tenant
	Users       int `json:"users"`
	Connections int `json:"connections"`
}

func (s *Server) view(t tenants.Tenant) tenantView {
	return tenantView{Tenant: t, Users: len(s.b.Registry().Users(t.ID)), Connections: len(s.b.Connections(t.ID))}
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	ts := s.b.Registry().Tenants()
	out := make([]tenantView, len(ts))
	for i, t := range ts {
		out[i] = s.view(t)
	}
	writeJSON(w, 200, map[string]any{"tenants": out})
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string `json:"id"`
		MaxConns int    `json:"maxConns"`
		Disabled bool   `json:"disabled"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, err)
		return
	}
	t, err := s.b.Registry().CreateTenant(r.Context(), in.ID, in.MaxConns, in.Disabled)
	s.record(r, "tenant.create", in.ID, err)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 201, s.view(t))
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	t, ok := s.b.Registry().Tenant(r.PathValue("id"))
	if !ok {
		fail(w, tenants.ErrNotFound)
		return
	}
	writeJSON(w, 200, s.view(t))
}

func (s *Server) patchTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MaxConns *int  `json:"maxConns"`
		Disabled *bool `json:"disabled"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, err)
		return
	}
	id := r.PathValue("id")
	t, err := s.b.Registry().UpdateTenant(r.Context(), id, in.Disabled, in.MaxConns)
	s.record(r, "tenant.update", id, err)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, 200, s.view(t))
}

func (s *Server) setDisabled(disabled bool) http.HandlerFunc {
	action := "tenant.enable"
	if disabled {
		action = "tenant.disable"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		t, err := s.b.Registry().UpdateTenant(r.Context(), id, &disabled, nil)
		s.record(r, action, id, err)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, s.view(t))
	}
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.b.Registry().DeleteTenant(r.Context(), id)
	s.record(r, "tenant.delete", id, err)
	if err != nil {
		fail(w, err)
		return
	}
	s.b.KillTenant(id)
	w.WriteHeader(204)
}

// ---- users --------------------------------------------------------------------

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.b.Registry().Tenant(id); !ok {
		fail(w, tenants.ErrNotFound)
		return
	}
	writeJSON(w, 200, map[string]any{"users": s.b.Registry().Users(id)})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, err)
		return
	}
	id := r.PathValue("id")
	reg := s.b.Registry()
	if t, ok := reg.Tenant(id); ok && t.Source == tenants.SourceConfig {
		err := tenants.ErrReadOnly
		s.record(r, "user.create", id+"/"+in.Username, err)
		fail(w, err)
		return
	}
	u, pw, err := reg.SetUser(r.Context(), id, in.Username, in.Password, false)
	s.record(r, "user.create", id+"/"+in.Username, err)
	if err != nil {
		fail(w, err)
		return
	}
	resp := map[string]any{"user": u}
	if in.Password == "" {
		resp["password"] = pw // generated: shown exactly once
	}
	writeJSON(w, 201, resp)
}

func (s *Server) resetUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, err)
		return
	}
	id, name := r.PathValue("id"), r.PathValue("name")
	u, pw, err := s.b.Registry().SetUser(r.Context(), id, name, in.Password, true)
	s.record(r, "user.reset-password", id+"/"+name, err)
	if err != nil {
		fail(w, err)
		return
	}
	resp := map[string]any{"user": u}
	if in.Password == "" {
		resp["password"] = pw
	}
	writeJSON(w, 200, resp)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.PathValue("name")
	err := s.b.Registry().DeleteUser(r.Context(), id, name)
	s.record(r, "user.delete", id+"/"+name, err)
	if err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(204)
}

// ---- connections, stats, reload ----------------------------------------------

func (s *Server) tenantConns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"connections": s.b.Connections(r.PathValue("id"))})
}

func (s *Server) allConns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"connections": s.b.Connections("")})
}

func (s *Server) killConn(w http.ResponseWriter, r *http.Request) {
	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil {
		fail(w, fmt.Errorf("%w connection id", tenants.ErrInvalid))
		return
	}
	info, ok := s.b.KillConnection(cid)
	if !ok {
		s.record(r, "connection.kill", r.PathValue("cid"), tenants.ErrNotFound)
		fail(w, tenants.ErrNotFound)
		return
	}
	s.record(r, "connection.kill", fmt.Sprintf("%d (tenant %s)", cid, info.Tenant), nil)
	w.WriteHeader(204)
}

func (s *Server) killTenantConns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n := s.b.KillTenant(id)
	s.record(r, "tenant.kill-connections", id, nil)
	writeJSON(w, 200, map[string]int{"killed": n})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.b.Registry().Tenant(id); !ok {
		fail(w, tenants.ErrNotFound)
		return
	}
	writeJSON(w, 200, s.b.TenantStats(id))
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	res, err := s.b.Reload()
	s.record(r, "config.reload", "", err)
	if err != nil {
		writeJSON(w, 422, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, res)
}
