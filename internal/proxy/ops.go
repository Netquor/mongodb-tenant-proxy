package proxy

// Operability hooks: live config reload, tenant status enforcement, connection
// inspection, per-tenant metrics and audit events. Kept out of the request
// path files so that the diff there stays small.

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/audit"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/metrics"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/tenants"
	"github.com/netquor/mongodb-tenant-proxy/internal/trace"
)

// runtime holds the settings that hot reload can change. It is replaced as a
// whole (atomic pointer) so readers never see a half-applied reload.
type runtime struct {
	rw           *rewrite.Rewriter
	maxConns     int
	idle         time.Duration
	maxMessage   int
	disableViews bool
	tracing      bool
	cl           config.ConnLimits
}

func (s *Server) newRuntime(cfg *config.Config) *runtime {
	return &runtime{
		rw: rewrite.New(rewrite.Config{
			Field:         cfg.Tenant.Field,
			Databases:     cfg.Databases,
			DenyCommands:  cfg.DenyCommands,
			AllowJS:       !cfg.DisableJS,
			ChangeStreams: !cfg.ChangeStreams.Disabled,
			IDPolicy:      cfg.Tenant.IDPolicy,
			AtomicOut:     s.txnSupported,
		}),
		maxConns:     cfg.MaxConnsPerTenant,
		idle:         cfg.IdleDuration(),
		maxMessage:   cfg.MaxMessageBytes,
		disableViews: cfg.DisableViews,
		tracing:      cfg.Tracing.Enabled,
		cl:           cfg.ConnLimits,
	}
}

func (s *Server) rt() *runtime { return s.run.Load() }

// opsState is embedded in Server.
type opsState struct {
	run      atomic.Pointer[runtime]
	reg      *tenants.Registry
	audit    *audit.Logger
	reloadMu sync.Mutex
	hooks    []func(*config.Config)
}

// initOps builds the registry (and its store), audit logger and runtime.
func (s *Server) initOps(ctx context.Context, cfg *config.Config) error {
	s.run.Store(s.newRuntime(cfg))
	var st tenants.Store
	switch cfg.Store.Type {
	case "mongo":
		uri := cfg.Store.URI
		if uri == "" {
			u := url.URL{Scheme: "mongodb", Host: cfg.Upstream.Addr, Path: "/"}
			if cfg.Upstream.Username != "" {
				u.User = url.UserPassword(cfg.Upstream.Username, cfg.Upstream.Password)
			}
			q := url.Values{"authSource": {cfg.Upstream.AuthSource}, "directConnection": {"true"}}
			if cfg.Upstream.TLS {
				q.Set("tls", "true")
			}
			u.RawQuery = q.Encode()
			uri = u.String()
		}
		ms, err := tenants.NewMongoStore(ctx, uri, cfg.Store.Database, cfg.Store.Collection)
		if err != nil {
			return err
		}
		st = ms
	case "file":
		p := cfg.Store.Path
		if p == "" {
			p = "tenants.json"
		}
		st = tenants.NewFileStore(p)
	default:
		if cfg.Store.Path != "" {
			st = tenants.NewFileStore(cfg.Store.Path)
		}
	}
	reg, err := tenants.NewRegistry(ctx, st)
	if err != nil {
		return err
	}
	s.reg = reg
	reg.SetStatic(cfg.Tenants, cfg.Auth.Users)
	s.pinTenants(cfg)
	s.auth.SetSource(reg)
	reg.OnChange(s.enforce)
	al, err := audit.New(cfg.Audit)
	if err != nil {
		return err
	}
	s.audit = al
	s.M.SetGaugeSource(s.tenantGauges)
	return nil
}

func (s *Server) pinTenants(cfg *config.Config) {
	var ids []string
	for _, t := range cfg.Tenants {
		ids = append(ids, t.ID)
	}
	for _, u := range cfg.Auth.Users {
		ids = append(ids, u.TenantID)
	}
	s.M.PinTenants(ids)
}

// Registry exposes the tenant/user registry (for the admin API).
func (s *Server) Registry() *tenants.Registry { return s.reg }

// Audit exposes the audit logger (nil when disabled; safe to call).
func (s *Server) Audit() *audit.Logger { return s.audit }

// OnReload registers a callback run after each successful reload.
func (s *Server) OnReload(f func(*config.Config)) {
	s.reloadMu.Lock()
	s.hooks = append(s.hooks, f)
	s.reloadMu.Unlock()
}

// ReloadResult describes a reload.
type ReloadResult struct {
	// RestartRequired lists changed settings that only apply after a restart.
	RestartRequired []string `json:"restartRequired,omitempty"`
}

// Reload re-reads the config file and applies it.
func (s *Server) Reload() (*ReloadResult, error) {
	if s.cfg.Path == "" {
		return nil, fmt.Errorf("no config file to reload")
	}
	cfg, err := config.Load(s.cfg.Path)
	if err != nil {
		s.auditReload(false, err.Error())
		return nil, err
	}
	return s.ReloadConfig(cfg)
}

// ReloadConfig atomically applies a validated config. Reloadable: auth.users,
// auth.appNameSecret, tenants, databases, denyCommands, disableJS,
// disableViews, maxConnsPerTenant, idleTimeout, maxMessageBytes, logLevel,
// audit.sampleReads. Everything else is reported in RestartRequired and left
// unchanged. On error nothing is changed.
func (s *Server) ReloadConfig(cfg *config.Config) (*ReloadResult, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if err := s.auth.SetUsers(cfg.Auth.Users); err != nil { // the only fallible step
		s.auditReload(false, err.Error())
		return nil, err
	}
	s.auth.SetAppNameSecret(cfg.Auth.AppNameSecret)
	// Keep the startup-time values for settings that cannot change live.
	next := *cfg
	next.Tenant = s.cfg.Tenant
	next.ChangeStreams = s.cfg.ChangeStreams
	s.run.Store(s.newRuntime(&next))
	s.reg.SetStatic(cfg.Tenants, cfg.Auth.Users) // triggers enforce()
	s.pinTenants(cfg)
	s.audit.SetSampleReads(cfg.Audit.SampleReads)
	res := &ReloadResult{RestartRequired: restartRequired(s.cfg, cfg)}
	for _, h := range s.hooks {
		h(cfg)
	}
	s.log.Info("config reloaded", "restartRequired", res.RestartRequired)
	s.auditReload(true, "")
	return res, nil
}

func (s *Server) auditReload(ok bool, reason string) {
	o := "ok"
	if !ok {
		o = "error"
	}
	s.audit.Log(audit.Event{Type: audit.ConfigReload, Outcome: o, Reason: reason})
}

func restartRequired(old, cur *config.Config) []string {
	var out []string
	chk := func(name string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			out = append(out, name)
		}
	}
	chk("listen", old.Listen, cur.Listen)
	chk("clientTLS", old.ClientTLS, cur.ClientTLS)
	chk("upstream", old.Upstream, cur.Upstream)
	chk("tenant", old.Tenant, cur.Tenant)
	chk("auth.mode", old.Auth.Mode, cur.Auth.Mode)
	chk("auth.staticTenant", old.Auth.StaticTenant, cur.Auth.StaticTenant)
	chk("auth.bruteForce", old.Auth.BruteForce, cur.Auth.BruteForce)
	chk("changeStreams", old.ChangeStreams, cur.ChangeStreams)
	chk("metricsAddr", old.MetricsAddr, cur.MetricsAddr)
	chk("adminAddr", old.AdminAddr, cur.AdminAddr)
	chk("admin", old.Admin, cur.Admin)
	chk("store", old.Store, cur.Store)
	chk("metrics", old.Metrics, cur.Metrics)
	a, b := old.Audit, cur.Audit
	a.SampleReads, b.SampleReads = 0, 0
	chk("audit", a, b)
	return out
}

// ---- connection state -------------------------------------------------------

// connOps is embedded in conn.
type connOps struct {
	sess    string
	since   time.Time
	tm      *metrics.Tenant
	tenantP atomic.Pointer[string]
	userP   atomic.Pointer[string]
	killed  atomic.Pointer[string]

	saslUser string // user named in saslStart (unverified; for failure audit)

	seq      uint64 // owned by the conn goroutine
	curDB    string
	cmdName  string
	cmdStart time.Time
	corr     string
	span     trace.Span

	nCursors atomic.Int64
	nStreams atomic.Int64
	nCmds    atomic.Int64
	bIn      atomic.Int64
	bOut     atomic.Int64
}

func (c *conn) initOps() {
	c.sess = audit.NewID()
	c.since = time.Now()
	c.tm = c.s.M.Tenant("")
}

func (c *conn) tenantID() string {
	if p := c.tenantP.Load(); p != nil {
		return *p
	}
	return ""
}

func (c *conn) userName() string {
	if p := c.userP.Load(); p != nil {
		return *p
	}
	return ""
}

func (c *conn) setUser(u string) { c.userP.Store(&u) }

// onBind is called when the connection learns its tenant.
func (c *conn) onBind(id string) {
	c.tenantP.Store(&id)
	c.tm = c.s.M.Tenant(id)
	c.tm.ConnsTotal.Add(1)
}

func (c *conn) event(typ string) audit.Event {
	remote := ""
	if c.nc != nil {
		remote = c.nc.RemoteAddr().String()
	}
	return audit.Event{Type: typ, Session: c.sess, ConnID: c.id, Tenant: c.tenantID(), User: c.userName(), Remote: remote}
}

func (c *conn) countIn(n int64) {
	c.s.M.BytesIn.Add(n)
	c.tm.BytesIn.Add(n)
	c.bIn.Add(n)
}

func (c *conn) countOut(n int64) {
	c.s.M.BytesOut.Add(n)
	c.tm.BytesOut.Add(n)
	c.bOut.Add(n)
}

// beginCmd marks the start of a command (called once the name is known).
func (c *conn) beginCmd(name, db string) {
	c.seq++
	c.curDB, c.cmdName, c.cmdStart = db, name, time.Now()
	c.corr = fmt.Sprintf("%s-%d", c.sess, c.seq)
	c.nCmds.Add(1)
	if c.s.rt().tracing {
		c.span = trace.Start("mongodb."+name, trace.Attrs{Tenant: c.tenantID(), User: c.userName(), DB: db, Command: name, Session: c.sess, Corr: c.corr})
	}
}

var (
	ddlCmds   = map[string]bool{"create": true, "drop": true, "dropDatabase": true, "createIndexes": true, "dropIndexes": true, "collMod": true, "renameCollection": true, "createView": true}
	writeCmds = map[string]bool{"insert": true, "update": true, "delete": true, "findAndModify": true, "findandmodify": true}
	readCmds  = map[string]bool{"find": true, "aggregate": true, "count": true, "distinct": true, "getMore": true, "listCollections": true, "listIndexes": true}
)

// cmdDone records a finished command in global and per-tenant metrics, the
// audit log and the trace span. It replaces direct calls to M.Command.
func (c *conn) cmdDone(name, outcome string) { c.finishCmd(name, outcome, "") }

// cmdDeny records a denied command together with the reason.
func (c *conn) cmdDeny(name, reason string) { c.finishCmd(name, "denied", reason) }

func (c *conn) finishCmd(name, outcome, reason string) {
	c.s.M.Command(name, outcome)
	var d time.Duration = -1
	if !c.cmdStart.IsZero() {
		d = time.Since(c.cmdStart)
	}
	c.tm.Command(name, outcome, d)
	if c.span != nil {
		c.span.End(outcome)
		c.span = nil
	}
	al := c.s.audit
	if al == nil {
		return
	}
	var typ string
	switch {
	case outcome == "denied":
		typ = audit.CmdDenied
	case outcome == "error":
		typ = audit.CmdError
	case ddlCmds[name]:
		typ = audit.CmdDDL
	case writeCmds[name]:
		typ = audit.CmdWrite
	case readCmds[name] && al.SampleRead():
		typ = audit.CmdRead
	default:
		return
	}
	e := c.event(typ)
	e.Corr, e.DB, e.Command, e.Outcome, e.Reason = c.corr, c.curDB, name, outcome, reason
	if d >= 0 {
		e.LatencyMs = float64(d) / float64(time.Millisecond)
	}
	al.Log(e)
}

// endMsg runs after every client message.
func (c *conn) endMsg() {
	c.nCursors.Store(int64(len(c.cursors)))
	c.nStreams.Store(int64(len(c.streams)))
	if c.span != nil { // command that never reported (e.g. unacknowledged)
		c.span.End("ok")
		c.span = nil
	}
	c.cmdStart = time.Time{}
}

func (c *conn) authOK() {
	c.s.audit.Log(c.event(audit.AuthSuccess))
}

func (c *conn) authFail(user, reason string) {
	c.s.authFailed(c.ip, user)
	c.auditAuthFail(user, reason)
}

// auditAuthFail records a refused authentication that is not a credential
// guess (the tenant is disabled or at its connection cap), so it does not
// count towards a lockout.
func (c *conn) auditAuthFail(user, reason string) {
	e := c.event(audit.AuthFailure)
	if user != "" {
		e.User = user
	}
	e.Reason = reason
	c.s.audit.Log(e)
}

// revoked reports whether the connection's tenant was disabled or its user
// removed or re-bound, and why.
func (c *conn) revoked() (string, bool) {
	id := c.tenantID()
	if id == "" {
		return "", false
	}
	if c.s.reg.Disabled(id) {
		return "tenant disabled", true
	}
	if u := c.userName(); u != "" && !c.s.auth.UserBound(u, id) {
		return "user removed", true
	}
	return "", false
}

// kill terminates the connection; the serve loop notices the closed socket.
func (c *conn) kill(reason string) {
	c.killed.CompareAndSwap(nil, &reason)
	c.nc.Close()
}

// enforce disconnects connections whose tenant/user is no longer valid.
func (s *Server) enforce() {
	s.mu.Lock()
	var victims []*conn
	var reasons []string
	for c := range s.conns {
		if why, bad := c.revoked(); bad {
			victims = append(victims, c)
			reasons = append(reasons, why)
		}
	}
	s.mu.Unlock()
	for i, c := range victims {
		c.kill(reasons[i])
	}
}

// ---- inspection -------------------------------------------------------------

// ConnInfo describes a live client connection.
type ConnInfo struct {
	ID          int64     `json:"id"`
	Session     string    `json:"session"`
	Tenant      string    `json:"tenant"`
	User        string    `json:"user,omitempty"`
	Remote      string    `json:"remote"`
	Since       time.Time `json:"since"`
	Commands    int64     `json:"commands"`
	BytesIn     int64     `json:"bytesIn"`
	BytesOut    int64     `json:"bytesOut"`
	OpenCursors int64     `json:"openCursors"`
	Streams     int64     `json:"changeStreamSubscribers"`
}

// Connections lists live connections, optionally for one tenant.
func (s *Server) Connections(tenant string) []ConnInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ConnInfo, 0, len(s.conns))
	for c := range s.conns {
		if tenant != "" && c.tenantID() != tenant {
			continue
		}
		out = append(out, ConnInfo{
			ID: c.id, Session: c.sess, Tenant: c.tenantID(), User: c.userName(), Remote: c.nc.RemoteAddr().String(),
			Since: c.since, Commands: c.nCmds.Load(), BytesIn: c.bIn.Load(), BytesOut: c.bOut.Load(),
			OpenCursors: c.nCursors.Load(), Streams: c.nStreams.Load(),
		})
	}
	return out
}

// KillConnection closes one connection by id.
func (s *Server) KillConnection(id int64) (ConnInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		if c.id == id {
			info := ConnInfo{ID: c.id, Session: c.sess, Tenant: c.tenantID(), User: c.userName(), Remote: c.nc.RemoteAddr().String()}
			c.kill("killed by admin")
			return info, true
		}
	}
	return ConnInfo{}, false
}

// KillTenant closes every connection of a tenant and returns how many.
func (s *Server) KillTenant(tenant string) int {
	s.mu.Lock()
	var cs []*conn
	for c := range s.conns {
		if c.tenantID() == tenant {
			cs = append(cs, c)
		}
	}
	s.mu.Unlock()
	for _, c := range cs {
		c.kill("killed by admin")
	}
	return len(cs)
}

// TenantStats returns per-tenant statistics.
func (s *Server) TenantStats(tenant string) metrics.TenantStats { return s.M.Stats(tenant) }

func (s *Server) tenantGauges() []metrics.TenantGauges {
	s.mu.Lock()
	defer s.mu.Unlock()
	by := map[string]*metrics.TenantGauges{}
	for c := range s.conns {
		id := c.tenantID()
		if id == "" {
			id = metrics.Unauthenticated
		}
		g := by[id]
		if g == nil {
			g = &metrics.TenantGauges{Tenant: id}
			by[id] = g
		}
		g.Conns++
		g.Cursors += c.nCursors.Load()
		g.Streams += c.nStreams.Load()
	}
	out := make([]metrics.TenantGauges, 0, len(by))
	for _, g := range by {
		out = append(out, *g)
	}
	return out
}

// saslUser extracts the user name from a SCRAM client-first message
// ("n,,n=<user>,r=<nonce>"). It is only used to label failed attempts.
func saslUser(payload []byte) string {
	s := string(payload)
	i := strings.Index(s, "n=")
	if i < 0 {
		return ""
	}
	s = s[i+2:]
	if j := strings.IndexByte(s, ','); j >= 0 {
		s = s[:j]
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
