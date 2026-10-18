// Package proxy implements the MongoDB wire-protocol server that sits between
// clients and the real database and applies tenant isolation to every command.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/fanout"
	"github.com/netquor/mongodb-tenant-proxy/internal/limits"
	"github.com/netquor/mongodb-tenant-proxy/internal/metrics"
	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Lock ordering
//
// Every mutex in internal/ and where it nests (outer -> inner). Anything not
// listed is a leaf: nothing else is acquired while it is held. The stress
// suite (-race, test/stress_*_test.go, internal/*/stress_test.go) exercises
// each of these edges concurrently.
//
//	Server.reloadMu  -> tenants.Registry.mu (SetStatic, released before OnChange)
//	                 -> then, with no lock held, Server.enforce -> Server.mu
//	                 (reload hooks run under reloadMu and must not call Reload)
//	Server.mu        leaf. enforce/Connections/tenantGauges only read atomics
//	                 and the lock-free tenants snapshot while holding it.
//	Server.opsMu     leaf ($currentOp attribution map).
//	tenants.Registry.mu -> Store implementation (FileStore.mu / MongoStore I/O);
//	                 readers use an atomic snapshot and never take it. The
//	                 onChange callback runs after Registry.mu is released.
//	metrics.Registry.tmu -> metrics.labeler.mu; Registry.mu, Tenant.mu leaves.
//	                 The gauge source (-> Server.mu) is called with no metrics
//	                 lock held.
//	audit.Logger.mu  -> sink mutex (FileSink/HTTPSink/syslog). Server code
//	                 never logs while holding Server.mu.
//	fanout.Manager.mu -> fanout.hub.mu -> fanout.Sub.mu (see fanout.go).
//	upstream topology.mu -> memberPool.mu (removeMemberLocked clears the pool);
//	                 the pool never calls into the topology while holding mu.
//	limits.Manager (sync.Map), limits bucket.mu, limits.Tenant.mu,
//	sessionTable.mu, upstream.Dialer.* : leaves.
//
// Per-connection state (conn.*, cursors, streams, txn pins) is owned by the
// connection's goroutine; other goroutines reach it only through the atomics
// in connOps (killed, tenantP, userP, nCursors, ...) and conn.nc.Close.

// Server accepts client connections and proxies them to the upstream.
type Server struct {
	cfg  *config.Config
	auth *auth.Authenticator
	dial *upstream.Dialer
	log  *slog.Logger
	M    *metrics.Registry

	opsState
	limits helloLimits
	lim    *limits.Manager
	sess   *sessionTable
	// clientComp is the set of compressors advertised to clients, with
	// clientCompList holding the names in preference order.
	clientComp     map[wire.Compressor]bool
	clientCompList []wire.Compressor

	nextID atomic.Int64
	mu     sync.Mutex
	conns  map[*conn]struct{}
	tenant map[string]int
	wg     sync.WaitGroup
	fan    *fanout.Manager
	views  viewCache
	// dbStreams records databases that have been watched at database level;
	// writes to their collections get pre/post images enabled first.
	dbStreams sync.Map
	opsMu     sync.Mutex
	upAddrs   map[string]map[string]struct{} // tenant -> upstream-side addresses of its connections
	txnKnown  bool
	txn       bool
	steps     sync.Map // CacheKey -> struct{}: housekeeping commands already applied
}

type helloLimits struct {
	maxBSON, maxMessage, maxBatch, minWire, maxWire, sessionTimeout int32
}

// New builds a Server and probes the upstream to learn its wire versions.
func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	if err := cfg.CheckIDPolicy(); err != nil {
		return nil, err
	}
	a, err := auth.New(cfg.Auth)
	if err != nil {
		return nil, err
	}
	d, err := upstream.NewDialer(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		auth:   a,
		dial:   d,
		log:    log,
		M:      metrics.NewWith(cfg.Metrics.TenantLabel),
		conns:  map[*conn]struct{}{},
		tenant: map[string]int{},
		lim:    limits.NewManager(cfg, nil),
	}
	s.clientComp = map[wire.Compressor]bool{}
	for _, n := range cfg.Compressors {
		if id, ok := wire.CompressorByName(n); ok && !s.clientComp[id] {
			s.clientComp[id] = true
			s.clientCompList = append(s.clientCompList, id)
		}
	}
	// New owns d, the registry store and the audit sink from here on: every
	// failing return below must release them (each holds goroutines, sockets
	// or file handles), or a failed start - e.g. an unreachable upstream, as
	// seen in a restart loop - leaks them.
	if err := s.initOps(context.Background(), cfg); err != nil {
		d.Close()
		s.audit.Close()
		if s.reg != nil {
			s.reg.Close()
		}
		return nil, err
	}
	if cs := cfg.ChangeStreams; !cs.Disabled && !cs.DisableFanout {
		s.fan = fanout.NewManager(d, cfg.Tenant.Field, !cs.DisableAutoImages, cfg.MaxMessageBytes, log)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.SetLogger(log)
	h, err := d.Hello(ctx)
	if err != nil {
		if s.fan != nil {
			s.fan.Close()
		}
		d.Close()
		s.audit.Close()
		s.reg.Close()
		return nil, fmt.Errorf("probing upstream %s: %w", cfg.Upstream.Addr, err)
	}
	get := func(k string, def int32) int32 {
		if v, ok := h.Lookup(k).AsInt64OK(); ok && v > 0 {
			return int32(v)
		}
		return def
	}
	s.limits = helloLimits{
		maxBSON:        get("maxBsonObjectSize", 16*1024*1024),
		maxMessage:     get("maxMessageSizeBytes", 48000000),
		maxBatch:       get("maxWriteBatchSize", 100000),
		minWire:        get("minWireVersion", 0),
		maxWire:        get("maxWireVersion", 17),
		sessionTimeout: get("logicalSessionTimeoutMinutes", 30),
	}
	s.sess = newSessionTable(s.limits.sessionTimeout, nil)
	s.M.Collectors = append(s.M.Collectors, s.writeUpstreamMetrics)
	log.Info("upstream reachable", "hosts", len(cfg.Upstream.HostList()), "pooled", d.Pooled(), "maxWireVersion", s.limits.maxWire)
	return s, nil
}

// Serve accepts connections until ctx is cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go s.reg.Run(ctx, s.cfg.Store.RefreshDuration(), func(err error) { s.log.Warn("tenant store refresh failed", "err", err) })
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.shutdown()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		c := newConn(s, nc)
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			c.serve(ctx)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

func (s *Server) shutdown() {
	s.mu.Lock()
	for c := range s.conns {
		c.nc.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if s.fan != nil {
		s.fan.Close() // before the dialer: stops hub streams and their reconnect loops
	}
	s.dial.Close()
	s.audit.Close()
	s.reg.Close()
}

// UpstreamStats reports the state of the upstream topology and pools.
func (s *Server) UpstreamStats() upstream.Stats { return s.dial.Stats() }

// acquireTenant enforces the per-tenant connection cap.
func (s *Server) acquireTenant(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.rt().maxConns
	if o := s.reg.MaxConns(id); o > 0 {
		m = o
	}
	if m > 0 && s.tenant[id] >= m {
		return false
	}
	s.tenant[id]++
	return true
}

func (s *Server) releaseTenant(id string) {
	s.mu.Lock()
	if s.tenant[id]--; s.tenant[id] <= 0 {
		delete(s.tenant, id)
	}
	s.mu.Unlock()
}

func (s *Server) dbWatched(db string) bool { _, ok := s.dbStreams.Load(db); return ok }

func (s *Server) writeUpstreamMetrics(w io.Writer) {
	st := s.dial.Stats()
	fmt.Fprintf(w, "# TYPE mtp_upstream_connections gauge\nmtp_upstream_connections %d\n", st.OpenConns)
	fmt.Fprintf(w, "# TYPE mtp_upstream_topology_events_total counter\nmtp_upstream_topology_events_total %d\n", st.TopologyEvents)
	fmt.Fprintf(w, "# TYPE mtp_upstream_pool_connections gauge\n")
	for _, m := range st.Members {
		fmt.Fprintf(w, "mtp_upstream_pool_connections{member=%q,state=\"in_use\"} %d\n", m.Addr, m.InUse)
		fmt.Fprintf(w, "mtp_upstream_pool_connections{member=%q,state=\"idle\"} %d\n", m.Addr, m.Idle)
		fmt.Fprintf(w, "mtp_upstream_member_info{member=%q,type=%q} 1\n", m.Addr, m.Type)
	}
}
