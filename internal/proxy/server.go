// Package proxy implements the MongoDB wire-protocol server that sits between
// clients and the real database and applies tenant isolation to every command.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/fanout"
	"github.com/netquor/mongodb-tenant-proxy/internal/metrics"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
)

// Server accepts client connections and proxies them to the upstream.
type Server struct {
	cfg  *config.Config
	auth *auth.Authenticator
	rw   *rewrite.Rewriter
	dial *upstream.Dialer
	log  *slog.Logger
	M    *metrics.Registry

	limits helloLimits

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
		M:      metrics.New(),
		conns:  map[*conn]struct{}{},
		tenant: map[string]int{},
	}
	s.rw = rewrite.New(rewrite.Config{
		Field:         cfg.Tenant.Field,
		Databases:     cfg.Databases,
		DenyCommands:  cfg.DenyCommands,
		AllowJS:       !cfg.DisableJS,
		ChangeStreams: !cfg.ChangeStreams.Disabled,
		AtomicOut:     s.txnSupported,
	})
	if cs := cfg.ChangeStreams; !cs.Disabled && !cs.DisableFanout {
		s.fan = fanout.NewManager(d, cfg.Tenant.Field, !cs.DisableAutoImages, cfg.MaxMessageBytes, log)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, err := d.Hello(ctx)
	if err != nil {
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
	log.Info("upstream reachable", "addr", cfg.Upstream.Addr, "maxWireVersion", s.limits.maxWire)
	return s, nil
}

// Serve accepts connections until ctx is cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
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
}

// acquireTenant enforces the per-tenant connection cap.
func (s *Server) acquireTenant(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.cfg.MaxConnsPerTenant; m > 0 && s.tenant[id] >= m {
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
