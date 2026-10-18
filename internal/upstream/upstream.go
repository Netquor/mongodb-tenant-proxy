// Package upstream dials and authenticates connections to the real MongoDB
// server.
package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// Conn is an authenticated connection to an upstream member.
type Conn struct {
	net.Conn
	R *bufio.Reader
	// Addr is the member this connection talks to.
	Addr string

	d        *Dialer
	pool     *memberPool // nil for unpooled connections
	gen      uint64
	born     time.Time
	lastUsed time.Time
	broken   bool
	once     sync.Once
}

// MarkBroken makes the pool discard the connection instead of reusing it
// (for example after a protocol error mid-reply).
func (c *Conn) MarkBroken() { c.broken = true }

// Close closes the socket exactly once.
func (c *Conn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		if c.d != nil {
			c.d.open.Add(-1)
		}
	})
	return err
}

// Dialer opens, monitors and pools upstream connections.
type Dialer struct {
	cfg    config.Upstream
	dial   net.Dialer
	tls    *tls.Config
	max    int
	ids    atomic.Int32
	images sync.Map // "db.coll" -> struct{}

	hosts  map[string]*hostTLS // per-member TLS overrides
	hostRW map[string]string
	topo   *topology
	logger atomic.Pointer[slog.Logger]

	started      atomic.Bool
	open         atomic.Int64 // live sockets of any kind
	pooledOpened atomic.Int64
	events       atomic.Int64 // topology changes observed
	stopReap     chan struct{}
	closeOnce    sync.Once
}

type hostTLS struct {
	cfg *tls.Config
}

// SetLogger sets the logger used for topology events.
func (d *Dialer) SetLogger(l *slog.Logger) { d.logger.Store(l) }

func (d *Dialer) log(msg string, args ...any) {
	if l := d.logger.Load(); l != nil {
		l.Info(msg, args...)
	}
}

func (d *Dialer) mapHost(a string) string {
	if r, ok := d.hostRW[a]; ok {
		return r
	}
	return a
}

// NewDialer prepares a Dialer from the upstream configuration and starts
// monitoring the members.
func NewDialer(cfg *config.Config) (*Dialer, error) {
	d := &Dialer{cfg: cfg.Upstream, max: cfg.MaxMessageBytes, hosts: map[string]*hostTLS{},
		hostRW: cfg.Upstream.HostMap, stopReap: make(chan struct{})}
	if d.cfg.AuthSource == "" {
		d.cfg.AuthSource = "admin"
	}
	d.dial.Timeout = cfg.DialDuration()
	d.dial.KeepAlive = 30e9
	build := func(on bool, ca string, skip bool, name string) (*tls.Config, error) {
		if !on {
			return nil, nil
		}
		tc := &tls.Config{InsecureSkipVerify: skip, MinVersion: tls.VersionTLS12, ServerName: name}
		if ca != "" {
			pem, err := os.ReadFile(ca)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("upstream.caFile contains no certificates")
			}
			tc.RootCAs = pool
		}
		return tc, nil
	}
	var err error
	if d.tls, err = build(cfg.Upstream.TLS, cfg.Upstream.CAFile, cfg.Upstream.InsecureSkipVerify, ""); err != nil {
		return nil, err
	}
	for _, h := range cfg.Upstream.HostList() {
		if h.TLS == nil && h.CAFile == "" && h.InsecureSkipVerify == nil && h.ServerName == "" {
			continue
		}
		on, ca, skip := cfg.Upstream.TLS, cfg.Upstream.CAFile, cfg.Upstream.InsecureSkipVerify
		if h.TLS != nil {
			on = *h.TLS
		}
		if h.CAFile != "" {
			ca = h.CAFile
		}
		if h.InsecureSkipVerify != nil {
			skip = *h.InsecureSkipVerify
		}
		tc, err := build(on, ca, skip, h.ServerName)
		if err != nil {
			return nil, err
		}
		d.hosts[d.mapHost(h.Addr)] = &hostTLS{cfg: tc}
	}
	d.topo = newTopology(d)
	d.started.Store(true)
	d.topo.start()
	go d.reaper()
	return d, nil
}

func (d *Dialer) reaper() {
	idle, life := d.cfg.PoolIdle(), d.cfg.PoolLifetime()
	every := idle / 4
	if every < 100*time.Millisecond {
		every = 100 * time.Millisecond
	}
	if every > 10*time.Second {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-d.stopReap:
			return
		case <-t.C:
			for _, m := range d.topo.snapshot() {
				m.pool.reap(idle, life)
			}
		}
	}
}

// Close stops monitoring and closes pooled connections. Connections checked
// out by clients are closed by their owners.
func (d *Dialer) Close() {
	d.closeOnce.Do(func() {
		close(d.stopReap)
		d.topo.close()
		for _, m := range d.topo.snapshot() {
			m.pool.close()
		}
	})
}

// dialAddr opens a connection to addr, authenticating when asked to.
func (d *Dialer) dialAddr(ctx context.Context, addr string, auth bool) (*Conn, error) {
	nc, err := d.dial.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := d.tls
	if h, ok := d.hosts[addr]; ok {
		tc = h.cfg
	}
	if tc != nil {
		tc = tc.Clone()
		if tc.ServerName == "" {
			host, _, _ := net.SplitHostPort(addr)
			tc.ServerName = host
		}
		tconn := tls.Client(nc, tc)
		if err := tconn.HandshakeContext(ctx); err != nil {
			nc.Close()
			return nil, err
		}
		nc = tconn
	}
	now := time.Now()
	c := &Conn{Conn: nc, R: bufio.NewReaderSize(nc, 64*1024), Addr: addr, d: d, born: now, lastUsed: now}
	d.open.Add(1)
	if auth && d.cfg.Username != "" {
		if err := d.authenticate(c); err != nil {
			c.Close()
			return nil, fmt.Errorf("upstream authentication: %w", err)
		}
	}
	return c, nil
}

// Select picks the member a command with this selector should run on,
// waiting for the topology to settle (for example during an election).
func (d *Dialer) Select(ctx context.Context, sel Selector) (string, error) {
	m, err := d.topo.selectMember(ctx, sel)
	if err != nil {
		return "", err
	}
	return m.addr, nil
}

// Dial opens an unpooled authenticated connection to the primary (or the
// only member). The caller closes it.
func (d *Dialer) Dial(ctx context.Context) (*Conn, error) {
	addr, err := d.Select(ctx, Selector{Mode: Primary})
	if err != nil {
		return nil, err
	}
	return d.DialMember(ctx, addr)
}

// DialMember opens an unpooled authenticated connection to addr.
func (d *Dialer) DialMember(ctx context.Context, addr string) (*Conn, error) {
	c, err := d.dialAddr(ctx, addr, true)
	if err != nil {
		d.NetworkError(addr, err)
	}
	return c, err
}

// Checkout borrows a pooled connection to addr. Return it with Release, or
// with Discard if it may be in an unknown protocol state.
func (d *Dialer) Checkout(ctx context.Context, addr string) (*Conn, error) {
	d.topo.mu.Lock()
	m := d.topo.members[addr]
	d.topo.mu.Unlock()
	if m == nil {
		return nil, errNoMember
	}
	c, err := m.pool.get(ctx)
	if err != nil {
		if !errors.Is(err, ErrPoolTimeout) && !errors.Is(err, context.Canceled) {
			d.NetworkError(addr, err)
		}
		return nil, err
	}
	m.inflight.Add(1)
	return c, nil
}

// Release returns a connection obtained from Checkout.
func (d *Dialer) Release(c *Conn) {
	if c == nil || c.pool == nil {
		return
	}
	c.pool.m.inflight.Add(-1)
	c.pool.put(c)
}

// Discard closes a connection obtained from Checkout (or DialMember).
func (d *Dialer) Discard(c *Conn) {
	if c == nil {
		return
	}
	if c.pool == nil {
		c.Close()
		return
	}
	c.pool.m.inflight.Add(-1)
	c.pool.discard(c)
}

// NetworkError tells the topology that talking to addr failed at the
// transport level: the member becomes Unknown, its pool is flushed and the
// monitors re-check immediately.
func (d *Dialer) NetworkError(addr string, err error) {
	d.topo.markUnknown(addr, true, err)
}

// StateChange tells the topology that addr answered with a "not primary" /
// "shutting down" style error code.
func (d *Dialer) StateChange(addr string, code int32) {
	d.topo.markUnknown(addr, IsShutdown(code), fmt.Errorf("server error %d", code))
}

// Direct reports whether the proxy talks to one fixed member (no routing).
func (d *Dialer) Direct() bool { return d.topo.direct }

// Pooled reports whether connections are shared between clients.
func (d *Dialer) Pooled() bool { return d.cfg.Pooled() }

// MemberStats describes one member for diagnostics and tests.
type MemberStats struct {
	Addr        string
	Type        string
	InUse, Idle int
	RTT         time.Duration
	Err         string
}

// Stats is a snapshot of the upstream side.
type Stats struct {
	Members []MemberStats
	// OpenConns counts every live upstream socket (monitors, pools, dedicated).
	OpenConns int64
	// PoolConnsOpened counts pooled connections ever dialed.
	PoolConnsOpened int64
	// TopologyEvents counts observed member state changes.
	TopologyEvents int64
}

// Stats returns a snapshot.
func (d *Dialer) Stats() Stats {
	st := Stats{OpenConns: d.open.Load(), PoolConnsOpened: d.pooledOpened.Load(), TopologyEvents: d.events.Load()}
	for _, m := range d.topo.snapshot() {
		d.topo.mu.Lock()
		desc := m.desc
		d.topo.mu.Unlock()
		in, idle := m.pool.counts()
		ms := MemberStats{Addr: m.addr, Type: desc.Type.String(), InUse: in, Idle: idle, RTT: desc.RTT}
		if desc.Err != nil {
			ms.Err = desc.Err.Error()
		}
		st.Members = append(st.Members, ms)
	}
	return st
}

// RunCommand sends a command and returns the reply document.
func (d *Dialer) RunCommand(c *Conn, db string, cmd bsoncore.Document) (bsoncore.Document, error) {
	body := bsoncore.Document(cmd)
	var err error
	body = appendDB(body, db)
	m := wire.Msg{Body: body}
	id := d.ids.Add(1)
	if err = wire.WriteFrame(c.Conn, id, 0, wire.OpMsg, m.Encode()); err != nil {
		return nil, err
	}
	_, b, err := wire.ReadFrame(c.R, d.max)
	if err != nil {
		return nil, err
	}
	rm, err := wire.ParseMsg(b)
	if err != nil {
		return nil, err
	}
	return rm.Body, nil
}

func appendDB(cmd bsoncore.Document, db string) bsoncore.Document {
	out := make([]byte, 0, len(cmd)+len(db)+8)
	out = append(out, cmd[:len(cmd)-1]...)
	out = bsoncore.AppendStringElement(out, "$db", db)
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// Hello waits for a member to answer and returns its hello reply, used to
// learn wire versions and limits. The primary is preferred.
func (d *Dialer) Hello(ctx context.Context) (bsoncore.Document, error) {
	d.topo.settled(ctx, 3*time.Second)
	m, err := d.topo.selectMember(ctx, Selector{Mode: PrimaryPreferred})
	if err != nil {
		return nil, err
	}
	d.topo.mu.Lock()
	defer d.topo.mu.Unlock()
	return m.desc.Hello, nil
}

func (d *Dialer) authenticate(c *Conn) error {
	client, err := scram.SHA256.NewClient(d.cfg.Username, d.cfg.Password, "")
	if err != nil {
		return err
	}
	conv := client.NewConversation()
	payload, err := conv.Step("")
	if err != nil {
		return err
	}
	opts := bsoncore.BuildDocument(nil, bsoncore.AppendBooleanElement(nil, "skipEmptyExchange", true))
	cmd := bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "saslStart", 1),
		bsoncore.AppendStringElement(nil, "mechanism", "SCRAM-SHA-256"),
		bsoncore.AppendBinaryElement(nil, "payload", 0, []byte(payload)),
		bsoncore.AppendDocumentElement(nil, "options", opts),
	)
	resp, err := d.RunCommand(c, d.cfg.AuthSource, cmd)
	for {
		if err != nil {
			return err
		}
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			msg, _ := resp.Lookup("errmsg").StringValueOK()
			return errors.New(msg)
		}
		_, data, _ := resp.Lookup("payload").BinaryOK()
		done, _ := resp.Lookup("done").BooleanOK()
		if !conv.Done() {
			payload, err = conv.Step(string(data))
			if err != nil {
				return err
			}
		} else {
			payload = ""
		}
		if done && conv.Done() {
			if !conv.Valid() {
				return errors.New("server signature mismatch")
			}
			return nil
		}
		cid := resp.Lookup("conversationId")
		cmd = bsoncore.BuildDocument(nil,
			bsoncore.AppendInt32Element(nil, "saslContinue", 1),
			valueElem("conversationId", cid),
			bsoncore.AppendBinaryElement(nil, "payload", 0, []byte(payload)),
		)
		resp, err = d.RunCommand(c, d.cfg.AuthSource, cmd)
	}
}

func valueElem(key string, v bsoncore.Value) []byte { return bsoncore.AppendValueElement(nil, key, v) }

// DialTimeout is the configured connect timeout.
func (d *Dialer) DialTimeout() time.Duration { return d.dial.Timeout }

// EnsureImages enables changeStreamPreAndPostImages on a collection (creating
// it if it does not exist). It is idempotent.
func (d *Dialer) EnsureImages(c *Conn, db, coll string) error {
	if _, ok := d.images.Load(db + "." + coll); ok {
		return nil
	}
	on := bsoncore.BuildDocument(nil, bsoncore.AppendBooleanElement(nil, "enabled", true))
	run := func(cmd bsoncore.Document) (bsoncore.Document, error) { return d.RunCommand(c, db, cmd) }
	resp, err := run(bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "collMod", coll),
		bsoncore.AppendDocumentElement(nil, "changeStreamPreAndPostImages", on)))
	if err != nil {
		return err
	}
	if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
		if code, _ := resp.Lookup("code").AsInt64OK(); code != 26 { // NamespaceNotFound
			msg, _ := resp.Lookup("errmsg").StringValueOK()
			return errors.New(msg)
		}
		resp, err = run(bsoncore.BuildDocument(nil,
			bsoncore.AppendStringElement(nil, "create", coll),
			bsoncore.AppendDocumentElement(nil, "changeStreamPreAndPostImages", on)))
		if err != nil {
			return err
		}
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			if code, _ := resp.Lookup("code").AsInt64OK(); code != 48 { // already exists (race)
				msg, _ := resp.Lookup("errmsg").StringValueOK()
				return errors.New(msg)
			}
		}
	}
	d.images.Store(db+"."+coll, struct{}{})
	return nil
}

// EnsureImagesDB enables pre/post images on every existing collection of db.
func (d *Dialer) EnsureImagesDB(c *Conn, db string) error {
	resp, err := d.RunCommand(c, db, bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "listCollections", 1),
		bsoncore.AppendBooleanElement(nil, "nameOnly", true),
		bsoncore.AppendDocumentElement(nil, "filter", bsoncore.BuildDocument(nil, bsoncore.AppendStringElement(nil, "type", "collection"))),
		bsoncore.AppendDocumentElement(nil, "cursor", bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "batchSize", 100000)))))
	if err != nil {
		return err
	}
	batch, _ := resp.Lookup("cursor", "firstBatch").ArrayOK()
	vals, _ := batch.Values()
	for _, v := range vals {
		doc, _ := v.DocumentOK()
		name, _ := doc.Lookup("name").StringValueOK()
		if name == "" || strings.HasPrefix(name, "system.") || strings.HasPrefix(name, "__mtp_") {
			continue
		}
		if err := d.EnsureImages(c, db, name); err != nil {
			return err
		}
	}
	return nil
}
