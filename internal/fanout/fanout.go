// Package fanout multiplexes change streams. Instead of one upstream change
// stream per watching client (each scanning the whole oplog), it keeps a
// single stream per collection and routes every event to the subscribers of
// the tenant that owns it. Cost on the database is O(collections watched),
// not O(watchers).
package fanout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

const (
	maxQueue      = 20000            // events buffered per subscriber before it is cut off
	hubIdleGrace  = 30 * time.Second // how long an unwatched hub keeps its stream
	upstreamBatch = 1000
)

// ErrOverflow is returned to a subscriber that fell too far behind; it is
// reported to the client as a resumable error so the driver resumes it on a
// private, server-filtered stream from its last token.
var ErrOverflow = errors.New("change stream subscriber too slow")

// errClosed is returned to subscribers of a hub that was shut down.
var errClosed = errors.New("change stream fan-out closed")

// Timestamp is a BSON timestamp.
type Timestamp struct{ T, I uint32 }

func (a Timestamp) after(b Timestamp) bool { return a.T > b.T || (a.T == b.T && a.I > b.I) }

// Options describes how a subscriber wants events shaped.
type Options struct {
	FullDocument string   // default | updateLookup | whenAvailable | required
	Before       string   // off | whenAvailable | required
	OpTypes      []string // nil = all
}

// Manager owns the hubs.
type Manager struct {
	Dial       *upstream.Dialer
	Field      string
	AutoImages bool
	Log        *slog.Logger
	MaxMessage int

	// idleGrace is how long an unwatched hub keeps its stream (tests shorten it).
	idleGrace time.Duration

	// Lock order (outer -> inner): Manager.mu -> hub.mu -> Sub.mu.
	// No path takes them in any other order: Subscribe releases Manager.mu
	// before hub.add; Sub methods release Sub.mu before calling into the hub;
	// hub.run releases hub.mu before taking Manager.mu.
	mu     sync.Mutex
	hubs   map[string]*hub
	closed bool
	wg     sync.WaitGroup // hub.run goroutines
}

// NewManager creates a Manager.
func NewManager(d *upstream.Dialer, field string, autoImages bool, maxMessage int, log *slog.Logger) *Manager {
	return &Manager{Dial: d, Field: field, AutoImages: autoImages, MaxMessage: maxMessage, Log: log, hubs: map[string]*hub{}, idleGrace: hubIdleGrace}
}

// ActiveHubs reports the number of upstream streams currently open.
func (m *Manager) ActiveHubs() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.hubs)
}

// Close shuts every hub down: upstream streams are cancelled, their goroutines
// exit and subscribers fail. Without it a hub (and its upstream connection)
// outlives the server until its idle grace period ends - never, if it still
// has subscribers or is retrying a broken stream.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	hubs := m.hubs
	m.hubs = map[string]*hub{}
	m.mu.Unlock()
	for _, h := range hubs {
		h.mu.Lock()
		h.closed = true
		if h.idle != nil {
			h.idle.Stop()
			h.idle = nil
		}
		h.mu.Unlock()
		h.cancel()
		h.failAll(errClosed)
	}
	m.wg.Wait() // hubs kill their upstream cursors before returning
}

// TenantKey is the routing key for a tenant value.
func TenantKey(t bsoncore.Type, data []byte) string { return string([]byte{byte(t)}) + string(data) }

// Subscribe registers a subscriber on the (db, coll) hub, creating it if
// needed. The subscriber buffers its tenant's events immediately; call Start
// to anchor it in time.
func (m *Manager) Subscribe(db, coll, tenantKey string, o Options) *Sub {
	for {
		m.mu.Lock()
		h := m.hubs[db+"."+coll]
		if h == nil {
			h = newHub(m, db, coll)
			if m.closed {
				// Shutting down: hand out a subscriber whose Start fails
				// instead of starting an upstream stream nobody will stop.
				h.cancel()
			} else {
				m.hubs[db+"."+coll] = h
			}
		}
		m.mu.Unlock()
		if s := h.add(tenantKey, o); s != nil {
			return s
		}
		// hub was shutting down; loop to create a fresh one
	}
}

// ---- hub -------------------------------------------------------------------

type hub struct {
	m        *Manager
	db, coll string
	ctx      context.Context
	cancel   context.CancelFunc

	mu      sync.Mutex
	byKey   map[string]map[*Sub]struct{}
	n       int
	closed  bool
	idle    *time.Timer
	started bool
	ready   chan struct{} // closed after the first successful open
	openErr error
	token   atomic.Value // bsoncore.Document: latest position
}

func (h *hub) collName() string {
	if h.coll == "" {
		return "$cmd.aggregate"
	}
	return h.coll
}

// DBWatched reports whether a database-level hub exists for db.
func (m *Manager) DBWatched(db string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.hubs[db+"."]
	return ok
}

func newHub(m *Manager, db, coll string) *hub {
	ctx, cancel := context.WithCancel(context.Background())
	return &hub{m: m, db: db, coll: coll, ctx: ctx, cancel: cancel,
		byKey: map[string]map[*Sub]struct{}{}, ready: make(chan struct{})}
}

func (h *hub) add(key string, o Options) *Sub {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	if h.idle != nil {
		h.idle.Stop()
		h.idle = nil
	}
	s := &Sub{h: h, key: key, opts: o, notify: make(chan struct{}, 1)}
	set := h.byKey[key]
	if set == nil {
		set = map[*Sub]struct{}{}
		h.byKey[key] = set
	}
	set[s] = struct{}{}
	h.n++
	return s
}

func (h *hub) remove(s *Sub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.byKey[s.key]; set != nil {
		if _, ok := set[s]; !ok {
			return
		}
		delete(set, s)
		if len(set) == 0 {
			delete(h.byKey, s.key)
		}
		h.n--
	}
	if h.n == 0 && !h.closed && h.idle == nil {
		h.idle = time.AfterFunc(h.m.idleGrace, h.shutdownIfIdle)
	}
}

func (h *hub) shutdownIfIdle() {
	h.m.mu.Lock()
	h.mu.Lock()
	if h.n > 0 || h.closed {
		h.mu.Unlock()
		h.m.mu.Unlock()
		return
	}
	h.closed = true
	delete(h.m.hubs, h.db+"."+h.coll)
	h.mu.Unlock()
	h.m.mu.Unlock()
	h.cancel()
}

// start launches the upstream stream (once), beginning at `at`, and waits
// until it is open.
func (h *hub) start(at Timestamp) error {
	if h.ctx.Err() != nil {
		return errClosed
	}
	h.mu.Lock()
	if !h.started {
		h.started = true
		h.m.wg.Add(1)
		go func() { defer h.m.wg.Done(); h.run(at) }()
	}
	h.mu.Unlock()
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	select {
	case <-h.ready:
		return h.openErr
	case <-timeout.C:
		return errors.New("timed out opening change stream")
	}
}

func (h *hub) failAll(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, set := range h.byKey {
		for s := range set {
			s.fail(err)
		}
	}
}

func (h *hub) run(first Timestamp) {
	var (
		token    bsoncore.Document
		firstSet = false
		backoff  = 200 * time.Millisecond
		log      = h.m.Log.With("hub", h.db+"."+h.coll)
	)
	signalReady := func(err error) {
		if !firstSet {
			firstSet = true
			h.openErr = err
			close(h.ready)
		}
	}
	// However run ends, a subscriber still waiting for the first open must
	// not sit out the 20s timeout.
	defer signalReady(errClosed)
	for h.ctx.Err() == nil {
		err := h.stream(first, &token, signalReady)
		if h.ctx.Err() != nil {
			return
		}
		if !firstSet {
			// Never opened: fail fast so the first subscriber sees the error.
			signalReady(err)
			h.mu.Lock()
			h.closed = true
			h.mu.Unlock()
			h.m.mu.Lock()
			delete(h.m.hubs, h.db+"."+h.coll)
			h.m.mu.Unlock()
			h.failAll(err)
			h.cancel() // release the hub context; nothing else will
			return
		}
		var fatal *fatalError
		if errors.As(err, &fatal) {
			log.Warn("change stream history lost; resetting subscribers", "err", err)
			h.failAll(ErrOverflow)
			token = nil
		} else {
			log.Warn("change stream interrupted; resuming", "err", err)
		}
		select {
		case <-time.After(backoff):
		case <-h.ctx.Done():
			return
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
		first = Timestamp{}
	}
}

type fatalError struct{ msg string }

func (e *fatalError) Error() string { return e.msg }

// stream opens one upstream change stream and pumps it until it fails.
func (h *hub) stream(first Timestamp, token *bsoncore.Document, ready func(error)) error {
	m := h.m
	ctx, cancel := context.WithTimeout(h.ctx, m.Dial.DialTimeout())
	c, err := m.Dial.Dial(ctx)
	cancel()
	if err != nil {
		return err
	}
	// sctx ends with this stream (not only with the hub): otherwise every
	// resume after a failover would leave one more goroutine parked on h.ctx
	// until the hub itself shut down.
	sctx, scancel := context.WithCancel(h.ctx)
	defer scancel()
	defer c.Close()
	go func() { <-sctx.Done(); c.Close() }()
	// A server-side change stream cursor outlives its connection (mongod only
	// reaps it after the 10 minute cursor timeout), so every hub that ends -
	// idle shutdown, server shutdown, a stream broken mid-way - would leave
	// one behind. Kill it from a fresh connection on the way out.
	var cursor int64
	defer func() {
		if cursor != 0 {
			h.killCursor(cursor)
		}
	}()

	mode := "required"
	if h.coll == "" {
		mode = "whenAvailable" // database-level: some collections may lack images
	}
	if m.AutoImages {
		var err error
		if h.coll == "" {
			err = m.Dial.EnsureImagesDB(c, h.db)
		} else {
			err = m.Dial.EnsureImages(c, h.db, h.coll)
		}
		if err != nil {
			return fmt.Errorf("enabling pre/post images: %w", err)
		}
	}

	cs := bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "fullDocument", mode),
		bsoncore.AppendStringElement(nil, "fullDocumentBeforeChange", mode))
	switch {
	case len(*token) > 0:
		cs = appendElem(cs, bsoncore.AppendDocumentElement(nil, "startAfter", *token))
	case first.T != 0:
		cs = appendElem(cs, bsoncore.AppendTimestampElement(nil, "startAtOperationTime", first.T, first.I))
	}
	var target []byte
	if h.coll == "" {
		target = bsoncore.AppendInt32Element(nil, "aggregate", 1)
	} else {
		target = bsoncore.AppendStringElement(nil, "aggregate", h.coll)
	}
	cmd := bsoncore.BuildDocument(nil,
		target,
		bsoncore.AppendArrayElement(nil, "pipeline", bsoncore.BuildArray(nil,
			bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: bsoncore.BuildDocument(nil,
				bsoncore.AppendDocumentElement(nil, "$changeStream", cs))})),
		bsoncore.AppendDocumentElement(nil, "cursor", bsoncore.BuildDocument(nil,
			bsoncore.AppendInt32Element(nil, "batchSize", upstreamBatch))),
	)
	resp, err := m.Dial.RunCommand(c, h.db, cmd)
	for {
		if err != nil {
			return err
		}
		if ok, _ := resp.Lookup("ok").AsInt64OK(); ok != 1 {
			msg, _ := resp.Lookup("errmsg").StringValueOK()
			code, _ := resp.Lookup("code").AsInt64OK()
			if code == 286 || code == 280 {
				return &fatalError{msg}
			}
			return fmt.Errorf("change stream error %d: %s", code, msg)
		}
		cur, _ := resp.Lookup("cursor").DocumentOK()
		id, _ := cur.Lookup("id").AsInt64OK()
		cursor = id
		batch, _ := cur.Lookup("firstBatch").ArrayOK()
		if batch == nil {
			batch, _ = cur.Lookup("nextBatch").ArrayOK()
		}
		pbrt, _ := cur.Lookup("postBatchResumeToken").DocumentOK()
		h.dispatch(batch, pbrt, token)
		ready(nil)
		if id == 0 {
			return errors.New("upstream closed the change stream")
		}
		next := bsoncore.BuildDocument(nil,
			bsoncore.AppendInt64Element(nil, "getMore", id),
			bsoncore.AppendStringElement(nil, "collection", h.collName()),
			bsoncore.AppendInt32Element(nil, "batchSize", upstreamBatch),
			bsoncore.AppendInt32Element(nil, "maxTimeMS", 1000),
		)
		resp, err = m.Dial.RunCommand(c, h.db, next)
	}
}

// killCursor best-effort kills the hub's upstream cursor on a fresh
// connection (the stream's own may be closed or mid-getMore).
func (h *hub) killCursor(id int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := h.m.Dial.Dial(ctx)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	h.m.Dial.RunCommand(c, h.db, bsoncore.BuildDocument(nil,
		bsoncore.AppendStringElement(nil, "killCursors", h.collName()),
		bsoncore.AppendArrayElement(nil, "cursors", bsoncore.BuildArray(nil,
			bsoncore.Value{Type: bsoncore.TypeInt64, Data: bsoncore.AppendInt64(nil, id)}))))
}

func appendElem(d bsoncore.Document, elem []byte) bsoncore.Document {
	out := make([]byte, 0, len(d)+len(elem))
	out = append(out, d[:len(d)-1]...)
	out = append(out, elem...)
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}

// dispatch routes a batch of raw events to subscribers, then publishes the
// batch's resume position to everyone.
func (h *hub) dispatch(batch bsoncore.Array, pbrt bsoncore.Document, token *bsoncore.Document) {
	field := h.m.Field
	vals, _ := batch.Values()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, v := range vals {
		ev, ok := v.DocumentOK()
		if !ok {
			continue
		}
		if id, ok := ev.Lookup("_id").DocumentOK(); ok {
			*token = id
		}
		if h.coll == "" {
			if c, _ := wire.LookupPath(ev, "ns", "coll").StringValueOK(); strings.HasPrefix(c, "__mtp_") {
				continue // proxy bookkeeping, never shown to tenants
			}
		}
		if op, _ := ev.Lookup("operationType").StringValueOK(); lifecycle(op) {
			// Collection/database lifecycle events carry no document data, so
			// every watcher of the (shared) collection gets them, as it would
			// from a real server.
			for _, set := range h.byKey {
				for s := range set {
					s.push(ev)
				}
			}
			continue
		}
		t := ev.Lookup("fullDocument", field)
		if t.Type == 0 {
			t = ev.Lookup("fullDocumentBeforeChange", field)
		}
		if t.Type == 0 {
			continue // drop/rename/invalidate etc: no tenant, nobody gets it
		}
		for s := range h.byKey[TenantKey(t.Type, t.Data)] {
			s.push(ev)
		}
	}
	if len(pbrt) > 0 {
		*token = pbrt
	}
	pos := *token
	h.token.Store(pos)
	for _, set := range h.byKey {
		for s := range set {
			s.setPos(pos)
		}
	}
}

func lifecycle(op string) bool {
	switch op {
	case "drop", "rename", "dropDatabase", "invalidate":
		return true
	}
	return false
}

// ---- subscriber -------------------------------------------------------------

// Sub is one client's view of the stream.
type Sub struct {
	h    *hub
	key  string
	opts Options

	mu     sync.Mutex
	queue  []bsoncore.Document
	pos    bsoncore.Document // hub position after everything queued so far
	after  Timestamp
	err    error
	closed bool
	ended  bool // an invalidate event was queued: the cursor closes after it
	notify chan struct{}
}

// Start anchors the subscriber at `after` (only later events are delivered),
// makes sure the upstream stream is open, and returns the initial resume
// token.
func (s *Sub) Start(after Timestamp) (bsoncore.Document, error) {
	s.mu.Lock()
	s.after = after
	s.mu.Unlock()
	if err := s.h.start(after); err != nil {
		s.Close()
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pos) == 0 {
		if t, ok := s.h.token.Load().(bsoncore.Document); ok {
			s.pos = t
		}
	}
	return s.pos, nil
}

func (s *Sub) push(ev bsoncore.Document) {
	s.mu.Lock()
	if s.err == nil && !s.closed {
		if len(s.queue) >= maxQueue {
			s.err = ErrOverflow
			s.queue = nil
		} else {
			s.queue = append(s.queue, ev)
			if op, _ := ev.Lookup("operationType").StringValueOK(); op == "invalidate" {
				s.ended = true
			}
		}
	}
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *Sub) setPos(p bsoncore.Document) {
	s.mu.Lock()
	s.pos = p
	s.mu.Unlock()
}

func (s *Sub) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Close detaches the subscriber.
func (s *Sub) Close() {
	s.mu.Lock()
	s.closed = true
	s.queue = nil
	s.mu.Unlock()
	s.h.remove(s)
}

// Next returns up to max events, waiting up to wait for at least one. The
// returned token is a valid resume position after the returned events. done
// is true once an invalidate event has been delivered: the cursor must close.
func (s *Sub) Next(max int, wait time.Duration) (events []bsoncore.Document, token bsoncore.Document, done bool, err error) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return nil, nil, false, err
		}
		// pos is read before the queue is taken: events of any batch whose
		// position we read were appended before that position was published.
		pos := s.pos
		var out []bsoncore.Document
		taken := 0
		for taken < len(s.queue) && len(out) < max {
			ev := s.queue[taken]
			taken++
			if s.wanted(ev) {
				out = append(out, s.shape(ev))
			}
		}
		s.queue = s.queue[taken:]
		drained := len(s.queue) == 0
		ended := s.ended && drained
		s.mu.Unlock()
		if len(out) > 0 {
			last, _ := out[len(out)-1].Lookup("_id").DocumentOK()
			if len(last) == 0 {
				last = pos
			}
			return out, last, ended, nil
		}
		if ended {
			return nil, pos, true, nil
		}
		if drained {
			select {
			case <-s.notify:
			case <-timer.C:
				return nil, pos, false, nil
			}
		}
	}
}

func (s *Sub) wanted(ev bsoncore.Document) bool {
	if t, i, ok := ev.Lookup("clusterTime").TimestampOK(); ok {
		if !(Timestamp{t, i}).after(s.after) {
			return false
		}
	}
	if s.opts.OpTypes == nil {
		return true
	}
	op, _ := ev.Lookup("operationType").StringValueOK()
	if lifecycle(op) {
		return true
	}
	for _, o := range s.opts.OpTypes {
		if o == op {
			return true
		}
	}
	return false
}

// shape removes the images the client did not ask for.
func (s *Sub) shape(ev bsoncore.Document) bsoncore.Document {
	dropFull, dropBefore := false, s.opts.Before == "" || s.opts.Before == "off"
	if s.opts.FullDocument == "" || s.opts.FullDocument == "default" {
		op, _ := ev.Lookup("operationType").StringValueOK()
		dropFull = op == "update"
	}
	if !dropFull && !dropBefore {
		return ev
	}
	elems, err := ev.Elements()
	if err != nil {
		return ev
	}
	out := make([]byte, 4, len(ev))
	for _, e := range elems {
		switch e.Key() {
		case "fullDocument":
			if dropFull {
				continue
			}
		case "fullDocumentBeforeChange":
			if dropBefore {
				continue
			}
		}
		out = append(out, e...)
	}
	out = append(out, 0)
	n := len(out)
	out[0], out[1], out[2], out[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return out
}
