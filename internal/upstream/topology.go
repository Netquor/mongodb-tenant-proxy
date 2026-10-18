package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// ServerType classifies a replica-set member (SDAM server types).
type ServerType int

// Server types.
const (
	Unknown ServerType = iota
	Standalone
	Mongos
	RSPrimary
	RSSecondary
	RSArbiter
	RSOther // hidden / starting up / removed
	RSGhost
)

func (t ServerType) String() string {
	return [...]string{"Unknown", "Standalone", "Mongos", "RSPrimary", "RSSecondary", "RSArbiter", "RSOther", "RSGhost"}[t]
}

// ServerDesc is what the monitor last learned about a member.
type ServerDesc struct {
	Type        ServerType
	SetName     string
	Tags        map[string]string
	RTT         time.Duration
	LastWrite   time.Time // lastWriteDate reported by the member
	LastUpdate  time.Time // when this description was taken
	SetVersion  int64
	ElectionID  [12]byte
	HasElection bool
	Hosts       []string // every member the set advertises
	Primary     string   // primary according to this member
	Hello       bsoncore.Document
	Err         error
}

func (d ServerDesc) known() bool { return d.Type != Unknown }

// member is one upstream server: its monitor, description and pool.
type member struct {
	t    *topology
	addr string
	pool *memberPool

	desc     ServerDesc // guarded by t.mu
	checked  bool       // the monitor has completed its first probe (guarded by t.mu)
	check    chan struct{}
	stop     chan struct{}
	inflight atomic.Int32
}

type topology struct {
	d       *Dialer
	direct  bool
	setName string

	mu       sync.Mutex
	members  map[string]*member
	order    []string // seed order
	setVer   int64
	electID  [12]byte
	haveElec bool
	changed  chan struct{} // closed and replaced on every change
	closed   bool
	wg       sync.WaitGroup
}

func newTopology(d *Dialer) *topology {
	t := &topology{
		d:       d,
		direct:  d.cfg.Direct(),
		setName: d.cfg.ReplicaSet,
		members: map[string]*member{},
		changed: make(chan struct{}),
	}
	hosts := d.cfg.HostList()
	if t.direct && len(hosts) > 1 {
		hosts = hosts[:1]
	}
	for _, h := range hosts {
		t.addMemberLocked(d.mapHost(h.Addr))
	}
	return t
}

func (t *topology) start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, m := range t.members {
		t.wg.Add(1)
		go m.run()
	}
}

func (t *topology) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	for _, m := range t.members {
		close(m.stop)
	}
	t.broadcastLocked()
	t.mu.Unlock()
	t.wg.Wait()
}

func (t *topology) addMemberLocked(addr string) *member {
	if m := t.members[addr]; m != nil {
		return m
	}
	m := &member{t: t, addr: addr, check: make(chan struct{}, 1), stop: make(chan struct{})}
	m.pool = newMemberPool(t.d, m)
	t.members[addr] = m
	t.order = append(t.order, addr)
	if !t.closed && t.d.started.Load() {
		t.wg.Add(1)
		go m.run()
	}
	return m
}

func (t *topology) removeMemberLocked(addr string) {
	m := t.members[addr]
	if m == nil {
		return
	}
	delete(t.members, addr)
	for i, a := range t.order {
		if a == addr {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
	close(m.stop)
	m.pool.clear()
}

func (t *topology) broadcastLocked() {
	close(t.changed)
	t.changed = make(chan struct{})
}

func (m *member) requestCheck() {
	select {
	case m.check <- struct{}{}:
	default:
	}
}

// ---- monitoring -------------------------------------------------------------

const minHeartbeat = 100 * time.Millisecond

func (m *member) run() {
	defer m.t.wg.Done()
	var mc *Conn
	closeConn := func() {
		if mc != nil {
			mc.Close()
			mc = nil
		}
	}
	defer closeConn()
	hb := m.t.d.cfg.Heartbeat()
	for {
		desc, err := m.probe(&mc)
		if err != nil {
			closeConn()
			// A member that just answered gets one immediate second chance
			// before being declared unknown.
			if m.t.known(m.addr) {
				desc, err = m.probe(&mc)
				if err != nil {
					closeConn()
				}
			}
		}
		if err != nil {
			desc = ServerDesc{Type: Unknown, Err: err, LastUpdate: time.Now()}
		}
		if !m.t.update(m, desc) {
			return
		}
		timer := time.NewTimer(hb)
		select {
		case <-m.stop:
			timer.Stop()
			return
		case <-m.check:
		case <-timer.C:
		}
		timer.Stop()
		select {
		case <-m.stop:
			return
		case <-time.After(minHeartbeat):
		}
	}
}

func (t *topology) known(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.members[addr]
	return m != nil && m.desc.known()
}

// probe runs one hello round trip on the monitoring connection.
func (m *member) probe(mc **Conn) (ServerDesc, error) {
	d := m.t.d
	ctx, cancel := context.WithTimeout(context.Background(), d.dial.Timeout+time.Second)
	defer cancel()
	if *mc == nil {
		c, err := d.dialAddr(ctx, m.addr, false)
		if err != nil {
			return ServerDesc{}, err
		}
		*mc = c
	}
	c := *mc
	c.SetDeadline(time.Now().Add(d.dial.Timeout + time.Second))
	defer c.SetDeadline(time.Time{})
	start := time.Now()
	cmd := bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "hello", 1))
	resp, err := d.RunCommand(c, "admin", cmd)
	if err != nil {
		return ServerDesc{}, err
	}
	if !Status(resp).OK {
		return ServerDesc{}, errors.New("hello failed")
	}
	desc := parseHello(resp)
	desc.RTT = time.Since(start)
	desc.LastUpdate = time.Now()
	return desc, nil
}

func parseHello(h bsoncore.Document) ServerDesc {
	d := ServerDesc{Hello: h}
	d.SetName, _ = h.Lookup("setName").StringValueOK()
	isPrimary, _ := h.Lookup("isWritablePrimary").BooleanOK()
	if !isPrimary {
		isPrimary, _ = h.Lookup("ismaster").BooleanOK()
	}
	secondary, _ := h.Lookup("secondary").BooleanOK()
	arbiter, _ := h.Lookup("arbiterOnly").BooleanOK()
	hidden, _ := h.Lookup("hidden").BooleanOK()
	ghost, _ := h.Lookup("isreplicaset").BooleanOK()
	msg, _ := h.Lookup("msg").StringValueOK()
	switch {
	case msg == "isdbgrid":
		d.Type = Mongos
	case ghost:
		d.Type = RSGhost
	case d.SetName == "":
		d.Type = Standalone
	case isPrimary:
		d.Type = RSPrimary
	case hidden:
		d.Type = RSOther
	case secondary:
		d.Type = RSSecondary
	case arbiter:
		d.Type = RSArbiter
	default:
		d.Type = RSOther
	}
	for _, k := range []string{"hosts", "passives", "arbiters"} {
		if arr, ok := h.Lookup(k).ArrayOK(); ok {
			vals, _ := arr.Values()
			for _, v := range vals {
				if s, ok := v.StringValueOK(); ok {
					d.Hosts = append(d.Hosts, s)
				}
			}
		}
	}
	d.Primary, _ = h.Lookup("primary").StringValueOK()
	if tags, ok := h.Lookup("tags").DocumentOK(); ok {
		d.Tags = map[string]string{}
		els, _ := tags.Elements()
		for _, e := range els {
			d.Tags[e.Key()], _ = e.Value().StringValueOK()
		}
	}
	if ms, ok := h.Lookup("lastWrite", "lastWriteDate").DateTimeOK(); ok {
		d.LastWrite = time.UnixMilli(ms)
	}
	if v, ok := h.Lookup("setVersion").AsInt64OK(); ok {
		d.SetVersion = v
	}
	if oid, ok := h.Lookup("electionId").ObjectIDOK(); ok {
		d.ElectionID = oid
		d.HasElection = true
	}
	return d
}

// update folds a fresh description into the topology (SDAM). It reports
// false when the member was removed and its monitor should exit.
func (t *topology) update(m *member, nd ServerDesc) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.members[m.addr] != m {
		return false
	}
	old := m.desc
	m.checked = true
	remove := func() bool {
		t.removeMemberLocked(m.addr)
		t.broadcastLocked()
		return false
	}
	if nd.Type != Unknown && !t.direct {
		if t.setName != "" && nd.SetName != t.setName && nd.Type != Mongos {
			t.d.log("upstream member has wrong replica set name", "addr", m.addr, "want", t.setName, "got", nd.SetName)
			return remove()
		}
		if nd.Type == Standalone && len(t.members) > 1 && t.setName != "" {
			return remove()
		}
	}
	switch nd.Type {
	case RSPrimary:
		if !t.direct {
			if t.setName == "" {
				t.setName = nd.SetName
			}
			// Ignore a stale primary (older election) per SDAM.
			if nd.HasElection && t.haveElec {
				if nd.SetVersion < t.setVer || (nd.SetVersion == t.setVer && bytes.Compare(nd.ElectionID[:], t.electID[:]) < 0) {
					nd = ServerDesc{Type: Unknown, Err: errors.New("stale primary"), LastUpdate: time.Now()}
					break
				}
			}
			if nd.HasElection {
				t.setVer, t.electID, t.haveElec = nd.SetVersion, nd.ElectionID, true
			}
			for a, o := range t.members {
				if a != m.addr && o.desc.Type == RSPrimary {
					o.desc = ServerDesc{Type: Unknown, LastUpdate: time.Now()}
					o.requestCheck()
				}
			}
			t.syncHostsLocked(nd.Hosts)
		}
	case RSSecondary, RSArbiter, RSOther:
		if !t.direct {
			if t.setName == "" {
				t.setName = nd.SetName
			}
			t.addHostsLocked(nd.Hosts)
			if nd.Primary != "" {
				if pm := t.members[t.d.mapHost(nd.Primary)]; pm != nil && !pm.desc.known() {
					pm.requestCheck()
				}
			}
		}
	}
	if old.RTT > 0 && nd.known() {
		nd.RTT = (old.RTT*4 + nd.RTT) / 5
	}
	m.desc = nd
	if old.Type == RSPrimary && nd.Type != RSPrimary || (old.known() && !nd.known()) {
		m.pool.clear() // connections to a former primary / dead member are suspect
	}
	if old.Type != nd.Type || old.Primary != nd.Primary {
		t.d.log("upstream topology change", "addr", m.addr, "from", old.Type.String(), "to", nd.Type.String(), "err", nd.Err)
		t.d.events.Add(1)
	}
	t.broadcastLocked()
	return true
}

// settled waits (bounded) until every known member has been probed once, so
// the first selection sees the whole set rather than whoever answered first.
func (t *topology) settled(ctx context.Context, max time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, max)
	defer cancel()
	for {
		t.mu.Lock()
		all := true
		for _, m := range t.members {
			all = all && m.checked
		}
		ch := t.changed
		t.mu.Unlock()
		if all {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
	}
}

func (t *topology) addHostsLocked(hosts []string) {
	for _, h := range hosts {
		t.addMemberLocked(t.d.mapHost(h))
	}
}

func (t *topology) syncHostsLocked(hosts []string) {
	want := map[string]bool{}
	for _, h := range hosts {
		want[t.d.mapHost(h)] = true
	}
	for a := range t.members {
		if !want[a] {
			t.removeMemberLocked(a)
		}
	}
	t.addHostsLocked(hosts)
}

// markUnknown is called when a command reveals that a member is no longer
// what the last heartbeat said (network error, "not primary", shutdown).
func (t *topology) markUnknown(addr string, clearPool bool, cause error) {
	t.mu.Lock()
	m := t.members[addr]
	if m == nil {
		t.mu.Unlock()
		return
	}
	if m.desc.known() {
		m.desc = ServerDesc{Type: Unknown, Err: cause, LastUpdate: time.Now()}
		t.d.events.Add(1)
		t.broadcastLocked()
	}
	t.mu.Unlock()
	if clearPool {
		m.pool.clear()
	}
	for _, o := range t.snapshot() {
		o.requestCheck()
	}
}

func (t *topology) snapshot() []*member {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*member, 0, len(t.members))
	for _, a := range t.order {
		out = append(out, t.members[a])
	}
	return out
}

// ---- selection --------------------------------------------------------------

var errNoMember = errors.New("upstream member no longer in topology")

// ErrSelection is returned when no member satisfied a selector in time.
type ErrSelection struct {
	Sel     Selector
	Timeout time.Duration
	Detail  string
}

func (e *ErrSelection) Error() string {
	return fmt.Sprintf("no suitable upstream member for read preference %s within %s: %s", e.Sel, e.Timeout, e.Detail)
}

// selectMember waits until a member satisfies sel.
func (t *topology) selectMember(ctx context.Context, sel Selector) (*member, error) {
	timeout := t.d.cfg.SelectionTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for first := true; ; first = false {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, errPoolClosed
		}
		m, err := t.pickLocked(sel)
		ch := t.changed
		detail := t.describeLocked()
		t.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if m != nil {
			return m, nil
		}
		if first {
			for _, o := range t.snapshot() {
				o.requestCheck()
			}
		}
		select {
		case <-ch:
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return nil, &ErrSelection{Sel: sel, Timeout: timeout, Detail: detail}
		}
	}
}

func (t *topology) describeLocked() string {
	var b bytes.Buffer
	for i, a := range t.order {
		m := t.members[a]
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: %s", a, m.desc.Type)
		if m.desc.Err != nil {
			fmt.Fprintf(&b, " (%v)", m.desc.Err)
		}
	}
	return b.String()
}

// pickLocked returns a suitable member, or nil to keep waiting.
func (t *topology) pickLocked(sel Selector) (*member, error) {
	if sel.Addr != "" {
		m := t.members[sel.Addr]
		if m == nil {
			return nil, errNoMember
		}
		if m.desc.known() {
			return m, nil
		}
		return nil, nil
	}
	var primary *member
	var secs, others []*member
	for _, a := range t.order {
		m := t.members[a]
		switch m.desc.Type {
		case RSPrimary:
			primary = m
		case RSSecondary:
			secs = append(secs, m)
		case Standalone, Mongos:
			others = append(others, m)
		}
	}
	if t.direct {
		for _, a := range t.order {
			if m := t.members[a]; m.desc.known() {
				return m, nil
			}
		}
		return nil, nil
	}
	if len(others) > 0 { // standalone or mongos behind the proxy: no roles
		return t.window(others), nil
	}
	switch sel.Mode {
	case Primary:
		return primary, nil
	case PrimaryPreferred:
		if primary != nil {
			return primary, nil
		}
		return t.chooseSecondary(secs, nil, sel), nil
	case Secondary:
		return t.chooseSecondary(secs, primary, sel), nil
	case SecondaryPreferred:
		if m := t.chooseSecondary(secs, primary, sel); m != nil {
			return m, nil
		}
		return primary, nil
	default: // Nearest
		cands := t.filterStale(secs, primary, sel)
		if primary != nil {
			cands = append(cands, primary)
		}
		return t.window(t.filterTags(cands, sel)), nil
	}
}

func (t *topology) chooseSecondary(secs []*member, primary *member, sel Selector) *member {
	return t.window(t.filterTags(t.filterStale(secs, primary, sel), sel))
}

// filterStale drops secondaries lagging beyond sel.MaxStaleness, using the
// SDAM max-staleness estimate.
func (t *topology) filterStale(secs []*member, primary *member, sel Selector) []*member {
	if sel.MaxStaleness <= 0 {
		return append([]*member(nil), secs...)
	}
	hb := t.d.cfg.Heartbeat()
	var best *member
	if primary == nil {
		for _, s := range secs {
			if best == nil || s.desc.LastWrite.After(best.desc.LastWrite) {
				best = s
			}
		}
	}
	var out []*member
	for _, s := range secs {
		var stale time.Duration
		if primary != nil {
			stale = s.desc.LastUpdate.Sub(s.desc.LastWrite) - primary.desc.LastUpdate.Sub(primary.desc.LastWrite) + hb
		} else {
			stale = best.desc.LastWrite.Sub(s.desc.LastWrite) + hb
		}
		if stale <= sel.MaxStaleness {
			out = append(out, s)
		}
	}
	return out
}

func (t *topology) filterTags(ms []*member, sel Selector) []*member {
	if len(sel.Tags) == 0 {
		return ms
	}
	for _, set := range sel.Tags {
		var out []*member
		for _, m := range ms {
			if tagsMatch(m.desc.Tags, set) {
				out = append(out, m)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// window picks among members within the latency window, preferring the one
// with fewer commands in flight (power of two choices).
func (t *topology) window(ms []*member) *member {
	if len(ms) == 0 {
		return nil
	}
	min := ms[0].desc.RTT
	for _, m := range ms {
		if m.desc.RTT < min {
			min = m.desc.RTT
		}
	}
	lim := min + t.d.cfg.Threshold()
	var in []*member
	for _, m := range ms {
		if m.desc.RTT <= lim {
			in = append(in, m)
		}
	}
	a := in[rand.IntN(len(in))]
	b := in[rand.IntN(len(in))]
	if b.inflight.Load() < a.inflight.Load() {
		return b
	}
	return a
}

func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
