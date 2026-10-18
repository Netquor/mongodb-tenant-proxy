package upstream

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

var (
	errPoolClosed = errors.New("upstream: closed")
	// ErrPoolTimeout is returned when no pooled connection became free in time.
	ErrPoolTimeout = errors.New("upstream: timed out waiting for a free connection")
)

// memberPool is a bounded pool of authenticated connections to one member.
//
// sem holds one token per checked-out connection, which bounds the number of
// connections in use; idle ones are reused LIFO so a quiet pool shrinks.
type memberPool struct {
	d *Dialer
	m *member

	sem chan struct{}

	mu     sync.Mutex
	idle   []*Conn
	gen    uint64
	closed bool
}

func newMemberPool(d *Dialer, m *member) *memberPool {
	return &memberPool{d: d, m: m, sem: make(chan struct{}, d.cfg.PoolMaxSize())}
}

// get checks a connection out, waiting up to the pool wait timeout.
func (p *memberPool) get(ctx context.Context) (*Conn, error) {
	wait := time.NewTimer(p.d.cfg.PoolWait())
	defer wait.Stop()
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-wait.C:
		return nil, ErrPoolTimeout
	}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			<-p.sem
			return nil, errPoolClosed
		}
		var c *Conn
		if n := len(p.idle); n > 0 {
			c = p.idle[n-1]
			p.idle[n-1] = nil
			p.idle = p.idle[:n-1]
		}
		gen := p.gen
		p.mu.Unlock()
		if c == nil {
			nc, err := p.d.dialAddr(ctx, p.m.addr, true)
			if err != nil {
				<-p.sem
				return nil, err
			}
			nc.pool, nc.gen = p, gen
			p.d.pooledOpened.Add(1)
			return nc, nil
		}
		if time.Since(c.lastUsed) > time.Second && !c.alive() {
			c.Close()
			continue
		}
		return c, nil
	}
}

// put returns a healthy connection.
func (p *memberPool) put(c *Conn) {
	defer func() { <-p.sem }()
	p.mu.Lock()
	if p.closed || c.gen != p.gen || c.expired(p.d.cfg.PoolLifetime()) || c.broken {
		p.mu.Unlock()
		c.Close()
		return
	}
	c.lastUsed = time.Now()
	c.Conn.SetDeadline(time.Time{})
	p.idle = append(p.idle, c)
	p.mu.Unlock()
}

// discard drops a checked-out connection.
func (p *memberPool) discard(c *Conn) {
	c.Close()
	<-p.sem
}

// clear invalidates every connection (idle ones are closed now, checked-out
// ones when they come back).
func (p *memberPool) clear() {
	p.mu.Lock()
	p.gen++
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, c := range idle {
		c.Close()
	}
}

func (p *memberPool) close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, c := range idle {
		c.Close()
	}
}

// reap closes connections idle longer than idle or older than life.
func (p *memberPool) reap(idle, life time.Duration) {
	now := time.Now()
	p.mu.Lock()
	keep := p.idle[:0]
	var drop []*Conn
	for _, c := range p.idle {
		if now.Sub(c.lastUsed) > idle || c.expired(life) {
			drop = append(drop, c)
		} else {
			keep = append(keep, c)
		}
	}
	for i := len(keep); i < len(p.idle); i++ {
		p.idle[i] = nil
	}
	p.idle = keep
	p.mu.Unlock()
	for _, c := range drop {
		c.Close()
	}
}

func (p *memberPool) counts() (inUse, idle int) {
	p.mu.Lock()
	idle = len(p.idle)
	p.mu.Unlock()
	return len(p.sem), idle
}

// alive reports whether an idle connection is still open on the far side.
func (c *Conn) alive() bool {
	c.Conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	_, err := c.R.Peek(1)
	c.Conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (c *Conn) expired(life time.Duration) bool {
	return life > 0 && time.Since(c.born) > life
}
