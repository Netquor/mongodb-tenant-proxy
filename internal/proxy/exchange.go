package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"io"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/upstream"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

const (
	defaultStreamThreshold = 256 * 1024
	// statusScanLimit bounds the replies we decode just to look for failover
	// errors; bigger ones are cursor batches.
	statusScanLimit = 64 * 1024
)

func (c *conn) streamThreshold() int {
	switch t := c.s.cfg.Streaming.ThresholdBytes; {
	case t < 0:
		return 0 // never stream
	case t == 0:
		return defaultStreamThreshold
	default:
		return t
	}
}

func (c *conn) maxPatchBytes() int {
	if m := c.s.cfg.Streaming.MaxPatchBytes; m > 0 {
		return m
	}
	return c.s.cfg.MaxMessageBytes
}

// exchange sends frame to the upstream member and relays the reply. It retries
// once, on another connection, in the two cases where that is provably safe:
// the request never left (write failed), or the member answered that it is not
// primary (so it did not run the command) - always for commands outside a
// transaction only.
func (c *conn) exchange(h wire.Header, flags uint32, res *rewrite.Result, getMoreID int64, frame []byte) error {
	rt := c.rt
	for attempt := 0; ; attempt++ {
		retry := attempt == 0 && !rt.inTxn && rt.pinned == nil
		if err := c.writeUp(h.RequestID, res.Command, frame); err != nil {
			c.upFailed(err)
			if retry && c.useUp(rt) == nil {
				c.s.M.UpstreamRetries.Add(1)
				continue
			}
			c.cmdDone(res.Command, "error")
			return c.reply(h, c.upstreamError(rt, err))
		}
		if flags&wire.FlagMoreToCome != 0 {
			c.cmdDone(res.Command, "ok")
			return nil // unacknowledged write: no reply
		}
		again, err := c.relayReply(h, flags, res, getMoreID, rt, retry)
		if again {
			c.s.M.UpstreamRetries.Add(1)
			if c.useUp(rt) == nil {
				continue
			}
			err = errors.New("no primary available")
			c.cmdDone(res.Command, "error")
			return c.reply(h, c.upstreamError(rt, err))
		}
		return err
	}
}

// relayReply reads the member's reply and delivers it. again=true asks the
// caller to repeat the command elsewhere.
func (c *conn) relayReply(h wire.Header, flags uint32, res *rewrite.Result, getMoreID int64, rt route, canRetry bool) (again bool, err error) {
	u := c.up
	rh, err := readHeader(u.R)
	if err != nil {
		return c.replyFailed(h, res, rt, canRetry && rt.read, err, false)
	}
	if rh.OpCode != wire.OpMsg && rh.OpCode != wire.OpCompressed {
		u.MarkBroken()
		return false, errors.New("unexpected upstream opcode")
	}
	maxMsg := c.s.cfg.MaxMessageBytes
	patch := res.Post != nil || res.Alias != "" || len(res.After) > 0 || res.IDCursor
	needParse := patch || tracksCursor(res.Command)
	limit := maxMsg
	if patch {
		limit = min(limit, c.maxPatchBytes())
	}
	overQuota := c.lim != nil && c.lim.L.MaxResultBytes > 0 && int(rh.Length) > c.lim.L.MaxResultBytes
	stream := rh.OpCode == wire.OpMsg && c.reqComp == wire.CompNone && !patch && !overQuota &&
		c.streamThreshold() > 0 && int(rh.Length) > c.streamThreshold()
	if !stream && int(rh.Length) > limit {
		// Too big to hold in memory for rewriting: refuse, and drop the
		// connection since the unread reply is still on it.
		c.upFailed(wire.ErrTooLarge)
		c.cmdDone(res.Command, "error")
		return false, c.reply(h, errorDoc(10334, "BSONObjectTooLarge",
			fmt.Sprintf("tenant proxy: reply of %d bytes exceeds the %d byte limit for rewritten replies", rh.Length, limit)))
	}
	if stream {
		return false, c.streamReply(h, res, getMoreID, rh)
	}
	rb := make([]byte, int(rh.Length)-16)
	if _, err := io.ReadFull(u.R, rb); err != nil {
		return c.replyFailed(h, res, rt, canRetry && rt.read, err, false)
	}
	raw := false
	if rh.OpCode == wire.OpCompressed {
		// Relay a compressed reply untouched when the client expects the same
		// compressor and nothing needs to look inside; small ones are opened
		// so failover errors are noticed.
		if id, ok := wire.CompressorID(rb); ok && !needParse && id == c.reqComp && id != wire.CompNone && len(rb) > statusScanLimit {
			raw = true
		} else {
			op, _, data, err := wire.Decompress(rb, maxMsg)
			if err != nil || op != wire.OpMsg {
				u.MarkBroken()
				return false, fmt.Errorf("upstream read: bad compressed reply: %v", err)
			}
			rb = data
		}
	}
	if raw {
		c.afterReply(res.Command, rt)
		c.cmdDone(res.Command, "ok")
		c.countOut(int64(len(rb) + 16))
		if c.lim != nil {
			c.lim.CountReply(len(rb) + 16)
		}
		return false, wire.WriteFrame(c.out(), rh.RequestID, h.RequestID, wire.OpCompressed, rb)
	}
	if c.lim != nil && c.lim.L.MaxResultBytes > 0 && len(rb) > c.lim.L.MaxResultBytes {
		return false, c.oversize(h, rb, res, getMoreID)
	}

	var rm *wire.Msg
	parse := func() error {
		if rm != nil {
			return nil
		}
		var err error
		rm, err = wire.ParseMsg(rb)
		return err
	}
	if len(rb) <= statusScanLimit {
		if err := parse(); err == nil {
			if st := upstream.Status(rm.Body); st.Code != 0 && upstream.IsStateChange(st.Code) {
				c.s.dial.StateChange(u.Addr, st.Code)
				if !st.OK && upstream.IsNotPrimary(st.Code) && canRetry {
					c.dropUp()
					return true, nil
				}
				if rb2 := c.labelFailover(rt, rm, st); rb2 != nil {
					rb = rb2
				}
			}
		}
	}
	if needParse {
		if err := parse(); err != nil {
			return false, err
		}
		if len(res.After) > 0 {
			if ok, _ := rm.Body.Lookup("ok").AsInt64OK(); ok == 1 {
				if bad := c.runSteps(res.After); bad != nil {
					c.cmdDone(res.Command, "error")
					return false, c.reply(h, bad)
				}
			}
		}
		if res.Post != nil {
			rm.Body = res.Post(rm.Body)
			rb = rm.Encode()
		}
		if res.Alias != "" {
			rm.Body = patchCursorNS(rm.Body, res.DB+"."+res.Alias)
			rb = rm.Encode()
			c.noteViewCursor(rm.Body, res.Phys, getMoreID)
		}
		c.trackCursor(res.Command, getMoreID, rm.Body)
		if res.IDCursor {
			c.noteIDCursor(res.Command, getMoreID, rm.Body)
		}
	}
	c.afterReply(res.Command, rt)
	c.cmdDone(res.Command, "ok")
	c.countOut(int64(len(rb) + 16))
	if c.lim != nil {
		c.lim.CountReply(len(rb) + 16)
	}
	return false, c.send(rh.RequestID, h.RequestID, wire.OpMsg, rb)
}

// writeUp sends a request upstream, compressing it when the upstream
// connection negotiated compression and the command may be compressed.
func (c *conn) writeUp(requestID int32, cmd string, body []byte) error {
	if c.up.Comp != wire.CompNone && wire.Compressible(cmd) {
		cb, err := wire.Compress(c.up.Comp, wire.OpMsg, body)
		if err != nil {
			return err
		}
		return wire.WriteFrame(c.up, requestID, 0, wire.OpCompressed, cb)
	}
	return wire.WriteFrame(c.up, requestID, 0, wire.OpMsg, body)
}

// labelFailover adds the error labels drivers need to retry a command that hit
// a failover, returning the re-encoded body (nil if unchanged).
func (c *conn) labelFailover(rt route, rm *wire.Msg, st upstream.ReplyStatus) []byte {
	var labels []string
	switch {
	case rt.inTxn:
		if !st.OK {
			labels = append(labels, upstream.LabelTransient)
		}
	case rt.retryableWrite:
		labels = append(labels, upstream.LabelRetryableWrite)
	}
	if len(labels) == 0 {
		return nil
	}
	nb := upstream.AddLabels(rm.Body, labels...)
	if len(nb) == len(rm.Body) {
		return nil
	}
	rm.Body = nb
	return rm.Encode()
}

// afterReply updates per-connection state once a command succeeded or failed
// in a way the client can see.
func (c *conn) afterReply(cmd string, rt route) {
	if rt.endTxn {
		c.endTxnConn()
		c.txnBody = nil
	}
}

// dropUp discards c.up without telling the topology (the member answered, the
// connection is healthy) - used before repeating a command on the new primary.
func (c *conn) dropUp() {
	u := c.up
	c.detach()
	c.up = nil
	if u == nil {
		return
	}
	if c.pooled() && !c.isPinned(u) {
		c.s.dial.Release(u)
	}
}

// replyFailed handles an upstream read failure before any byte of the reply
// reached the client.
func (c *conn) replyFailed(h wire.Header, res *rewrite.Result, rt route, retry bool, err error, wrote bool) (bool, error) {
	c.upFailed(err)
	if retry {
		return true, nil
	}
	c.cmdDone(res.Command, "error")
	return false, c.reply(h, c.upstreamError(rt, err))
}

func readHeader(r io.Reader) (wire.Header, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return wire.Header{}, err
	}
	h := wire.Header{
		Length:     safeconv.I32(binary.LittleEndian.Uint32(b[0:])),
		RequestID:  safeconv.I32(binary.LittleEndian.Uint32(b[4:])),
		ResponseTo: safeconv.I32(binary.LittleEndian.Uint32(b[8:])),
		OpCode:     safeconv.I32(binary.LittleEndian.Uint32(b[12:])),
	}
	if h.Length < 21 {
		return h, fmt.Errorf("wire: invalid message length %d", h.Length)
	}
	return h, nil
}

// streamReply relays a large reply in chunks, never holding more than the
// relay buffers.
func (c *conn) streamReply(h wire.Header, res *rewrite.Result, getMoreID int64, rh wire.Header) error {
	out := bufio.NewWriterSize(c.out(), relayBufSize)
	meta, err := relayStream(c.up.R, out, rh, h.RequestID)
	if err != nil {
		// Part of the reply may already be with the client: the stream is
		// unusable on both sides.
		c.up.MarkBroken()
		c.failConn(c.up, err)
		return fmt.Errorf("streaming upstream reply: %w", err)
	}
	if tracksCursor(res.Command) {
		c.noteCursor(res.Command, getMoreID, meta.ok, meta.cursorID, meta.ns)
	}
	c.afterReply(res.Command, c.rt)
	c.s.M.StreamedReplies.Add(1)
	c.cmdDone(res.Command, "ok")
	c.countOut(int64(rh.Length))
	if c.lim != nil {
		c.lim.CountReply(int(rh.Length))
	}
	return nil
}

var _ bsoncore.Document
