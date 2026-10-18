package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/fanout"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

const defaultAwait = time.Second

// openStream serves a fresh change stream from the shared fan-out. It
// returns handled=false when the caller should fall back to a private
// server-side stream.
func (c *conn) openStream(h wire.Header, m *wire.Msg, res *rewrite.Result) (handled bool, err error) {
	if m.Flags&wire.FlagMoreToCome != 0 {
		return false, nil
	}
	if err := c.ensureUp(); err != nil {
		return false, nil
	}
	spec := res.Stream
	if res.DBLevel {
		c.s.dbStreams.Store(res.DB, struct{}{})
	}
	sub := c.s.fan.Subscribe(res.DB, res.Collection, fanout.TenantKey(c.tenant.Value.Type, c.tenant.Value.Data),
		fanout.Options{FullDocument: spec.FullDocument, Before: spec.Before, OpTypes: spec.OpTypes})

	// Anchor the stream at the cluster's current operation time: the client
	// must see events from after this call, not ones the shared stream
	// happens to still be delivering from before it.
	pong, err := c.s.dial.RunCommand(c.up, "admin", bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "ping", 1)))
	t, i, ok := pong.Lookup("operationTime").TimestampOK()
	if err != nil || !ok {
		sub.Close()
		return false, nil
	}
	token, err := sub.Start(fanout.Timestamp{T: t, I: i})
	if err != nil {
		c.log.Error("change stream fan-out failed", "err", err)
		c.cmdDone("aggregate", "error")
		return true, c.reply(h, errorDoc(8, "UnknownError", "tenant proxy: could not open change stream: "+err.Error()))
	}
	id := c.newCursorID()
	ns := res.DB + "." + res.Collection
	if res.DBLevel {
		ns = res.DB + ".$cmd.aggregate"
	}
	c.cursors[id] = ns
	c.streams[id] = sub
	c.cmdDone("aggregate", "ok")

	cursor := bsoncore.BuildDocument(nil,
		bsoncore.AppendArrayElement(nil, "firstBatch", bsoncore.BuildArray(nil)),
		bsoncore.AppendDocumentElement(nil, "postBatchResumeToken", token),
		bsoncore.AppendInt64Element(nil, "id", id),
		bsoncore.AppendStringElement(nil, "ns", ns),
	)
	return true, c.reply(h, bsoncore.BuildDocument(nil,
		bsoncore.AppendDocumentElement(nil, "cursor", cursor),
		bsoncore.AppendTimestampElement(nil, "operationTime", t, i),
		bsoncore.AppendInt32Element(nil, "ok", 1),
	))
}

func (c *conn) newCursorID() int64 {
	for {
		var b [8]byte
		rand.Read(b[:])
		id := int64(binary.LittleEndian.Uint64(b[:]) >> 1)
		if _, taken := c.cursors[id]; id != 0 && !taken {
			return id
		}
	}
}

func (c *conn) streamGetMore(h wire.Header, m *wire.Msg, id int64, sub *fanout.Sub, ns string) error {
	batch := 1000
	if v, ok := m.Body.Lookup("batchSize").AsInt64OK(); ok && v > 0 && v < 1000 {
		batch = int(v)
	}
	wait := defaultAwait
	if v, ok := m.Body.Lookup("maxTimeMS").AsInt64OK(); ok && v >= 0 {
		wait = time.Duration(v) * time.Millisecond
		if wait > time.Minute {
			wait = time.Minute
		}
	}
	events, token, done, err := sub.Next(batch, wait)
	if err != nil {
		sub.Close()
		delete(c.streams, id)
		delete(c.cursors, id)
		c.cmdDone("getMore", "error")
		return c.reply(h, resumableError(err))
	}
	vals := make([]bsoncore.Value, len(events))
	for i, e := range events {
		vals[i] = bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: e}
	}
	cid := id
	if done {
		cid = 0
		sub.Close()
		delete(c.streams, id)
		delete(c.cursors, id)
	}
	cursor := bsoncore.BuildDocument(nil,
		bsoncore.AppendArrayElement(nil, "nextBatch", bsoncore.BuildArray(nil, vals...)),
		bsoncore.AppendDocumentElement(nil, "postBatchResumeToken", token),
		bsoncore.AppendInt64Element(nil, "id", cid),
		bsoncore.AppendStringElement(nil, "ns", ns),
	)
	c.cmdDone("getMore", "ok")
	return c.reply(h, bsoncore.BuildDocument(nil,
		bsoncore.AppendDocumentElement(nil, "cursor", cursor),
		bsoncore.AppendInt32Element(nil, "ok", 1),
	))
}

// resumableError tells the driver to resume from its last token, which it
// does as a private server-side stream; no events are lost.
func resumableError(err error) bsoncore.Document {
	msg := "tenant proxy: change stream interrupted"
	if !errors.Is(err, fanout.ErrOverflow) {
		msg += ": " + err.Error()
	}
	return bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "ok", 0),
		bsoncore.AppendStringElement(nil, "errmsg", msg),
		bsoncore.AppendInt32Element(nil, "code", 11602), // InterruptedDueToReplStateChange
		bsoncore.AppendStringElement(nil, "codeName", "InterruptedDueToReplStateChange"),
		bsoncore.AppendArrayElement(nil, "errorLabels", bsoncore.BuildArray(nil,
			bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, "ResumableChangeStreamError")})),
	)
}
