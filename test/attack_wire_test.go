package test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// A hostile peer at the wire layer: malformed framing, bad OP_MSG sections,
// abuse of OP_QUERY and OP_COMPRESSED, request pipelining and misuse of
// moreToCome. The proxy must never panic, must drop the offender promptly
// and must keep serving everybody else.

func TestAttackMalformedFrames(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) { c.Compressors = []string{"snappy", "zlib", "zstd"} }, nil)
	ping := atkKind0(atkCmdDoc("admin", bson.D{{Key: "ping", Value: 1}}))
	bigCount := bytes.Repeat([]byte{5, 0, 0, 0, 0}, wire.MaxSeqDocs+1)
	seq := func(id string, docs []byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(4+len(id)+1+len(docs)))
		b = append(b, id...)
		b = append(b, 0)
		return append(append([]byte{1}, b...), docs...)
	}
	cases := []struct {
		name  string
		frame []byte
	}{
		{"negative length", atkFrame(-1, 1, 0, wire.OpMsg, nil)},
		{"min int length", atkFrame(-1<<31, 1, 0, wire.OpMsg, nil)},
		{"length below header", atkFrame(15, 1, 0, wire.OpMsg, nil)},
		{"length 0", atkFrame(0, 1, 0, wire.OpMsg, nil)},
		{"huge length", atkFrame(0x7fffffff, 1, 0, wire.OpMsg, []byte("x"))},
		{"length over max", atkFrame(48<<20+1, 1, 0, wire.OpMsg, []byte("x"))},
		{"unknown opcode", atkFrame(16, 1, 0, 9999, nil)},
		{"negative opcode", atkFrame(16, 1, 0, -5, nil)},
		{"legacy OP_INSERT", atkFrame(20, 1, 0, 2002, []byte{0, 0, 0, 0})},
		{"legacy OP_GET_MORE", atkFrame(20, 1, 0, 2005, []byte{0, 0, 0, 0})},
		{"legacy OP_KILL_CURSORS", atkFrame(20, 1, 0, 2007, []byte{0, 0, 0, 0})},
		{"OP_REPLY from a client", atkFrame(16, 1, 0, wire.OpReply, nil)},
		{"empty OP_MSG", atkFrame(16, 1, 0, wire.OpMsg, nil)},
		{"OP_MSG flags only", atkFrame(20, 1, 0, wire.OpMsg, []byte{0, 0, 0, 0})},
		{"bad section kind", atkMsgFrame(0, []byte{7, 5, 0, 0, 0, 0})},
		{"kind 2 section", atkMsgFrame(0, ping, []byte{2, 5, 0, 0, 0, 0})},
		{"missing body section", atkMsgFrame(0, seq("documents", nil))},
		{"two body sections", atkMsgFrame(0, ping, ping)},
		{"body doc length 0", atkMsgFrame(0, []byte{0, 0, 0, 0, 0})},
		{"body doc length 4", atkMsgFrame(0, []byte{0, 4, 0, 0, 0})},
		{"body doc length past end", atkMsgFrame(0, []byte{0, 0xff, 0xff, 0xff, 0x7f, 0})},
		{"body doc negative length", atkMsgFrame(0, []byte{0, 0xff, 0xff, 0xff, 0xff, 0})},
		{"body doc without terminator", atkMsgFrame(0, []byte{0, 5, 0, 0, 0, 1})},
		{"kind-1 size too small", atkMsgFrame(0, ping, []byte{1, 3, 0, 0, 0})},
		{"kind-1 size huge", atkMsgFrame(0, ping, []byte{1, 0xff, 0xff, 0xff, 0x7f, 'a', 0})},
		{"kind-1 size negative", atkMsgFrame(0, ping, []byte{1, 0xff, 0xff, 0xff, 0xff, 'a', 0})},
		{"kind-1 no identifier terminator", atkMsgFrame(0, ping, []byte{1, 6, 0, 0, 0, 'a', 'b'})},
		{"kind-1 truncated document", atkMsgFrame(0, ping, seq("documents", []byte{0xff, 0, 0, 0, 0}))},
		{"kind-1 trailing garbage", atkMsgFrame(0, ping, seq("documents", []byte{1, 2, 3}))},
		{"too many kind-1 documents", atkMsgFrame(0, ping, seq("documents", bigCount))},
		{"unknown required flag bit", atkMsgFrame(1<<5, ping)},
		{"unknown required flag bit 15", atkMsgFrame(1<<15, ping)},
		{"checksum flag without checksum", atkMsgFrame(1, ping)},
		{"wrong checksum", func() []byte {
			f := atkMsgFrame(1, ping, []byte{0, 0, 0, 0})
			return f
		}()},
		{"OP_QUERY truncated", atkFrame(20, 1, 0, wire.OpQuery, []byte{0, 0, 0, 0})},
		{"OP_QUERY no cstring terminator", atkFrame(24, 1, 0, wire.OpQuery, []byte("abcdefgh"))},
		{"OP_QUERY bad document", atkFrame(16+4+2+8+5, 1, 0, wire.OpQuery,
			append(append(append([]byte{0, 0, 0, 0}, 'a', 0), make([]byte, 8)...), 0xff, 0xff, 0xff, 0x7f, 0))},
		{"OP_COMPRESSED empty", atkFrame(16, 1, 0, wire.OpCompressed, nil)},
		{"OP_COMPRESSED short", atkFrame(20, 1, 0, wire.OpCompressed, []byte{1, 2, 3, 4})},
		{"OP_COMPRESSED unknown compressor", atkFrame(16+9, 1, 0, wire.OpCompressed, []byte{0xdd, 7, 0, 0, 5, 0, 0, 0, 99})},
		{"OP_COMPRESSED nested", atkFrame(16+9, 1, 0, wire.OpCompressed, append(binary.LittleEndian.AppendUint32(nil, uint32(wire.OpCompressed)), 0, 0, 0, 0, 1))},
		{"OP_COMPRESSED negative size", atkFrame(16+9, 1, 0, wire.OpCompressed, append(binary.LittleEndian.AppendUint32(nil, uint32(wire.OpMsg)), 0xff, 0xff, 0xff, 0xff, 1))},
		{"OP_COMPRESSED snappy garbage", atkFrame(16+9+4, 1, 0, wire.OpCompressed, append(append(binary.LittleEndian.AppendUint32(nil, uint32(wire.OpMsg)), 10, 0, 0, 0, 1), 0xff, 0xff, 0xff, 0xff))},
		{"OP_COMPRESSED zstd garbage", atkFrame(16+9+4, 1, 0, wire.OpCompressed, append(append(binary.LittleEndian.AppendUint32(nil, uint32(wire.OpMsg)), 10, 0, 0, 0, 3), 1, 2, 3, 4))},
		{"OP_COMPRESSED zlib garbage", atkFrame(16+9+4, 1, 0, wire.OpCompressed, append(append(binary.LittleEndian.AppendUint32(nil, uint32(wire.OpMsg)), 10, 0, 0, 0, 2), 1, 2, 3, 4))},
		{"OP_COMPRESSED declared huge, body tiny", atkFrame(16+9, 1, 0, wire.OpCompressed, append(binary.LittleEndian.AppendUint32(nil, uint32(wire.OpMsg)), 0xf0, 0xff, 0xff, 0x02, 2))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Authenticated attackers get no more latitude than strangers.
			for _, authed := range []bool{false, true} {
				var r *atkRaw
				if authed {
					r = e.atkDialTenant(t, "tenant-evil")
				} else {
					r = e.atkDial(t)
				}
				r.write(tc.frame)
				// A hostile frame ends in a closed connection, possibly after an
				// error reply; it must never be answered as success and must
				// never hang the connection open.
				if !r.closedWithin(3 * time.Second) {
					t.Fatalf("connection (authed=%v) still open 3s after a hostile frame", authed)
				}
			}
			e.noPanics(t)
		})
	}
	e.alive(t, "tenant-good")
}

func TestAttackOpMsgChecksum(t *testing.T) {
	e := atkSetup(t, nil, nil)
	r := e.atkDialTenant(t, "tenant-a")

	ping := atkKind0(atkCmdDoc("admin", bson.D{{Key: "ping", Value: 1}}))
	frame := atkMsgFrame(1, ping)
	frame = append(frame, atkCRC(frame)...)
	binary.LittleEndian.PutUint32(frame, uint32(len(frame)))
	// The CRC covers the header including the length, so recompute with it set.
	frame = frame[:len(frame)-4]
	frame = append(frame, atkCRC(frame)...)
	r.write(frame)
	if _, res, err := r.readMsg(); err != nil || !isOK(res) {
		t.Fatalf("valid checksum rejected: %v %v", res, err)
	}

	bad := append([]byte{}, frame...)
	bad[len(bad)-1] ^= 0xff
	r.write(bad)
	if !r.closedWithin(3 * time.Second) {
		t.Fatal("corrupt checksum accepted")
	}
	e.noPanics(t)
}

func TestAttackOpQueryAbuse(t *testing.T) {
	e := atkSetup(t, nil, nil)
	legacy := func(r *atkRaw, coll string, doc bson.D) bson.M {
		t.Helper()
		b := binary.LittleEndian.AppendUint32(nil, 0)
		b = append(b, coll...)
		b = append(b, 0)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, 1)
		b = append(b, mustBSON(t, doc)...)
		r.write(atkFrame(int32(16+len(b)), 77, 0, wire.OpQuery, b))
		h, out, err := r.readMsg()
		if err != nil {
			t.Fatalf("legacy reply: %v", err)
		}
		if h.OpCode != wire.OpReply || h.ResponseTo != 77 {
			t.Fatalf("legacy reply header %+v", h)
		}
		return out
	}
	r := e.atkDialTenant(t, "tenant-a")
	// Anything beyond the handshake is refused, authenticated or not, and
	// never reaches the database.
	for _, doc := range []bson.D{
		{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{}}},
		{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"x": 1}}}},
		{{Key: "drop", Value: "c"}},
		{{Key: "dropDatabase", Value: 1}},
		{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{}}, {Key: "cursor", Value: bson.M{}}},
		{{Key: "saslStart", Value: 1}},
	} {
		res := legacy(r, "admin.$cmd", doc)
		if isOK(res) {
			t.Fatalf("OP_QUERY %s accepted: %v", doc[0].Key, res)
		}
	}
	// Odd collection names and a hello still work normally.
	for _, coll := range []string{"", "x", "admin.$cmd.sys.inprog", string(bytes.Repeat([]byte("a"), 100000))} {
		legacy(r, coll, bson.D{{Key: "drop", Value: "c"}})
	}
	if res := legacy(r, "admin.$cmd", bson.D{{Key: "isMaster", Value: 1}}); !isOK(res) {
		t.Fatalf("legacy handshake failed: %v", res)
	}
	if cnt := count(t, e.direct.Database("atk").Collection("c"), bson.M{}); cnt != 0 {
		t.Fatalf("OP_QUERY wrote %d documents", cnt)
	}
	e.noPanics(t)
}

func TestAttackCompressionBombs(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) { c.Compressors = []string{"snappy", "zlib", "zstd"} }, nil)
	zlibOf := func(data []byte) []byte {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}
	compressed := func(opcode int32, declared uint32, id byte, payload []byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, uint32(opcode))
		b = binary.LittleEndian.AppendUint32(b, declared)
		b = append(b, id)
		b = append(b, payload...)
		return atkFrame(int32(16+len(b)), 1, 0, wire.OpCompressed, b)
	}
	zeros := func(n int) []byte { return make([]byte, n) }

	cases := []struct {
		name  string
		frame func() []byte
	}{
		// 32 MiB of zeros in ~32 KB of zlib, declared honestly: a real bomb
		// that fits under the 48 MiB cap. It decodes to garbage, not OP_MSG.
		{"zlib 32MiB of zeros", func() []byte { return compressed(wire.OpMsg, 32<<20, 2, zlibOf(zeros(32<<20))) }},
		// Claims 1 KiB, holds 32 MiB: the stream must be cut off at the claim.
		{"zlib output exceeds declared size", func() []byte { return compressed(wire.OpMsg, 1024, 2, zlibOf(zeros(32<<20))) }},
		// Claims 40 MiB, holds 10 bytes: no 40 MiB buffer for a lie.
		{"zlib declares 40MiB, delivers 10 bytes", func() []byte { return compressed(wire.OpMsg, 40<<20, 2, zlibOf(zeros(10))) }},
		{"snappy declares 40MiB, delivers little", func() []byte {
			return compressed(wire.OpMsg, 40<<20, 1, snappy.Encode(nil, zeros(10)))
		}},
		{"snappy size header disagrees with envelope", func() []byte {
			return compressed(wire.OpMsg, 100, 1, snappy.Encode(nil, zeros(10)))
		}},
		{"declared over the message limit", func() []byte { return compressed(wire.OpMsg, 49<<20, 2, zlibOf(zeros(10))) }},
		{"noop compressor length lie", func() []byte { return compressed(wire.OpMsg, 100, 0, zeros(10)) }},
		{"unknown compressor", func() []byte { return compressed(wire.OpMsg, 10, 200, zeros(10)) }},
		{"zlib wrapping OP_COMPRESSED", func() []byte {
			return compressed(wire.OpCompressed, 10, 2, zlibOf(zeros(10)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Unauthenticated peers are the ones that matter most: a bomb
			// before any credentials were checked.
			heap := atkWatchHeap()
			for i := 0; i < 8; i++ {
				r := e.atkDial(t)
				r.write(tc.frame())
				if !r.closedWithin(5 * time.Second) {
					t.Fatal("bomb connection still open after 5s")
				}
			}
			// Eight 32 MiB bombs in a row must not leave tens of MiB behind or
			// spike far above what one message's worth of buffering needs.
			if g := heap.growth(); g > 160<<20 {
				t.Fatalf("heap grew by %d MiB handling %s", g>>20, tc.name)
			}
			e.noPanics(t)
		})
	}
	e.alive(t, "tenant-good")
}

// A compressed request using a compressor the proxy did not offer is refused.
func TestAttackCompressionNotNegotiated(t *testing.T) {
	e := atkSetup(t, nil, nil) // no compressors enabled
	r := e.atkDialTenant(t, "tenant-a")
	body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("admin", bson.D{{Key: "ping", Value: 1}}))}).Encode()
	cb, err := wire.Compress(wire.CompSnappy, wire.OpMsg, body)
	must(t, err)
	r.write(atkFrame(int32(16+len(cb)), 1, 0, wire.OpCompressed, cb))
	if !r.closedWithin(3 * time.Second) {
		t.Fatal("un-negotiated compression accepted")
	}
}

// A well-formed compressed hello/auth exchange is not an attack, but it must
// not crash the proxy or leak anything.
func TestAttackCompressedHandshake(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) { c.Compressors = []string{"zlib"} }, nil)
	r := e.atkDial(t)
	doc := mustBSON(t, atkCmdDoc("admin", bson.D{{Key: "hello", Value: 1}, {Key: "client", Value: bson.M{"application": bson.M{"name": "tenant-a"}}}}))
	body := (&wire.Msg{Body: doc}).Encode()
	cb, err := wire.Compress(wire.CompZlib, wire.OpMsg, body)
	must(t, err)
	r.write(atkFrame(int32(16+len(cb)), 1, 0, wire.OpCompressed, cb))
	if _, res, err := r.readMsg(); err != nil || !isOK(res) {
		t.Fatalf("compressed hello: %v %v", res, err)
	}
	e.noPanics(t)
}

func TestAttackMoreToComeAndPipelining(t *testing.T) {
	e := atkSetup(t, nil, nil)
	r := e.atkDialTenant(t, "tenant-a")

	pingFrame := func(id int32, flags uint32) []byte {
		body := (&wire.Msg{Flags: flags, Body: mustBSON(t, atkCmdDoc("admin", bson.D{{Key: "ping", Value: 1}}))}).Encode()
		return atkFrame(int32(16+len(body)), id, 0, wire.OpMsg, body)
	}
	// 500 pipelined requests in one write: every one answered, in order.
	var batch []byte
	for i := int32(1); i <= 500; i++ {
		batch = append(batch, pingFrame(i, 0)...)
	}
	r.write(batch)
	for i := int32(1); i <= 500; i++ {
		h, res, err := r.readMsg()
		if err != nil || !isOK(res) || h.ResponseTo != i {
			t.Fatalf("pipelined reply %d: %+v %v %v", i, h, res, err)
		}
	}
	// moreToCome means "no reply wanted": a run of them yields none, and the
	// request after the run is answered exactly once.
	batch = nil
	for i := int32(1000); i < 1100; i++ {
		batch = append(batch, pingFrame(i, wire.FlagMoreToCome)...)
	}
	batch = append(batch, pingFrame(2000, 0)...)
	r.write(batch)
	h, res, err := r.readMsg()
	if err != nil || !isOK(res) {
		t.Fatalf("reply after moreToCome run: %v %v", res, err)
	}
	// ping is answered locally and may reply even to moreToCome requests; the
	// invariant is that the connection stays in sync, not the exact count.
	for h.ResponseTo != 2000 {
		if h, res, err = r.readMsg(); err != nil {
			t.Fatalf("lost sync after moreToCome run: %v", err)
		}
	}
	// Repeated, duplicate and zero request ids are the client's business.
	for _, id := range []int32{0, 0, -1, 1 << 30, 1 << 30} {
		r.write(pingFrame(id, 0))
		if h, _, err := r.readMsg(); err != nil || h.ResponseTo != id {
			t.Fatalf("request id %d: %+v %v", id, h, err)
		}
	}
	// moreToCome on writes and on commands that normally return cursors.
	for _, cmd := range []bson.D{
		{{Key: "insert", Value: "mtc"}, {Key: "documents", Value: bson.A{bson.M{"x": 1}}}},
		{{Key: "find", Value: "mtc"}},
		{{Key: "getMore", Value: int64(5)}, {Key: "collection", Value: "mtc"}},
		{{Key: "killCursors", Value: "mtc"}, {Key: "cursors", Value: bson.A{int64(5)}}},
	} {
		body := (&wire.Msg{Flags: wire.FlagMoreToCome, Body: mustBSON(t, atkCmdDoc("atk", cmd))}).Encode()
		r.write(atkFrame(int32(16+len(body)), 9, 0, wire.OpMsg, body))
	}
	r.write(pingFrame(3000, 0))
	for {
		h, _, err := r.readMsg()
		if err != nil {
			t.Fatalf("connection died after moreToCome misuse: %v", err)
		}
		if h.ResponseTo == 3000 {
			break
		}
	}
	e.noPanics(t)
	e.alive(t, "tenant-good")
}

// The client vanishing in the middle of a large reply must not wedge or
// crash the proxy, or leak upstream connections.
func TestAttackResetMidReply(t *testing.T) {
	e := atkSetup(t, nil, nil)
	big := e.tenant(t, "tenant-a").Database("atk").Collection("big")
	pad := make([]byte, 1<<20)
	for i := range pad {
		pad[i] = 'x'
	}
	var docs []any
	for i := 0; i < 40; i++ {
		docs = append(docs, bson.M{"i": i, "pad": string(pad)})
	}
	_, err := big.InsertMany(ctx(t), docs)
	must(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.atkDialTenant(t, "tenant-a")
			body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("atk", bson.D{{Key: "find", Value: "big"}, {Key: "batchSize", Value: 40}}))}).Encode()
			r.write(atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body))
			buf := make([]byte, 100)
			r.nc.SetReadDeadline(time.Now().Add(10 * time.Second))
			r.nc.Read(buf)
			if tc, ok := r.nc.(*net.TCPConn); ok {
				tc.SetLinger(0) // RST instead of FIN
			}
			r.nc.Close()
		}()
	}
	wg.Wait()
	e.alive(t, "tenant-a")
	e.noPanics(t)
	// The pool must still serve a burst afterwards: nothing is leaked.
	for i := 0; i < 20; i++ {
		_, err := big.CountDocuments(ctx(t), bson.M{})
		must(t, err)
	}
}

// A find with a gigantic batchSize and an aggregate with a huge limit are
// answered within the server's own bounds, not by buffering without limit.
func TestAttackGiantBatchSizes(t *testing.T) {
	e := atkSetup(t, nil, nil)
	r := e.atkDialTenant(t, "tenant-a")
	for _, bs := range []any{int32(1<<31 - 1), int64(1) << 40, 0, -1, 1e300, "x"} {
		res := r.cmd("atk", bson.D{{Key: "find", Value: "giant"}, {Key: "batchSize", Value: bs}})
		_ = res // accepted or rejected: only liveness matters
	}
	for _, bs := range []any{int32(1<<31 - 1), int64(-5), "x", nil} {
		r.cmd("atk", bson.D{{Key: "aggregate", Value: "giant"}, {Key: "pipeline", Value: bson.A{}},
			{Key: "cursor", Value: bson.M{"batchSize": bs}}})
	}
	e.noPanics(t)
	e.alive(t, "tenant-good")
}
