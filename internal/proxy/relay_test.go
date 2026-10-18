package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	goruntime "runtime"
	"testing"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// cursorReply builds a server-style find reply: a firstBatch of n documents of
// about docSize bytes, then id and ns, then ok and trailing metadata.
func cursorReply(n, docSize int, id int64, ns string) []byte {
	pad := string(bytes.Repeat([]byte("x"), docSize))
	var vals []bsoncore.Value
	for i := 0; i < n; i++ {
		d := bsoncore.BuildDocument(nil,
			bsoncore.AppendInt32Element(nil, "_id", int32(i)),
			bsoncore.AppendStringElement(nil, "pad", pad),
			// A field that looks like the cursor metadata must not confuse the relay.
			bsoncore.AppendInt64Element(nil, "id", 12345),
		)
		vals = append(vals, bsoncore.Value{Type: bsoncore.TypeEmbeddedDocument, Data: d})
	}
	cursor := bsoncore.BuildDocument(nil,
		bsoncore.AppendArrayElement(nil, "firstBatch", bsoncore.BuildArray(nil, vals...)),
		bsoncore.AppendInt64Element(nil, "id", id),
		bsoncore.AppendStringElement(nil, "ns", ns),
	)
	body := bsoncore.BuildDocument(nil,
		bsoncore.AppendDocumentElement(nil, "cursor", cursor),
		bsoncore.AppendTimestampElement(nil, "operationTime", 7, 1),
		bsoncore.AppendInt32Element(nil, "ok", 1),
	)
	m := wire.Msg{Body: body}
	var buf bytes.Buffer
	wire.WriteFrame(&buf, 42, 0, wire.OpMsg, m.Encode())
	return buf.Bytes()
}

func readHdr(t testing.TB, b []byte) wire.Header {
	t.Helper()
	h, err := readHeader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRelayStreamCopiesAndReportsCursor(t *testing.T) {
	for _, tc := range []struct{ n, size int }{{0, 0}, {1, 10}, {50, 1000}, {400, 4096}} {
		frame := cursorReply(tc.n, tc.size, 987654321, "db.coll")
		// The upstream stream carries a second frame behind the first: it must be left alone.
		up := bufio.NewReaderSize(bytes.NewReader(append(append([]byte{}, frame...), "NEXT-FRAME"...)), 4096)
		var out bytes.Buffer
		bw := bufio.NewWriterSize(&out, 1024)
		h := readHdr(t, frame)
		if _, err := io.ReadFull(up, make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		meta, err := relayStream(up, bw, h, 99)
		if err != nil {
			t.Fatalf("n=%d: %v", tc.n, err)
		}
		if !meta.ok || meta.cursorID != 987654321 || meta.ns != "db.coll" {
			t.Fatalf("n=%d: meta %+v", tc.n, meta)
		}
		want := append([]byte{}, frame...)
		want[8], want[9], want[10], want[11] = 99, 0, 0, 0 // responseTo rewritten
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("n=%d: relayed bytes differ", tc.n)
		}
		rest, _ := io.ReadAll(up)
		if string(rest) != "NEXT-FRAME" {
			t.Fatalf("n=%d: relay over-read: %q", tc.n, rest)
		}
	}
}

func TestRelayStreamRejectsTruncatedAndLying(t *testing.T) {
	frame := cursorReply(5, 100, 1, "a.b")
	h := readHdr(t, frame)
	// Truncated upstream.
	up := bufio.NewReader(bytes.NewReader(frame[16 : len(frame)-10]))
	if _, err := relayStream(up, bufio.NewWriter(io.Discard), h, 1); err == nil {
		t.Fatal("expected error for truncated reply")
	}
	// A document length that overruns the frame.
	bad := append([]byte{}, frame...)
	bad[21], bad[22] = 0xff, 0xff // body document length
	up = bufio.NewReader(bytes.NewReader(bad[16:]))
	if _, err := relayStream(up, bufio.NewWriter(io.Discard), readHdr(t, bad), 1); err == nil {
		t.Fatal("expected error for lying length")
	}
}

func FuzzRelayStream(f *testing.F) {
	f.Add(cursorReply(3, 20, 5, "x.y"))
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) < 21 {
			return
		}
		h, err := readHeader(bytes.NewReader(frame))
		if err != nil || int(h.Length) > len(frame) {
			return
		}
		up := bufio.NewReader(bytes.NewReader(frame[16:h.Length]))
		var out bytes.Buffer
		relayStream(up, bufio.NewWriter(&out), h, 1) // must not panic or hang
	})
}

// cycle replays one frame forever.
type cycle struct {
	b   []byte
	off int
}

func (c *cycle) Read(p []byte) (int, error) {
	n := copy(p, c.b[c.off:])
	c.off = (c.off + n) % len(c.b)
	return n, nil
}

// bufferedRelay is the previous behaviour: read the whole reply, write it back.
func bufferedRelay(up *bufio.Reader, w io.Writer, responseTo int32) error {
	h, body, err := wire.ReadFrame(up, 64<<20)
	if err != nil {
		return err
	}
	return wire.WriteFrame(w, h.RequestID, responseTo, wire.OpMsg, body)
}

// BenchmarkRelayLargeBatch compares relaying one large cursor batch the old
// way (buffer the whole reply) with the streaming relay. Compare B/op and the
// peak-heap metric; the streaming relay's memory does not grow with the batch.
func BenchmarkRelayLargeBatch(b *testing.B) {
	for _, mb := range []int{1, 8, 32} {
		frame := cursorReply(mb*1024, 1000, 77, "bench.c") // ~mb MiB in 1 KiB documents
		for _, mode := range []string{"buffered", "streaming"} {
			b.Run(fmt.Sprintf("%dMiB/%s", mb, mode), func(b *testing.B) {
				up := bufio.NewReaderSize(&cycle{b: frame}, 64*1024)
				out := bufio.NewWriterSize(io.Discard, relayBufSize)
				goruntime.GC()
				var base goruntime.MemStats
				goruntime.ReadMemStats(&base)
				var peak uint64
				b.SetBytes(int64(len(frame)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var err error
					if mode == "buffered" {
						err = bufferedRelay(up, io.Discard, 1)
					} else {
						var h wire.Header
						if h, err = readHeader(up); err == nil {
							_, err = relayStream(up, out, h, 1)
						}
					}
					if err != nil {
						b.Fatal(err)
					}
					if i%4 == 0 {
						var ms goruntime.MemStats
						goruntime.ReadMemStats(&ms)
						if ms.HeapAlloc > peak {
							peak = ms.HeapAlloc
						}
					}
				}
				b.ReportMetric(float64(peak-min(peak, base.HeapAlloc))/(1<<20), "peakHeapMiB")
			})
		}
	}
}

var _ = rand.IntN
