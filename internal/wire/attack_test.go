package wire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
)

// reader that yields a header claiming n bytes then blocks forever, counting
// how much the caller asked to be allocated via the read sizes.
type stalled struct {
	head []byte
	pos  int
	max  int // largest read buffer ever offered
}

func (s *stalled) Read(p []byte) (int, error) {
	if len(p) > s.max {
		s.max = len(p)
	}
	if s.pos < len(s.head) {
		n := copy(p, s.head[s.pos:])
		s.pos += n
		return n, nil
	}
	return 0, io.ErrUnexpectedEOF // the peer went away without sending the body
}

// A header that claims a huge body must not make ReadFrame allocate it before
// the bytes show up.
func TestReadFrameDoesNotTrustTheDeclaredLength(t *testing.T) {
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr, 40<<20)
	binary.LittleEndian.PutUint32(hdr[12:], uint32(OpMsg))
	s := &stalled{head: hdr}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := ReadFrame(s, 48<<20)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("truncated frame accepted")
	}
	if s.max > 1<<20 {
		t.Fatalf("ReadFrame offered a %d MiB buffer to a peer that had sent nothing", s.max>>20)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 4<<20 {
		t.Fatalf("allocated %d MiB for a body that never arrived", grown>>20)
	}
}

func TestReadFrameRoundTripsLargeBodies(t *testing.T) {
	for _, n := range []int{0, 1, readChunk - 1, readChunk, readChunk + 1, 3*readChunk + 7, 5 << 20} {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i * 7)
		}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, 5, 6, OpMsg, body); err != nil {
			t.Fatal(err)
		}
		h, got, err := ReadFrame(&buf, 0)
		if err != nil || h.RequestID != 5 || !bytes.Equal(got, body) {
			t.Fatalf("n=%d: %v %+v", n, err, h)
		}
	}
	// Truncated at every interesting point.
	var buf bytes.Buffer
	WriteFrame(&buf, 1, 0, OpMsg, make([]byte, 3*readChunk))
	full := buf.Bytes()
	for _, cut := range []int{0, 5, 15, 16, 17, 16 + readChunk, 16 + readChunk + 1, len(full) - 1} {
		if _, _, err := ReadFrame(bytes.NewReader(full[:cut]), 0); err == nil {
			t.Fatalf("frame cut at %d accepted", cut)
		}
	}
}

func msgWith(flags uint32, sections ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, flags)
	for _, s := range sections {
		b = append(b, s...)
	}
	return b
}

var emptyDoc = []byte{5, 0, 0, 0, 0}

func TestParseMsgLimits(t *testing.T) {
	body := append([]byte{0}, emptyDoc...)
	seq := func(id string, n int) []byte {
		docs := bytes.Repeat(emptyDoc, n)
		b := binary.LittleEndian.AppendUint32([]byte{1}, uint32(4+len(id)+1+len(docs)))
		b = append(b, id...)
		b = append(b, 0)
		return append(b, docs...)
	}
	if _, err := ParseMsg(msgWith(0, body, seq("documents", MaxSeqDocs))); err != nil {
		t.Fatalf("a batch of exactly %d documents refused: %v", MaxSeqDocs, err)
	}
	if _, err := ParseMsg(msgWith(0, body, seq("documents", MaxSeqDocs+1))); err == nil {
		t.Fatal("batch over the document cap accepted")
	}
	// Sequences count together.
	if _, err := ParseMsg(msgWith(0, body, seq("a", MaxSeqDocs), seq("b", 1))); err == nil {
		t.Fatal("document cap applies per section, not per message")
	}
	// Section flood: each costs 6 bytes.
	var many [][]byte
	many = append(many, body)
	for i := 0; i < MaxSeqs+1; i++ {
		many = append(many, seq("s", 0))
	}
	if _, err := ParseMsg(msgWith(0, many...)); err == nil {
		t.Fatal("too many kind-1 sections accepted")
	}
	// Allocation stays small for the worst accepted message.
	msg := msgWith(0, body, seq("documents", MaxSeqDocs))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := ParseMsg(msg); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 16<<20 {
		t.Fatalf("parsing a %d byte message allocated %d MiB", len(msg), grown>>20)
	}
}

func TestParseMsgFlags(t *testing.T) {
	body := append([]byte{0}, emptyDoc...)
	for bit := 2; bit < 16; bit++ {
		if _, err := ParseMsg(msgWith(1<<bit, body)); err == nil {
			t.Errorf("unknown required flag bit %d accepted", bit)
		}
	}
	// Optional bits (16 and up) are ignorable by definition.
	if _, err := ParseMsg(msgWith(FlagExhaustAllowed|1<<20|1<<31, body)); err != nil {
		t.Errorf("optional flag bits rejected: %v", err)
	}
	if _, err := ParseMsg(msgWith(FlagMoreToCome, body)); err != nil {
		t.Errorf("moreToCome rejected: %v", err)
	}
}

func TestVerifyChecksum(t *testing.T) {
	body := msgWith(FlagChecksumPresent, append([]byte{0}, emptyDoc...))
	body = append(body, 0, 0, 0, 0)
	h := Header{Length: int32(16 + len(body)), RequestID: 9, ResponseTo: 3, OpCode: OpMsg}
	if err := VerifyChecksum(h, body); err == nil {
		t.Fatal("zero checksum accepted")
	}
	var hb [16]byte
	binary.LittleEndian.PutUint32(hb[0:], uint32(h.Length))
	binary.LittleEndian.PutUint32(hb[4:], uint32(h.RequestID))
	binary.LittleEndian.PutUint32(hb[8:], uint32(h.ResponseTo))
	binary.LittleEndian.PutUint32(hb[12:], uint32(h.OpCode))
	sum := crcUpdate(crcUpdate(0, hb[:]), body[:len(body)-4])
	binary.LittleEndian.PutUint32(body[len(body)-4:], sum)
	if err := VerifyChecksum(h, body); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	// The header is covered too.
	h2 := h
	h2.RequestID++
	if err := VerifyChecksum(h2, body); err == nil {
		t.Fatal("checksum did not cover the header")
	}
	body[6] ^= 1
	if err := VerifyChecksum(h, body); err == nil {
		t.Fatal("corrupted body accepted")
	}
	// No flag, no check.
	if err := VerifyChecksum(h, msgWith(0, append([]byte{0}, emptyDoc...))); err != nil {
		t.Fatal(err)
	}
	// Flag but no room for a checksum.
	if err := VerifyChecksum(h, msgWith(FlagChecksumPresent)); err == nil {
		t.Fatal("flag with no checksum bytes accepted")
	}
}

func zlibOf(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func compressedBody(opcode int32, declared uint32, id Compressor, payload []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(opcode))
	b = binary.LittleEndian.AppendUint32(b, declared)
	b = append(b, byte(id))
	return append(b, payload...)
}

// Decompression bombs: the output buffer follows what the decompressor
// really produces, never the (attacker-chosen) declared size.
func TestDecompressBombs(t *testing.T) {
	zstdEnc, _ := zstd.NewWriter(nil)
	const limit = 48 << 20
	zeros := func(n int) []byte { return make([]byte, n) }
	cases := []struct {
		name string
		body []byte
	}{
		{"zlib: declared 40MiB, delivers 10 bytes", compressedBody(2013, 40<<20, CompZlib, zlibOf(zeros(10)))},
		{"zstd: declared 40MiB, delivers 10 bytes", compressedBody(2013, 40<<20, CompZstd, zstdEnc.EncodeAll(zeros(10), nil))},
		{"snappy: declared 40MiB, delivers 10 bytes", compressedBody(2013, 40<<20, CompSnappy, snappy.Encode(nil, zeros(10)))},
		{"zlib: 8MiB delivered, 1KiB declared", compressedBody(2013, 1024, CompZlib, zlibOf(zeros(8<<20)))},
		{"zstd: 8MiB delivered, 1KiB declared", compressedBody(2013, 1024, CompZstd, zstdEnc.EncodeAll(zeros(8<<20), nil))},
		{"snappy: header disagrees with envelope", compressedBody(2013, 5, CompSnappy, snappy.Encode(nil, zeros(100)))},
		{"declared over the limit", compressedBody(2013, limit, CompZlib, zlibOf(zeros(10)))},
		{"declared negative", compressedBody(2013, 0xffffffff, CompZlib, zlibOf(zeros(10)))},
		{"unknown compressor", compressedBody(2013, 10, 77, zeros(10))},
		{"nested compression", compressedBody(OpCompressed, 10, CompNone, zeros(10))},
		{"noop length lie", compressedBody(2013, 11, CompNone, zeros(10))},
		{"truncated zlib stream", compressedBody(2013, 1<<20, CompZlib, zlibOf(zeros(1 << 20))[:20])},
		{"truncated zstd stream", compressedBody(2013, 1<<20, CompZstd, zstdEnc.EncodeAll(zeros(1<<20), nil)[:12])},
		{"empty", nil},
		{"header only", compressedBody(2013, 0, CompZlib, nil)},
	}
	for _, tc := range cases {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, _, data, err := Decompress(tc.body, limit)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("%s: accepted (%d bytes)", tc.name, len(data))
		}
		// An honest 8 MiB stream legitimately costs a few buffer doublings;
		// nothing here may approach the 40 MiB the headers claim.
		if grown := after.TotalAlloc - before.TotalAlloc; grown > 40<<20 {
			t.Errorf("%s: allocated %d MiB", tc.name, grown>>20)
		}
	}
	// A claimed size that is true still works, for every compressor.
	payload := bytes.Repeat([]byte("abc"), 100000)
	for _, id := range []Compressor{CompNone, CompSnappy, CompZlib, CompZstd} {
		cb, err := Compress(id, OpMsg, payload)
		if err != nil {
			t.Fatal(err)
		}
		op, _, got, err := Decompress(cb, limit)
		if err != nil || op != OpMsg || !bytes.Equal(got, payload) {
			t.Errorf("%v round trip: %v", id, err)
		}
	}
}

func TestDecompressSnappyRatioCheck(t *testing.T) {
	// A snappy stream whose header claims 30 MiB but which is 8 bytes long
	// cannot be genuine: refused without allocating.
	src := binary.AppendUvarint(nil, 30<<20)
	src = append(src, 0, 0, 0, 0, 0, 0)
	_, _, _, err := Decompress(compressedBody(2013, 30<<20, CompSnappy, src), 48<<20)
	if !errors.Is(err, ErrBadCompressed) {
		t.Fatalf("got %v", err)
	}
}
