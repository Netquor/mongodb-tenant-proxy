package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCompressRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("mongodb tenant proxy "), 500)
	for _, id := range []Compressor{CompNone, CompSnappy, CompZlib, CompZstd} {
		body, err := Compress(id, OpMsg, data)
		if err != nil {
			t.Fatalf("%v: %v", id, err)
		}
		if got, ok := CompressorID(body); !ok || got != id {
			t.Fatalf("%v: CompressorID = %v", id, got)
		}
		if id != CompNone && len(body) >= len(data) {
			t.Errorf("%v: %d bytes did not shrink (%d)", id, len(data), len(body))
		}
		op, gid, out, err := Decompress(body, 1<<20)
		if err != nil || op != OpMsg || gid != id || !bytes.Equal(out, data) {
			t.Fatalf("%v: round trip failed: op=%d err=%v", id, op, err)
		}
		// Pooled readers/writers must stay correct on reuse.
		if _, _, out, err = Decompress(body, 1<<20); err != nil || !bytes.Equal(out, data) {
			t.Fatalf("%v: second round trip failed: %v", id, err)
		}
	}
}

func TestDecompressRejectsBadInput(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 4096)
	for _, id := range []Compressor{CompSnappy, CompZlib, CompZstd} {
		good, _ := Compress(id, OpMsg, data)

		big := append([]byte(nil), good...)
		binary.LittleEndian.PutUint32(big[4:], 1<<30)
		if _, _, _, err := Decompress(big, 1<<20); err != ErrTooLarge {
			t.Errorf("%v: oversized declared size: %v", id, err)
		}
		lie := append([]byte(nil), good...)
		binary.LittleEndian.PutUint32(lie[4:], 100) // smaller than real
		if _, _, _, err := Decompress(lie, 1<<20); err == nil {
			t.Errorf("%v: understated size accepted", id)
		}
		lie2 := append([]byte(nil), good...)
		binary.LittleEndian.PutUint32(lie2[4:], 9000) // larger than real
		if _, _, _, err := Decompress(lie2, 1<<20); err == nil {
			t.Errorf("%v: overstated size accepted", id)
		}
		if _, _, _, err := Decompress(good[:len(good)/2], 1<<20); err == nil {
			t.Errorf("%v: truncated body accepted", id)
		}
	}
	if _, _, _, err := Decompress([]byte{1, 2}, 0); err == nil {
		t.Error("short body accepted")
	}
	nested, _ := Compress(CompNone, OpCompressed, data)
	if _, _, _, err := Decompress(nested, 0); err == nil {
		t.Error("nested OP_COMPRESSED accepted")
	}
	unk := append([]byte(nil), nested...)
	unk[8], unk[0] = 9, byte(OpMsg&0xff)
	binary.LittleEndian.PutUint32(unk[0:], uint32(OpMsg))
	if _, _, _, err := Decompress(unk, 0); err == nil {
		t.Error("unknown compressor accepted")
	}
}

func TestCompressible(t *testing.T) {
	for _, c := range []string{"hello", "isMaster", "saslStart", "authenticate", "createUser"} {
		if Compressible(c) {
			t.Errorf("%s must not be compressible", c)
		}
	}
	if !Compressible("find") {
		t.Error("find must be compressible")
	}
}

func FuzzDecompress(f *testing.F) {
	for _, id := range []Compressor{CompSnappy, CompZlib, CompZstd} {
		b, _ := Compress(id, OpMsg, []byte("seed seed seed seed"))
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { Decompress(b, 1<<20) })
}

func BenchmarkCompress(b *testing.B) {
	data := bytes.Repeat([]byte(`{"_id":1,"tenantId":"acme","name":"some document body"}`), 2000)
	for _, id := range []Compressor{CompSnappy, CompZlib, CompZstd} {
		body, _ := Compress(id, OpMsg, data)
		b.Run(id.String()+"/compress", func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				Compress(id, OpMsg, data)
			}
		})
		b.Run(id.String()+"/decompress", func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				Decompress(body, 0)
			}
		})
	}
}
