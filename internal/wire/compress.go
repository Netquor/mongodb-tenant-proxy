package wire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/netquor/mongodb-tenant-proxy/internal/safeconv"
	"io"
	"strings"
	"sync"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
)

// Compressor identifies an OP_COMPRESSED algorithm.
type Compressor uint8

// Compressor ids as defined by the MongoDB wire protocol.
const (
	CompNone   Compressor = 0
	CompSnappy Compressor = 1
	CompZlib   Compressor = 2
	CompZstd   Compressor = 3
)

// String returns the name used in hello's compression list.
func (c Compressor) String() string {
	switch c {
	case CompNone:
		return "noop"
	case CompSnappy:
		return "snappy"
	case CompZlib:
		return "zlib"
	case CompZstd:
		return "zstd"
	}
	return fmt.Sprintf("compressor(%d)", uint8(c))
}

// CompressorByName maps a hello compression name to its id.
func CompressorByName(name string) (Compressor, bool) {
	switch strings.ToLower(name) {
	case "snappy":
		return CompSnappy, true
	case "zlib":
		return CompZlib, true
	case "zstd":
		return CompZstd, true
	}
	return CompNone, false
}

// compressedHeader is originalOpcode(4) + uncompressedSize(4) + compressorId(1).
const compressedHeader = 9

var (
	zstdEnc = mustZstdEncoder()

	zlibWriters sync.Pool
	zlibReaders sync.Pool
)

func mustZstdEncoder() *zstd.Encoder {
	e, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		panic(err)
	}
	return e
}

// CompressorID returns the compressor used by an OP_COMPRESSED body without
// decompressing it.
func CompressorID(body []byte) (Compressor, bool) {
	if len(body) < compressedHeader {
		return CompNone, false
	}
	return Compressor(body[8]), true
}

// Compress wraps an uncompressed message body (the bytes after its header) as
// an OP_COMPRESSED body.
func Compress(id Compressor, opcode int32, data []byte) ([]byte, error) {
	out := make([]byte, compressedHeader, compressedHeader+len(data)/2+32)
	binary.LittleEndian.PutUint32(out[0:], safeconv.U32(opcode))
	binary.LittleEndian.PutUint32(out[4:], safeconv.Len32(len(data)))
	out[8] = byte(id)
	switch id {
	case CompNone:
		return append(out, data...), nil
	case CompSnappy:
		return append(out, snappy.Encode(nil, data)...), nil
	case CompZstd:
		return zstdEnc.EncodeAll(data, out), nil
	case CompZlib:
		buf := bytes.NewBuffer(out)
		zw, _ := zlibWriters.Get().(*zlib.Writer)
		if zw == nil {
			zw = zlib.NewWriter(buf)
		} else {
			zw.Reset(buf)
		}
		_, err := zw.Write(data)
		if cerr := zw.Close(); err == nil {
			err = cerr
		}
		zlibWriters.Put(zw)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("wire: unsupported compressor %d", id)
}

// ErrBadCompressed is returned for malformed OP_COMPRESSED bodies.
var ErrBadCompressed = errors.New("wire: malformed OP_COMPRESSED")

// snappyMaxRatio bounds how far snappy can expand: a 3-byte copy element
// yields at most 64 bytes. A header claiming more than this per compressed
// byte is lying and is refused before any buffer is allocated.
const snappyMaxRatio = 22

// zstdMaxWindow bounds the history buffer a zstd frame may demand.
const zstdMaxWindow = 16 << 20

var zstdReaders sync.Pool

// Decompress unwraps an OP_COMPRESSED body. maxSize bounds the declared
// uncompressed size (0 = unlimited). The declared size is only a claim: the
// output buffer grows with the bytes the decompressor really produces and the
// stream must end exactly at the claimed size, so neither a tiny body that
// declares a huge size nor a decompression bomb makes the proxy allocate more
// than the (verified) declared size, which is itself capped by maxSize.
func Decompress(body []byte, maxSize int) (opcode int32, id Compressor, data []byte, err error) {
	if len(body) < compressedHeader {
		return 0, 0, nil, ErrBadCompressed
	}
	opcode = safeconv.I32(binary.LittleEndian.Uint32(body[0:]))
	size := int(safeconv.I32(binary.LittleEndian.Uint32(body[4:])))
	id = Compressor(body[8])
	src := body[compressedHeader:]
	if opcode == OpCompressed {
		return 0, id, nil, errors.New("wire: nested OP_COMPRESSED")
	}
	if size < 0 || (maxSize > 0 && size+headerSize > maxSize) {
		return 0, id, nil, ErrTooLarge
	}
	switch id {
	case CompNone:
		if len(src) != size {
			return 0, id, nil, ErrBadCompressed
		}
		data = src
	case CompSnappy:
		n, derr := snappy.DecodedLen(src)
		if derr != nil || n != size || size > snappyMaxRatio*len(src)+64 {
			return 0, id, nil, ErrBadCompressed
		}
		data, err = snappy.Decode(make([]byte, size), src)
	case CompZstd:
		zr, _ := zstdReaders.Get().(*zstd.Decoder)
		if zr == nil {
			zr, err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(zstdMaxWindow))
			if err != nil {
				return 0, id, nil, err
			}
		}
		if err = zr.Reset(bytes.NewReader(src)); err == nil {
			data, err = readExact(zr, size)
		}
		zr.Reset(nil)
		zstdReaders.Put(zr)
	case CompZlib:
		zr, _ := zlibReaders.Get().(io.ReadCloser)
		if zr == nil {
			zr, err = zlib.NewReader(bytes.NewReader(src))
		} else {
			err = zr.(zlib.Resetter).Reset(bytes.NewReader(src), nil)
		}
		if err != nil {
			return 0, id, nil, err
		}
		data, err = readExact(zr, size)
		zlibReaders.Put(zr)
	default:
		return 0, id, nil, fmt.Errorf("wire: unsupported compressor %d", id)
	}
	if err != nil {
		return 0, id, nil, err
	}
	if len(data) != size {
		return 0, id, nil, ErrBadCompressed
	}
	return opcode, id, data, nil
}

// readExact reads a stream that must hold exactly n bytes.
func readExact(r io.Reader, n int) ([]byte, error) {
	data, err := readBody(r, n)
	if err != nil {
		return nil, ErrBadCompressed
	}
	// Anything beyond the declared size is a lie about the size.
	var one [1]byte
	if m, _ := r.Read(one[:]); m != 0 {
		return nil, ErrBadCompressed
	}
	return data, nil
}

// Compressible reports whether MongoDB permits compressing a command. The
// handshake and authentication commands must never be compressed.
func Compressible(cmd string) bool {
	switch cmd {
	case "hello", "ismaster", "isMaster", "saslStart", "saslContinue", "getnonce",
		"authenticate", "createUser", "updateUser", "copydbSaslStart",
		"copydbgetnonce", "copydb":
		return false
	}
	return true
}
