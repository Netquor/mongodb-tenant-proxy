package wire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
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
	zstdDec = mustZstdDecoder()

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

func mustZstdDecoder() *zstd.Decoder {
	d, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
	if err != nil {
		panic(err)
	}
	return d
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
	binary.LittleEndian.PutUint32(out[0:], uint32(opcode))
	binary.LittleEndian.PutUint32(out[4:], uint32(len(data)))
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

// Decompress unwraps an OP_COMPRESSED body. maxSize bounds the declared
// uncompressed size (0 = unlimited); the declared size is verified, so a
// hostile peer cannot make the proxy allocate more than maxSize.
func Decompress(body []byte, maxSize int) (opcode int32, id Compressor, data []byte, err error) {
	if len(body) < compressedHeader {
		return 0, 0, nil, ErrBadCompressed
	}
	opcode = int32(binary.LittleEndian.Uint32(body[0:]))
	size := int(int32(binary.LittleEndian.Uint32(body[4:])))
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
		data = src
	case CompSnappy:
		n, derr := snappy.DecodedLen(src)
		if derr != nil || n != size {
			return 0, id, nil, ErrBadCompressed
		}
		data, err = snappy.Decode(make([]byte, size), src)
	case CompZstd:
		data, err = zstdDec.DecodeAll(src, make([]byte, 0, size))
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
		data = make([]byte, size)
		_, err = io.ReadFull(zr, data)
		if err == nil {
			// Anything beyond the declared size is a lie about the size.
			var one [1]byte
			if n, _ := zr.Read(one[:]); n != 0 {
				err = ErrBadCompressed
			}
		}
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
