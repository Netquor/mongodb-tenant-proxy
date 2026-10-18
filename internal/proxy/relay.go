package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// relayBufSize is the client-side write buffer of the streaming relay and so,
// with the upstream reader's 64 KiB buffer, the working set of a relayed reply
// of any size.
const relayBufSize = 32 * 1024

// replyMeta is what the relay learns about a reply while passing it through.
type replyMeta struct {
	ok       bool
	cursorID int64
	ns       string
	hasCur   bool
}

// walker copies an OP_MSG reply from upstream to the client while following
// just enough of its BSON structure to read the top-level "ok" and the cursor
// id and namespace. Everything else (the document batches) is copied through
// without being decoded or retained.
type walker struct {
	r    *bufio.Reader
	w    *bufio.Writer
	left int64 // bytes of the frame not yet consumed
	buf  [64]byte
}

var errMalformedReply = errors.New("malformed upstream reply")

func (w *walker) take(n int64) error {
	if n < 0 || n > w.left {
		return errMalformedReply
	}
	w.left -= n
	return nil
}

// read consumes n (<= len(buf)) bytes, forwarding them.
func (w *walker) read(n int) ([]byte, error) {
	if err := w.take(int64(n)); err != nil {
		return nil, err
	}
	b := w.buf[:n]
	if _, err := io.ReadFull(w.r, b); err != nil {
		return nil, err
	}
	_, err := w.w.Write(b)
	return b, err
}

func (w *walker) skip(n int64) error {
	if err := w.take(n); err != nil {
		return err
	}
	_, err := io.CopyN(w.w, w.r, n)
	return err
}

func (w *walker) u32() (int64, error) {
	b, err := w.read(4)
	if err != nil {
		return 0, err
	}
	return int64(int32(binary.LittleEndian.Uint32(b))), nil
}

// cstring forwards a NUL-terminated string and returns it (keys are short).
func (w *walker) cstring() (string, error) {
	b, err := w.r.ReadSlice(0)
	if err != nil {
		return "", err
	}
	if err := w.take(int64(len(b))); err != nil {
		return "", err
	}
	if _, err := w.w.Write(b); err != nil {
		return "", err
	}
	return string(b[:len(b)-1]), nil
}

// skipValue forwards one BSON value of the given type.
func (w *walker) skipValue(t byte) error {
	switch t {
	case 0x01, 0x09, 0x11, 0x12:
		return w.skip(8)
	case 0x02, 0x0D, 0x0E: // string, javascript, symbol
		n, err := w.u32()
		if err != nil {
			return err
		}
		return w.skip(n)
	case 0x03, 0x04, 0x0F: // document, array, code with scope
		n, err := w.u32()
		if err != nil {
			return err
		}
		return w.skip(n - 4)
	case 0x05:
		n, err := w.u32()
		if err != nil {
			return err
		}
		return w.skip(n + 1)
	case 0x06, 0x0A, 0xFF, 0x7F:
		return nil
	case 0x07:
		return w.skip(12)
	case 0x08:
		return w.skip(1)
	case 0x0B:
		for i := 0; i < 2; i++ {
			if _, err := w.cstring(); err != nil {
				return err
			}
		}
		return nil
	case 0x0C:
		n, err := w.u32()
		if err != nil {
			return err
		}
		return w.skip(n + 12)
	case 0x10:
		return w.skip(4)
	case 0x13:
		return w.skip(16)
	}
	return fmt.Errorf("%w: unknown BSON type 0x%x", errMalformedReply, t)
}

// document walks one embedded document, calling on for each element; on
// returns true when it consumed the value itself.
func (w *walker) document(on func(key string, t byte) (bool, error)) error {
	size, err := w.u32()
	if err != nil {
		return err
	}
	if size < 5 || size-4 > w.left {
		return errMalformedReply
	}
	end := w.left - (size - 4) // frame bytes remaining once this document is done
	for {
		tb, err := w.read(1)
		if err != nil {
			return err
		}
		t := tb[0]
		if t == 0 {
			if w.left != end {
				return fmt.Errorf("%w: document length mismatch", errMalformedReply)
			}
			return nil
		}
		if w.left < end {
			return errMalformedReply
		}
		key, err := w.cstring()
		if err != nil {
			return err
		}
		done, err := on(key, t)
		if err != nil {
			return err
		}
		if !done {
			if err := w.skipValue(t); err != nil {
				return err
			}
		}
	}
}

func (w *walker) number(t byte) (float64, bool, error) {
	var n int
	switch t {
	case 0x01, 0x12:
		n = 8
	case 0x10:
		n = 4
	default:
		return 0, false, nil
	}
	b, err := w.read(n)
	if err != nil {
		return 0, true, err
	}
	switch t {
	case 0x01:
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), true, nil
	case 0x10:
		return float64(int32(binary.LittleEndian.Uint32(b))), true, nil
	}
	return float64(int64(binary.LittleEndian.Uint64(b))), true, nil
}

// relayStream forwards the rest of a reply whose 16-byte header has been read
// but not yet sent. It returns what it saw of the reply.
func relayStream(up *bufio.Reader, out *bufio.Writer, hdr wire.Header, responseTo int32) (replyMeta, error) {
	var meta replyMeta
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:], uint32(hdr.Length))
	binary.LittleEndian.PutUint32(h[4:], uint32(hdr.RequestID))
	binary.LittleEndian.PutUint32(h[8:], uint32(responseTo))
	binary.LittleEndian.PutUint32(h[12:], uint32(hdr.OpCode))
	if _, err := out.Write(h[:]); err != nil {
		return meta, err
	}
	w := &walker{r: up, w: out, left: int64(hdr.Length) - 16}
	flags, err := w.read(4)
	if err != nil {
		return meta, err
	}
	trailer := int64(0)
	if binary.LittleEndian.Uint32(flags)&wire.FlagChecksumPresent != 0 {
		trailer = 4
	}
	kind, err := w.read(1)
	if err != nil {
		return meta, err
	}
	if kind[0] == 0 {
		w.left -= trailer
		err = w.document(func(key string, t byte) (bool, error) {
			switch {
			case key == "ok":
				v, isNum, err := w.number(t)
				meta.ok = isNum && v == 1
				return isNum, err
			case key == "cursor" && t == 0x03:
				meta.hasCur = true
				return true, w.document(func(k string, t byte) (bool, error) {
					switch {
					case k == "id" && t == 0x12:
						b, err := w.read(8)
						if err == nil {
							meta.cursorID = int64(binary.LittleEndian.Uint64(b))
						}
						return true, err
					case k == "ns" && t == 0x02:
						n, err := w.u32()
						if err != nil || n < 1 || n > 4096 {
							return true, errors.Join(err, errMalformedReply)
						}
						s := make([]byte, n)
						if err := w.take(n); err != nil {
							return true, err
						}
						if _, err := io.ReadFull(up, s); err != nil {
							return true, err
						}
						if _, err := out.Write(s); err != nil {
							return true, err
						}
						meta.ns = string(s[:n-1])
						return true, nil
					}
					return false, nil
				})
			}
			return false, nil
		})
		if err != nil {
			return meta, err
		}
		w.left += trailer
	}
	if err := w.skip(w.left); err != nil {
		return meta, err
	}
	return meta, out.Flush()
}
