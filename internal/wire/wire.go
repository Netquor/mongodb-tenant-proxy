// Package wire implements the subset of the MongoDB wire protocol the proxy
// needs: message framing, OP_MSG, and the legacy OP_QUERY/OP_REPLY pair that
// drivers still use for the very first handshake.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Opcodes.
const (
	OpReply      int32 = 1
	OpQuery      int32 = 2004
	OpCompressed int32 = 2012
	OpMsg        int32 = 2013
)

// OP_MSG flag bits.
const (
	FlagChecksumPresent uint32 = 1 << 0
	FlagMoreToCome      uint32 = 1 << 1
	FlagExhaustAllowed  uint32 = 1 << 16
)

const headerSize = 16

// Header is the standard 16-byte message header.
type Header struct {
	Length     int32
	RequestID  int32
	ResponseTo int32
	OpCode     int32
}

// ErrTooLarge is returned when a frame exceeds the configured maximum.
var ErrTooLarge = errors.New("wire: message exceeds maximum size")

// ReadFrame reads one complete message and returns its header and body (the
// bytes after the header).
func ReadFrame(r io.Reader, maxSize int) (Header, []byte, error) {
	var hb [headerSize]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return Header{}, nil, err
	}
	h := Header{
		Length:     int32(binary.LittleEndian.Uint32(hb[0:])),
		RequestID:  int32(binary.LittleEndian.Uint32(hb[4:])),
		ResponseTo: int32(binary.LittleEndian.Uint32(hb[8:])),
		OpCode:     int32(binary.LittleEndian.Uint32(hb[12:])),
	}
	if h.Length < headerSize {
		return h, nil, fmt.Errorf("wire: invalid message length %d", h.Length)
	}
	if maxSize > 0 && int(h.Length) > maxSize {
		return h, nil, ErrTooLarge
	}
	body, err := readBody(r, int(h.Length)-headerSize)
	if err != nil {
		return h, nil, err
	}
	return h, body, nil
}

// readChunk is how much buffer readBody commits before the peer has proved it
// is really sending data.
const readChunk = 64 * 1024

// readBody reads exactly n bytes, growing the buffer as data arrives. The
// declared length is attacker controlled: allocating it up front would let a
// connection that sends only a header pin maxSize bytes (48 MB by default).
func readBody(r io.Reader, n int) ([]byte, error) {
	if n <= readChunk {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	b := make([]byte, 0, readChunk)
	for len(b) < n {
		if len(b) == cap(b) {
			nb := make([]byte, len(b), min(2*cap(b), n))
			copy(nb, b)
			b = nb
		}
		m, err := r.Read(b[len(b):min(cap(b), n)])
		b = b[:len(b)+m]
		if err != nil {
			if err == io.EOF && len(b) < n {
				err = io.ErrUnexpectedEOF
			}
			if len(b) < n {
				return nil, err
			}
		}
	}
	return b, nil
}

// WriteFrame writes a message with the given header fields and body.
func WriteFrame(w io.Writer, requestID, responseTo, opCode int32, body []byte) error {
	buf := make([]byte, headerSize, headerSize+len(body))
	binary.LittleEndian.PutUint32(buf[0:], uint32(headerSize+len(body)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(requestID))
	binary.LittleEndian.PutUint32(buf[8:], uint32(responseTo))
	binary.LittleEndian.PutUint32(buf[12:], uint32(opCode))
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// LookupPath returns the value at a nested path, or a zero Value when any step
// is missing or is not a (well-formed) document. bsoncore.Document.Lookup with
// several keys panics when an intermediate document value is malformed, so
// lookups on data that has not been deeply validated go through this instead.
func LookupPath(d bsoncore.Document, path ...string) bsoncore.Value {
	for i, k := range path {
		v := d.Lookup(k)
		if i == len(path)-1 {
			return v
		}
		sub, ok := v.DocumentOK()
		if !ok {
			return bsoncore.Value{}
		}
		d = sub
	}
	return bsoncore.Value{}
}

// Limits on what one OP_MSG may carry. Every document costs a slice header
// whatever its size and the smallest one is 5 bytes, so without a cap a 48 MB
// message of empty documents makes the parser allocate hundreds of MB.
// 100000 is MongoDB's own maxWriteBatchSize.
const (
	MaxSeqDocs = 100000
	MaxSeqs    = 16
)

// knownFlagBits are the OP_MSG flag bits this implementation understands.
// Unknown bits 0-15 are "required": the receiver must reject the message.
const knownRequiredBits = FlagChecksumPresent | FlagMoreToCome

// Seq is an OP_MSG kind-1 document sequence.
type Seq struct {
	ID   string
	Docs []bsoncore.Document
}

// Msg is a decoded OP_MSG.
type Msg struct {
	Flags uint32
	Body  bsoncore.Document
	Seqs  []Seq
}

// ParseMsg decodes an OP_MSG body (the bytes after the header).
func ParseMsg(b []byte) (*Msg, error) {
	if len(b) < 5 {
		return nil, errors.New("wire: short OP_MSG")
	}
	m := &Msg{Flags: binary.LittleEndian.Uint32(b)}
	if m.Flags&0xFFFF&^knownRequiredBits != 0 {
		return nil, fmt.Errorf("wire: unknown required OP_MSG flag bits %#x", m.Flags&0xFFFF&^knownRequiredBits)
	}
	b = b[4:]
	if m.Flags&FlagChecksumPresent != 0 {
		if len(b) < 4 {
			return nil, errors.New("wire: short OP_MSG checksum")
		}
		b = b[:len(b)-4]
	}
	haveBody := false
	totalDocs := 0
	for len(b) > 0 {
		kind := b[0]
		b = b[1:]
		switch kind {
		case 0:
			doc, rest, ok := readDocument(b)
			if !ok {
				return nil, errors.New("wire: malformed OP_MSG body document")
			}
			if haveBody {
				return nil, errors.New("wire: multiple kind-0 sections")
			}
			haveBody = true
			m.Body = doc
			b = rest
		case 1:
			if len(b) < 4 {
				return nil, errors.New("wire: short kind-1 section")
			}
			size := int(int32(binary.LittleEndian.Uint32(b)))
			if size < 5 || size > len(b) {
				return nil, errors.New("wire: invalid kind-1 section size")
			}
			sec := b[4:size]
			b = b[size:]
			id, rest, ok := readCString(sec)
			if !ok {
				return nil, errors.New("wire: malformed kind-1 identifier")
			}
			if len(m.Seqs) >= MaxSeqs {
				return nil, errors.New("wire: too many kind-1 sections")
			}
			s := Seq{ID: id}
			for len(rest) > 0 {
				if totalDocs++; totalDocs > MaxSeqDocs {
					return nil, errors.New("wire: too many documents in OP_MSG")
				}
				doc, r2, ok := readDocument(rest)
				if !ok {
					return nil, errors.New("wire: malformed kind-1 document")
				}
				s.Docs = append(s.Docs, doc)
				rest = r2
			}
			m.Seqs = append(m.Seqs, s)
		default:
			return nil, fmt.Errorf("wire: unknown OP_MSG section kind %d", kind)
		}
	}
	if !haveBody {
		return nil, errors.New("wire: OP_MSG without body section")
	}
	return m, nil
}

// ErrBadChecksum is returned when an OP_MSG checksum does not match.
var ErrBadChecksum = errors.New("wire: OP_MSG checksum mismatch")

var crc32c = crc32.MakeTable(crc32.Castagnoli)

func crcUpdate(sum uint32, b []byte) uint32 { return crc32.Update(sum, crc32c, b) }

// VerifyChecksum checks the CRC-32C trailer of an uncompressed OP_MSG when its
// checksumPresent flag is set (it covers the header and all but the last four
// bytes). Messages without the flag pass.
func VerifyChecksum(h Header, body []byte) error {
	if len(body) < 4 || binary.LittleEndian.Uint32(body)&FlagChecksumPresent == 0 {
		return nil
	}
	if len(body) < 8 {
		return ErrBadChecksum
	}
	var hb [headerSize]byte
	binary.LittleEndian.PutUint32(hb[0:], uint32(h.Length))
	binary.LittleEndian.PutUint32(hb[4:], uint32(h.RequestID))
	binary.LittleEndian.PutUint32(hb[8:], uint32(h.ResponseTo))
	binary.LittleEndian.PutUint32(hb[12:], uint32(h.OpCode))
	sum := crc32.Update(crc32.Update(0, crc32c, hb[:]), crc32c, body[:len(body)-4])
	if sum != binary.LittleEndian.Uint32(body[len(body)-4:]) {
		return ErrBadChecksum
	}
	return nil
}

// Encode serialises the message body. The checksum flag is always cleared.
func (m *Msg) Encode() []byte {
	n := 4 + 1 + len(m.Body)
	for _, s := range m.Seqs {
		n += 1 + 4 + len(s.ID) + 1
		for _, d := range s.Docs {
			n += len(d)
		}
	}
	out := make([]byte, 4, n)
	binary.LittleEndian.PutUint32(out, m.Flags&^FlagChecksumPresent)
	out = append(out, 0)
	out = append(out, m.Body...)
	for _, s := range m.Seqs {
		size := 4 + len(s.ID) + 1
		for _, d := range s.Docs {
			size += len(d)
		}
		out = append(out, 1)
		out = binary.LittleEndian.AppendUint32(out, uint32(size))
		out = append(out, s.ID...)
		out = append(out, 0)
		for _, d := range s.Docs {
			out = append(out, d...)
		}
	}
	return out
}

// Seq returns the document sequence with the given identifier.
func (m *Msg) Seq(id string) *Seq {
	for i := range m.Seqs {
		if m.Seqs[i].ID == id {
			return &m.Seqs[i]
		}
	}
	return nil
}

// Query is a decoded legacy OP_QUERY.
type Query struct {
	Flags      int32
	Collection string
	Skip       int32
	Return     int32
	Doc        bsoncore.Document
}

// ParseQuery decodes an OP_QUERY body.
func ParseQuery(b []byte) (*Query, error) {
	if len(b) < 4 {
		return nil, errors.New("wire: short OP_QUERY")
	}
	q := &Query{Flags: int32(binary.LittleEndian.Uint32(b))}
	name, rest, ok := readCString(b[4:])
	if !ok || len(rest) < 8 {
		return nil, errors.New("wire: malformed OP_QUERY")
	}
	q.Collection = name
	q.Skip = int32(binary.LittleEndian.Uint32(rest))
	q.Return = int32(binary.LittleEndian.Uint32(rest[4:]))
	doc, _, ok := readDocument(rest[8:])
	if !ok {
		return nil, errors.New("wire: malformed OP_QUERY document")
	}
	q.Doc = doc
	return q, nil
}

// EncodeReply builds an OP_REPLY body carrying a single document.
func EncodeReply(doc bsoncore.Document) []byte {
	out := make([]byte, 20, 20+len(doc))
	binary.LittleEndian.PutUint32(out[0:], 8) // AwaitCapable
	binary.LittleEndian.PutUint32(out[16:], 1)
	return append(out, doc...)
}

// readDocument is bsoncore.ReadDocument plus the framing checks it omits: a
// document is at least 5 bytes (it accepts a declared length of 4) and ends in
// a NUL byte. Everything downstream may then slice off the terminator.
func readDocument(b []byte) (bsoncore.Document, []byte, bool) {
	d, rest, ok := bsoncore.ReadDocument(b)
	if !ok || len(d) < 5 || d[len(d)-1] != 0 {
		return nil, b, false
	}
	return d, rest, true
}

func readCString(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}
