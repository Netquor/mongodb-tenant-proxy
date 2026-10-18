// Package wire implements the subset of the MongoDB wire protocol the proxy
// needs: message framing, OP_MSG, and the legacy OP_QUERY/OP_REPLY pair that
// drivers still use for the very first handshake.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	body := make([]byte, int(h.Length)-headerSize)
	if _, err := io.ReadFull(r, body); err != nil {
		return h, nil, err
	}
	return h, body, nil
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
	b = b[4:]
	if m.Flags&FlagChecksumPresent != 0 {
		if len(b) < 4 {
			return nil, errors.New("wire: short OP_MSG checksum")
		}
		b = b[:len(b)-4]
	}
	haveBody := false
	for len(b) > 0 {
		kind := b[0]
		b = b[1:]
		switch kind {
		case 0:
			doc, rest, ok := bsoncore.ReadDocument(b)
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
			s := Seq{ID: id}
			for len(rest) > 0 {
				doc, r2, ok := bsoncore.ReadDocument(rest)
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
	doc, _, ok := bsoncore.ReadDocument(rest[8:])
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

func readCString(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}
