package wire

import (
	"bytes"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

func msgSeeds() [][]byte {
	body, _ := bson.Marshal(bson.D{{Key: "find", Value: "c"}, {Key: "$db", Value: "app"}})
	doc, _ := bson.Marshal(bson.D{{Key: "a", Value: 1}})
	m := &Msg{Body: body, Seqs: []Seq{{ID: "documents", Docs: []bsoncore.Document{doc, doc}}, {ID: "x"}}}
	withSum := append(append([]byte(nil), m.Encode()...), 1, 2, 3, 4)
	withSum[0] |= byte(FlagChecksumPresent)
	return [][]byte{m.Encode(), (&Msg{Body: body}).Encode(), withSum, {}, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 1, 5, 0, 0, 0, 0}}
}

// FuzzParseMsg: never panics; anything it accepts survives an Encode/Parse
// round trip unchanged (so the proxy forwards exactly what it inspected).
func FuzzParseMsg(f *testing.F) {
	for _, s := range msgSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMsg(b)
		if err != nil {
			return
		}
		if len(m.Body) < 5 {
			t.Fatalf("accepted a body shorter than a document: %x", m.Body)
		}
		for _, s := range m.Seqs {
			for _, d := range s.Docs {
				if len(d) < 5 {
					t.Fatalf("accepted a sequence document shorter than a document")
				}
			}
		}
		enc := m.Encode()
		m2, err := ParseMsg(enc)
		if err != nil {
			t.Fatalf("re-parse of encoded message failed: %v", err)
		}
		if !bytes.Equal(m.Body, m2.Body) || len(m.Seqs) != len(m2.Seqs) || m2.Flags != m.Flags&^FlagChecksumPresent {
			t.Fatalf("round trip changed the message")
		}
		for i := range m.Seqs {
			if m.Seqs[i].ID != m2.Seqs[i].ID || len(m.Seqs[i].Docs) != len(m2.Seqs[i].Docs) {
				t.Fatalf("round trip changed sequence %d", i)
			}
			for j := range m.Seqs[i].Docs {
				if !bytes.Equal(m.Seqs[i].Docs[j], m2.Seqs[i].Docs[j]) {
					t.Fatalf("round trip changed sequence document")
				}
			}
		}
		_ = m.Seq("documents")
	})
}

// FuzzParseQuery: never panics; the returned document lies inside the input.
func FuzzParseQuery(f *testing.F) {
	doc, _ := bson.Marshal(bson.D{{Key: "isMaster", Value: 1}})
	q := append([]byte{0, 0, 0, 0}, []byte("admin.$cmd\x00")...)
	q = append(q, 0, 0, 0, 0, 1, 0, 0, 0)
	q = append(q, doc...)
	f.Add(q)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseQuery(b)
		if err != nil {
			return
		}
		if len(got.Doc) < 5 || !bytes.Contains(b, got.Doc) {
			t.Fatalf("returned document is not part of the input")
		}
		_ = EncodeReply(got.Doc)
	})
}

// FuzzReadFrame: never panics and never allocates more than the limit.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0})
	f.Add([]byte{0, 0, 0, 0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0xdd, 0x07, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, body, err := ReadFrame(bytes.NewReader(b), 1<<20)
		if err == nil && (int(h.Length) < headerSize || len(body) != int(h.Length)-headerSize) {
			t.Fatalf("inconsistent frame")
		}
	})
}

// ReadDocument alone accepts a "document" whose declared length is 4.
func TestParseRejectsUndersizedDocuments(t *testing.T) {
	tiny := []byte{4, 0, 0, 0}
	msg := append([]byte{0, 0, 0, 0, 0}, tiny...)
	if _, err := ParseMsg(msg); err == nil {
		t.Error("ParseMsg accepted a 4-byte body document")
	}
	body := []byte{5, 0, 0, 0, 0}
	seq := append([]byte{0, 0, 0, 0, 0}, body...)
	seq = append(seq, 1, 4+2+4, 0, 0, 0, 'x', 0)
	seq = append(seq, tiny...)
	if _, err := ParseMsg(seq); err == nil {
		t.Error("ParseMsg accepted a 4-byte sequence document")
	}
	noTerm := append([]byte{0, 0, 0, 0, 0}, 5, 0, 0, 0, 1)
	if _, err := ParseMsg(noTerm); err == nil {
		t.Error("ParseMsg accepted a document without terminator")
	}
	q := append([]byte{0, 0, 0, 0}, "a.$cmd\x00"...)
	q = append(q, 0, 0, 0, 0, 1, 0, 0, 0)
	q = append(q, tiny...)
	if _, err := ParseQuery(q); err == nil {
		t.Error("ParseQuery accepted a 4-byte document")
	}
}
