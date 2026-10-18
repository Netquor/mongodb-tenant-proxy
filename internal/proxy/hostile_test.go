package proxy

import (
	"io"
	"log/slog"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
)

// rawBad returns {<first>: 1, <key>: <document-typed value with a bogus length>}:
// framing that survives a shallow check but makes bsoncore's accessors panic.
func rawBad(first, key string) bsoncore.Document {
	d := []byte{0, 0, 0, 0}
	d = bsoncore.AppendInt32Element(d, first, 1)
	d = append(d, 0x03)
	d = append(d, key...)
	d = append(d, 0, 2, 0, 0, 0)
	d = append(d, 0)
	d[0] = byte(len(d))
	return d
}

func rawBadSASL() bsoncore.Document {
	d := []byte{0, 0, 0, 0}
	d = bsoncore.AppendStringElement(d, "saslStart", "1")
	d = bsoncore.AppendStringElement(d, "mechanism", "SCRAM-SHA-256")
	d = bsoncore.AppendBinaryElement(d, "payload", 0, []byte("n,,n=u,r=x"))
	d = append(d, 0x03)
	d = append(d, "options"...)
	d = append(d, 0, 2, 0, 0, 0)
	d = append(d, 0)
	d[0] = byte(len(d))
	return d
}

func TestValidateBodyRejectsBadNesting(t *testing.T) {
	for _, d := range []bsoncore.Document{rawBad("hello", "client"), rawBadSASL()} {
		if err := rewrite.ValidateBody(d); err == nil {
			t.Errorf("ValidateBody accepted a malformed nested document")
		}
	}
}

func testConn(t *testing.T, mode string) *conn {
	t.Helper()
	a, err := auth.New(config.Auth{Mode: config.Mode(mode), StaticTenant: "T1"})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &Server{cfg: &config.Config{}, auth: a, log: log}
	srv.run.Store(&runtime{rw: rewrite.New(rewrite.Config{})})
	return &conn{
		viewPhys: map[int64]string{}, cursors: map[int64]string{}, log: log,
		s: srv,
	}
}

// Defence in depth: the handshake and SASL handlers read nested client-supplied
// fields before authentication. They must survive malformed values even if the
// framing check in front of them ever lets one through (bsoncore's multi-key
// Lookup panics on a malformed intermediate document).
func TestHandshakeAndSASLSurviveTypeConfusion(t *testing.T) {
	c := testConn(t, "appname")
	for _, req := range []any{
		bson.M{"hello": 1, "client": "x"},
		bson.M{"hello": 1, "client": bson.A{}},
		bson.M{"hello": 1, "client": bson.M{"application": 5}},
		bson.M{"hello": 1, "client": bson.M{"application": bson.M{"name": 5}}},
		bson.M{"isMaster": 1, "client": int32(7)},
		rawBad("hello", "client"),
	} {
		var b []byte
		if raw, ok := req.(bsoncore.Document); ok {
			b = raw
		} else {
			b = marshal(req)
		}
		d := c.hello(b)
		if ok, _ := d.Lookup("ok").AsInt64OK(); ok != 1 {
			t.Errorf("hello(%v) = %s", req, bson.Raw(d))
		}
	}
	s := testConn(t, "scram")
	for _, req := range []any{
		bson.M{"saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": bson.Binary{Data: []byte("n,,n=u,r=x")}, "options": 5},
		bson.M{"saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": bson.Binary{Data: []byte("n,,n=u,r=x")}, "options": "x"},
		bson.M{"saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": bson.Binary{Data: []byte("n,,n=u,r=x")}, "options": bson.A{}},
		rawBadSASL(),
	} {
		var b []byte
		if raw, ok := req.(bsoncore.Document); ok {
			b = raw
		} else {
			b = marshal(req)
		}
		d := s.handleSASL("saslStart", b)
		if ok, _ := d.Lookup("ok").AsInt64OK(); ok == 1 {
			t.Errorf("saslStart with bogus credentials succeeded: %s", bson.Raw(d))
		}
	}
}

func TestSafelyContainsPanics(t *testing.T) {
	c := testConn(t, "static")
	if err := c.safely(func() error { panic("boom") }); err == nil {
		t.Fatal("panic was not converted to an error")
	}
	if err := c.safely(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestReplyPatchersTolerateWrongTypes(t *testing.T) {
	c := testConn(t, "static")
	c.s.rt().disableViews = true
	for _, resp := range []any{
		bson.M{"cursor": "x", "ok": 1},
		bson.M{"cursor": bson.A{}, "ok": 1},
		bson.M{"cursor": bson.M{"firstBatch": "x", "id": "y", "ns": 5}, "ok": 1},
		bson.M{"cursor": bson.M{"firstBatch": bson.A{1, "x", nil}}, "ok": 1},
	} {
		d := bsoncore.Document(marshal(resp))
		c.noteViewCursor(d, "p", 0)
		_ = patchCursorNS(d, "app.v")
		res := &rewrite.Result{}
		c.hookListCollections(res, marshal(bson.M{"listCollections": 1}), "app")
		if out := res.Post(d); out.Validate() != nil {
			t.Errorf("hookListCollections broke %v", resp)
		}
	}
}
