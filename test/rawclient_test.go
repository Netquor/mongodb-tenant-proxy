package test

import (
	"bufio"
	"net"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// rawConn speaks OP_MSG directly so tests can send commands a driver would
// never construct (foreign session ids, hand-built lsid fields, ...).
type rawConn struct {
	t  testing.TB
	nc net.Conn
	br *bufio.Reader
	id int32
}

func (e *env) raw(t testing.TB, tenant string) *rawConn {
	t.Helper()
	nc, err := net.Dial("tcp", e.proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	r := &rawConn{t: t, nc: nc, br: bufio.NewReader(nc)}
	res := r.run("admin", bson.D{{Key: "hello", Value: 1},
		{Key: "client", Value: bson.M{"application": bson.M{"name": tenant}}}})
	if res["ok"] != 1.0 && res["ok"] != int32(1) {
		t.Fatalf("hello failed: %v", res)
	}
	return r
}

func (r *rawConn) run(db string, cmd bson.D) bson.M {
	r.t.Helper()
	r.nc.SetDeadline(time.Now().Add(30 * time.Second))
	body, err := bson.Marshal(append(cmd, bson.E{Key: "$db", Value: db}))
	if err != nil {
		r.t.Fatal(err)
	}
	r.id++
	if err := wire.WriteFrame(r.nc, r.id, 0, wire.OpMsg, (&wire.Msg{Body: body}).Encode()); err != nil {
		r.t.Fatal(err)
	}
	_, rb, err := wire.ReadFrame(r.br, 48<<20)
	if err != nil {
		r.t.Fatal(err)
	}
	m, err := wire.ParseMsg(rb)
	if err != nil {
		r.t.Fatal(err)
	}
	var out bson.M
	if err := bson.Unmarshal(m.Body, &out); err != nil {
		r.t.Fatal(err)
	}
	return out
}

func isOK(res bson.M) bool {
	switch v := res["ok"].(type) {
	case float64:
		return v == 1
	case int32:
		return v == 1
	case int64:
		return v == 1
	}
	return false
}
