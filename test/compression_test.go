package test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

var allCompressors = []string{"snappy", "zlib", "zstd"}

func compressedClient(t testing.TB, addr, appName string, comps ...string) *mongo.Client {
	t.Helper()
	o := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?appName=%s", addr, appName)).
		SetCompressors(comps).SetServerSelectionTimeout(20 * time.Second)
	c, err := mongo.Connect(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Disconnect(context.Background()) })
	return c
}

// upstreamDecompressed reports how many bytes mongod has decompressed with
// the algorithm, i.e. how much compressed traffic the proxy sent it.
func upstreamDecompressed(t testing.TB, e *env, alg string) int64 {
	t.Helper()
	raw, err := e.direct.Database("admin").RunCommand(context.Background(), bson.D{{Key: "serverStatus", Value: 1}}).Raw()
	must2(t, err)
	v, err := raw.LookupErr("network", "compression", alg, "decompressor", "bytesIn")
	if err != nil {
		return 0
	}
	n, _ := v.AsInt64OK()
	return n
}

func must2(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func bigDoc(i int) bson.M {
	return bson.M{"i": i, "payload": strings.Repeat("compress me please ", 200)}
}

// TestCompressionDriver runs the official driver with each compressor against
// a proxy that compresses in both directions (client side and upstream).
func TestCompressionDriver(t *testing.T) {
	for _, alg := range allCompressors {
		t.Run(alg, func(t *testing.T) {
			e := setup(t, func(c *config.Config) {
				c.Compressors = allCompressors
				c.Upstream.Compressors = []string{alg}
			})
			cl := compressedClient(t, e.proxyAddr, "comp-"+alg, alg)
			coll := cl.Database("c").Collection("docs")
			before := upstreamDecompressed(t, e, alg)

			var docs []any
			for i := 0; i < 50; i++ {
				docs = append(docs, bigDoc(i))
			}
			_, err := coll.InsertMany(context.Background(), docs)
			must2(t, err)
			cur, err := coll.Find(context.Background(), bson.M{}, options.Find().SetBatchSize(10))
			must2(t, err)
			var got []bson.M
			must2(t, cur.All(context.Background(), &got))
			if len(got) != 50 || got[7]["payload"] != bigDoc(7)["payload"] {
				t.Fatalf("round trip through compression corrupted data (%d docs)", len(got))
			}
			if n := count(t, coll, bson.M{"i": bson.M{"$gte": 25}}); n != 25 {
				t.Fatalf("count = %d", n)
			}
			if after := upstreamDecompressed(t, e, alg); after <= before {
				t.Fatalf("upstream never decompressed %s traffic from the proxy (%d -> %d)", alg, before, after)
			}
			if n := count(t, e.direct.Database("c").Collection("docs"), bson.M{"tenantId": "comp-" + alg}); n != 50 {
				t.Fatalf("documents not stamped with the tenant: %d", n)
			}
		})
	}
}

// TestCompressionMixed covers client/upstream combinations that differ.
func TestCompressionMixed(t *testing.T) {
	cases := []struct {
		name             string
		proxy, upstream  []string
		driver           []string
		wantUpstreamAlgo string
	}{
		{"client zstd, upstream snappy", allCompressors, []string{"snappy"}, []string{"zstd"}, "snappy"},
		{"client compressed, upstream plain", allCompressors, nil, []string{"zlib"}, ""},
		{"client plain, upstream zstd", nil, []string{"zstd"}, nil, "zstd"},
		{"driver asks, proxy has none", nil, nil, allCompressors, ""},
		{"driver asks for a disabled one", []string{"zlib"}, nil, []string{"snappy"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t, func(c *config.Config) {
				c.Compressors, c.Upstream.Compressors = tc.proxy, tc.upstream
			})
			cl := compressedClient(t, e.proxyAddr, "mixed", tc.driver...)
			coll := cl.Database("m").Collection("docs")
			before := int64(0)
			if tc.wantUpstreamAlgo != "" {
				before = upstreamDecompressed(t, e, tc.wantUpstreamAlgo)
			}
			_, err := coll.InsertOne(context.Background(), bigDoc(1))
			must2(t, err)
			var out bson.M
			must2(t, coll.FindOne(context.Background(), bson.M{"i": 1}).Decode(&out))
			if out["payload"] != bigDoc(1)["payload"] {
				t.Fatal("payload corrupted")
			}
			if tc.wantUpstreamAlgo != "" && upstreamDecompressed(t, e, tc.wantUpstreamAlgo) <= before {
				t.Fatalf("no %s traffic reached mongod", tc.wantUpstreamAlgo)
			}
		})
	}
}

// compConn is a minimal wire client used to look at opcodes the driver hides.
type compConn struct {
	t  testing.TB
	nc net.Conn
	id int32
}

func dialRaw(t testing.TB, addr string) *compConn {
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	return &compConn{t: t, nc: nc}
}

// roundTrip sends a command (compressed when comp != 0) and returns the reply
// document together with the opcode and compressor of the reply frame.
func (r *compConn) roundTrip(cmd bson.D, comp wire.Compressor) (bsoncore.Document, int32, wire.Compressor) {
	r.t.Helper()
	raw, err := bson.Marshal(cmd)
	must2(r.t, err)
	body := (&wire.Msg{Body: raw}).Encode()
	r.id++
	if comp != wire.CompNone {
		cb, err := wire.Compress(comp, wire.OpMsg, body)
		must2(r.t, err)
		must2(r.t, wire.WriteFrame(r.nc, r.id, 0, wire.OpCompressed, cb))
	} else {
		must2(r.t, wire.WriteFrame(r.nc, r.id, 0, wire.OpMsg, body))
	}
	r.nc.SetReadDeadline(time.Now().Add(20 * time.Second))
	h, rb, err := wire.ReadFrame(r.nc, 64<<20)
	must2(r.t, err)
	if h.ResponseTo != r.id {
		r.t.Fatalf("responseTo = %d, want %d", h.ResponseTo, r.id)
	}
	op, used := h.OpCode, wire.CompNone
	if op == wire.OpCompressed {
		_, used, rb, err = wire.Decompress(rb, 64<<20)
		must2(r.t, err)
	}
	m, err := wire.ParseMsg(rb)
	must2(r.t, err)
	return m.Body, h.OpCode, used
}

// TestCompressionNegotiationAndMirroring checks the handshake rules: hello
// advertises the configured intersection, hello/auth are never compressed, and
// replies mirror the compressor of the request.
func TestCompressionNegotiationAndMirroring(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		c.Compressors = []string{"zstd", "zlib"} // snappy deliberately off
		c.Upstream.Compressors = []string{"snappy"}
	})
	r := dialRaw(t, e.proxyAddr)
	hello, op, _ := r.roundTrip(bson.D{
		{Key: "hello", Value: 1}, {Key: "$db", Value: "admin"},
		{Key: "compression", Value: bson.A{"snappy", "zlib", "zstd"}},
		{Key: "client", Value: bson.D{{Key: "application", Value: bson.D{{Key: "name", Value: "raw-t"}}}}},
	}, wire.CompNone)
	if op != wire.OpMsg {
		t.Fatalf("hello reply opcode %d: handshake must not be compressed", op)
	}
	arr, ok := hello.Lookup("compression").ArrayOK()
	if !ok {
		t.Fatal("hello reply has no compression field")
	}
	vals, _ := arr.Values()
	var names []string
	for _, v := range vals {
		s, _ := v.StringValueOK()
		names = append(names, s)
	}
	if strings.Join(names, ",") != "zlib,zstd" { // client order, restricted to enabled
		t.Fatalf("advertised %v, want [zlib zstd]", names)
	}

	big := strings.Repeat("x", 4096)
	for _, id := range []wire.Compressor{wire.CompZlib, wire.CompZstd, wire.CompNone} {
		ins, op, used := r.roundTrip(bson.D{
			{Key: "insert", Value: "raw"}, {Key: "$db", Value: "rawdb"},
			{Key: "documents", Value: bson.A{bson.D{{Key: "v", Value: big}}}},
		}, id)
		if n, _ := ins.Lookup("n").AsInt64OK(); n != 1 {
			t.Fatalf("%v: insert reply %v", id, ins)
		}
		if (id == wire.CompNone) != (op == wire.OpMsg) || used != id {
			t.Fatalf("request compressed with %v, reply opcode %d compressor %v", id, op, used)
		}
		find, op, used := r.roundTrip(bson.D{{Key: "find", Value: "raw"}, {Key: "$db", Value: "rawdb"}}, id)
		first, _ := find.Lookup("cursor", "firstBatch").Array().Values()
		if len(first) == 0 || used != id || (id == wire.CompNone) != (op == wire.OpMsg) {
			t.Fatalf("%v: find reply opcode %d compressor %v batch %d", id, op, used, len(first))
		}
	}

	// snappy was not advertised, so a client using it anyway is dropped.
	body := (&wire.Msg{Body: mustMarshal(t, bson.D{{Key: "ping", Value: 1}, {Key: "$db", Value: "admin"}})}).Encode()
	cb, _ := wire.Compress(wire.CompSnappy, wire.OpMsg, body)
	must2(t, wire.WriteFrame(r.nc, 99, 0, wire.OpCompressed, cb))
	r.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := wire.ReadFrame(r.nc, 1<<20); err == nil {
		t.Fatal("proxy answered a request compressed with a non-negotiated compressor")
	}
}

func mustMarshal(t testing.TB, d bson.D) []byte {
	b, err := bson.Marshal(d)
	must2(t, err)
	return b
}

// BenchmarkCompression measures find throughput of 64 KiB-ish documents with
// each client/upstream compression setting against the uncompressed baseline.
func BenchmarkCompression(b *testing.B) {
	for _, alg := range append([]string{"none"}, allCompressors...) {
		b.Run(alg, func(b *testing.B) {
			var comps []string
			if alg != "none" {
				comps = []string{alg}
			}
			e := setup(b, func(c *config.Config) { c.Compressors, c.Upstream.Compressors = comps, comps })
			cl := compressedClient(b, e.proxyAddr, "bench", comps...)
			coll := cl.Database("bench").Collection("big")
			var docs []any
			for i := 0; i < 20; i++ {
				docs = append(docs, bson.M{"i": i, "payload": strings.Repeat("benchmark payload ", 4000)})
			}
			if _, err := coll.InsertMany(context.Background(), docs); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.SetBytes(20 * 18 * 4000)
			for i := 0; i < b.N; i++ {
				cur, err := coll.Find(context.Background(), bson.M{})
				if err != nil {
					b.Fatal(err)
				}
				var out []bson.M
				if err := cur.All(context.Background(), &out); err != nil || len(out) != 20 {
					b.Fatal(err, len(out))
				}
			}
		})
	}
}
