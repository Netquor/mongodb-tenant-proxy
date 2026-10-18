package proxy

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
)

func marshal(v any) []byte {
	b, err := bson.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func replySeeds() [][]byte {
	return [][]byte{
		marshal(bson.M{"cursor": bson.M{"firstBatch": bson.A{bson.M{"a": 1}}, "id": int64(5), "ns": "app.__mtp_v.abc.view"}, "ok": 1}),
		marshal(bson.M{"cursor": bson.M{"nextBatch": bson.A{}, "id": int64(0), "ns": "app.x"}, "ok": 1}),
		marshal(bson.M{"cursor": bson.M{"firstBatch": bson.A{bson.M{"name": "__mtp_views"}, bson.M{"name": "c", "type": "collection"}, 5, bson.M{"name": 5}}, "id": int64(0)}, "ok": 1}),
		marshal(bson.M{"cursor": "x", "ok": 1}),
		marshal(bson.M{"ok": 0, "errmsg": "x"}),
		{5, 0, 0, 0, 0},
	}
}

// Reply patchers must never panic on whatever the upstream (or a hostile
// intermediary) returns, and must keep well-formed replies well-formed.
func FuzzReplyPatchers(f *testing.F) {
	for _, s := range replySeeds() {
		f.Add(s, "app.view", "collection")
	}
	srv := &Server{cfg: &config.Config{DisableViews: true}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv.run.Store(&runtime{rw: rewrite.New(rewrite.Config{}), disableViews: true})
	c := &conn{viewPhys: map[int64]string{}, s: srv}
	c.s.views = viewCache{}
	f.Fuzz(func(t *testing.T, resp []byte, ns, key string) {
		// Replies come from ReadDocument, so they are exactly one document.
		n, _, ok := bsoncore.ReadLength(resp)
		valid := ok && int(n) == len(resp) && bsoncore.Document(resp).Validate() == nil
		if len(ns) > 1<<12 || len(key) > 1<<12 || strings.Contains(key, "\x00") {
			return
		}
		check := func(name string, out bsoncore.Document) {
			if valid {
				if err := out.Validate(); err != nil {
					t.Fatalf("%s turned a valid reply into invalid BSON: %v", name, err)
				}
			}
		}
		d := bsoncore.Document(resp)
		check("patchCursorNS", patchCursorNS(d, ns))
		check("withString", withString(d, key, ns))
		check("patchTop", patchTop(d, key, bsoncore.Value{Type: bsoncore.TypeString, Data: bsoncore.AppendString(nil, ns)}))
		if valid {
			check("appendRaw", appendRaw(d, bsoncore.AppendStringElement(nil, key, ns)))
		}
		res := &rewrite.Result{}
		c.hookListCollections(res, bsoncore.Document(marshal(bson.M{"listCollections": 1})), "app")
		check("hookListCollections", res.Post(d))
		c.noteViewCursor(d, "phys", 0)
	})
}
