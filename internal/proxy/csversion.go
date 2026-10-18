package proxy

import (
	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/rewrite"
)

// minChangeStreamWire is the wire version of MongoDB 6.0, the first release
// with collection pre/post images, which tenant filtering of change streams
// depends on.
const minChangeStreamWire = 17

// changeStreamUnsupported returns an error reply when res opens a change
// stream the upstream cannot serve tenant-safely (MongoDB < 6.0), or nil.
// Failing up front gives drivers a clear CommandNotSupported instead of a
// confusing collMod error from the upstream.
func changeStreamUnsupported(res *rewrite.Result, upstreamMaxWire int32) bsoncore.Document {
	if !res.ChangeStream || upstreamMaxWire >= minChangeStreamWire {
		return nil
	}
	return errorDoc(115, "CommandNotSupported",
		"tenant proxy: change streams require MongoDB 6.0 or newer (collection pre/post images)")
}
