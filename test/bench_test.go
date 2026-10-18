package test

import (
	"context"
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// BenchmarkFindOne compares point reads straight to mongod with the same
// reads through the proxy.
func BenchmarkFindOne(b *testing.B) {
	e := setup(b, nil)
	tc := e.tenant(b, "bench").Database("bench").Collection("c")
	_, err := tc.InsertOne(context.Background(), bson.M{"_id": 1, "v": "x"})
	if err != nil {
		b.Fatal(err)
	}
	// The direct client reads the same physical document.
	dc := e.direct.Database("bench").Collection("c")
	if _, err := dc.Indexes().CreateOne(context.Background(), mongo.IndexModel{Keys: bson.D{{Key: "tenantId", Value: 1}, {Key: "k", Value: 1}}}); err != nil {
		b.Fatal(err)
	}
	for name, c := range map[string]*mongo.Collection{"direct": dc, "proxy": tc} {
		b.Run(name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					var out bson.M
					if err := c.FindOne(context.Background(), bson.M{"_id": 1}).Decode(&out); err != nil {
						b.Fatal(fmt.Sprint(err))
					}
				}
			})
		})
	}
}
