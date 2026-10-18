package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// TestScramAuth covers both authentication hops: clients authenticate to the
// proxy with SCRAM-SHA-256 (user -> tenant), and the proxy authenticates to an
// auth-enabled upstream.
func TestScramAuth(t *testing.T) {
	ua, err := auth.NewUser("alice", "tenant-a", "alice-pw")
	must(t, err)
	ub, err := auth.NewUser("bob", "tenant-b", "bob-pw")
	must(t, err)
	e := setupWith(t, true, func(c *config.Config) {
		c.Auth = config.Auth{Mode: "scram", Users: []config.User{ua, ub}}
	})
	cli := func(user, pw string) string {
		return fmt.Sprintf("mongodb://%s:%s@%s/?authMechanism=SCRAM-SHA-256&authSource=admin", user, pw, e.proxyAddr)
	}
	a := connect(t, cli("alice", "alice-pw"))
	defer a.Disconnect(context.Background())
	b := connect(t, cli("bob", "bob-pw"))
	defer b.Disconnect(context.Background())

	_, err = a.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"who": "alice"})
	must(t, err)
	_, err = b.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"who": "bob"})
	must(t, err)
	if n := count(t, a.Database("s").Collection("c"), bson.M{}); n != 1 {
		t.Fatalf("alice sees %d docs, want 1", n)
	}
	if n := count(t, e.direct.Database("s").Collection("c"), bson.M{"who": "bob", "tenantId": "tenant-b"}); n != 1 {
		t.Fatal("bob's document is not stamped tenant-b")
	}

	for name, uri := range map[string]string{
		"wrong password": cli("alice", "nope"),
		"unknown user":   cli("mallory", "x"),
	} {
		bad := connectTimeout(t, uri, 5*time.Second)
		_, err := bad.Database("s").Collection("c").InsertOne(ctx(t), bson.M{"x": 1})
		bad.Disconnect(context.Background())
		mustFail(t, err, name)
	}
}
