package test

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestSessionsAreBoundToTenants(t *testing.T) {
	e := setup(t, nil)
	a, b := e.raw(t, "tenant-a"), e.raw(t, "tenant-b")
	lsid := bson.M{"id": bson.Binary{Subtype: 4, Data: []byte("0123456789abcdef")}}
	other := bson.M{"id": bson.Binary{Subtype: 4, Data: []byte("fedcba9876543210")}}

	// Tenant A uses the session first and owns it.
	res := a.run("app", bson.D{{Key: "insert", Value: "s"}, {Key: "documents", Value: bson.A{bson.M{"n": 1}}}, {Key: "lsid", Value: lsid}})
	if !isOK(res) {
		t.Fatalf("owner insert failed: %v", res)
	}

	foreign := map[string]bson.D{
		"find":              {{Key: "find", Value: "s"}, {Key: "lsid", Value: lsid}},
		"insert":            {{Key: "insert", Value: "s"}, {Key: "documents", Value: bson.A{bson.M{"n": 9}}}, {Key: "lsid", Value: lsid}},
		"getMore":           {{Key: "getMore", Value: int64(1)}, {Key: "collection", Value: "s"}, {Key: "lsid", Value: lsid}},
		"commitTransaction": {{Key: "commitTransaction", Value: 1}, {Key: "lsid", Value: lsid}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}},
		"abortTransaction":  {{Key: "abortTransaction", Value: 1}, {Key: "lsid", Value: lsid}, {Key: "txnNumber", Value: int64(1)}, {Key: "autocommit", Value: false}},
		"endSessions":       {{Key: "endSessions", Value: bson.A{other, lsid}}},
		"refreshSessions":   {{Key: "refreshSessions", Value: bson.A{lsid}}},
		"killSessions":      {{Key: "killSessions", Value: bson.A{lsid}}},
	}
	for name, cmd := range foreign {
		res := b.run("app", cmd)
		if isOK(res) {
			t.Errorf("%s with another tenant's lsid was accepted: %v", name, res)
		}
	}
	// The rejected endSessions must not have bound `other` to B... and A can still use its session.
	if res := a.run("app", bson.D{{Key: "find", Value: "s"}, {Key: "lsid", Value: lsid}}); !isOK(res) {
		t.Fatalf("owner lost its session: %v", res)
	}
	if res := a.run("app", bson.D{{Key: "endSessions", Value: bson.A{lsid, other}}}); !isOK(res) {
		t.Fatalf("owner endSessions failed: %v", res)
	}
	// B never wrote anything through A's session.
	n, err := e.tenant(t, "tenant-b").Database("app").Collection("s").CountDocuments(ctx(t), bson.M{})
	must(t, err)
	if n != 0 {
		t.Fatalf("tenant-b sees %d docs", n)
	}
	// B's own sessions still work, including through the driver.
	cb := e.tenant(t, "tenant-b").Database("app").Collection("s")
	_, err = cb.InsertOne(ctx(t), bson.M{"n": 2})
	must(t, err)
}

func TestDriverSessionsAndTransactionsStillWork(t *testing.T) {
	e := setup(t, nil)
	a := e.tenant(t, "tenant-a")
	sess, err := a.StartSession()
	must(t, err)
	defer sess.EndSession(ctx(t))
	c := a.Database("app").Collection("tx")
	_, err = sess.WithTransaction(ctx(t), func(sc context.Context) (any, error) {
		return c.InsertOne(sc, bson.M{"n": 1})
	})
	must(t, err)

	// Another tenant presenting that session's id is refused.
	_, idData := sess.ID().Lookup("id").Binary()
	b := e.raw(t, "tenant-b")
	res := b.run("app", bson.D{{Key: "find", Value: "tx"}, {Key: "lsid", Value: bson.M{"id": bson.Binary{Subtype: 4, Data: idData}}}})
	if isOK(res) {
		t.Fatalf("driver session hijacked: %v", res)
	}
}
