package test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// View create / collMod / drop racing reads and cache invalidation.
//
// Each worker owns a view name and checks read-your-writes on its own
// connection immediately after every DDL (the view cache must not serve - or
// re-publish - a pre-DDL snapshot). A set of contended names is hammered by
// everyone to shake out races between DDL and cached reads. Two tenants use
// the same names; neither may ever see the other's documents.
func TestStressViews(t *testing.T) {
	defer stresstest.Watchdog(t, 4*time.Minute)()
	t.Cleanup(stresstest.NoLeak(t, 10))
	e := setup(t, nil)
	tenants := []string{"ta", "tb"}
	for _, tn := range tenants {
		docs := make([]any, 20)
		for i := range docs {
			docs[i] = bson.M{"o": tn, "n": i}
		}
		cl := connect(t, fmt.Sprintf("mongodb://%s/?appName=%s", e.proxyAddr, tn))
		_, err := cl.Database("vv").Collection("base").InsertMany(ctx(t), docs)
		cl.Disconnect(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
	}
	end := time.Now().Add(stresstest.D(5*time.Second, 90*time.Second))
	findView := func(c *sc, name string, me string) (int, error) {
		res, err := c.run("vv", bson.D{{Key: "find", Value: name}})
		if err != nil {
			return 0, err
		}
		if !isOK(res) {
			return -1, nil
		}
		_, batch, _ := cursorOf(res)
		for _, d := range batch {
			if d["o"] != me {
				return 0, fmt.Errorf("tenant %s saw %v in view %s", me, d, name)
			}
		}
		return len(batch), nil
	}
	workers(len(tenants)*8, func(w int) {
		me := tenants[w%len(tenants)]
		if w >= len(tenants)*4 {
			// Pure readers: keep view-cache reloads in flight while the DDL
			// workers invalidate, so a loader that started before a DDL
			// finishes after it (the stale-republish window).
			c, err := dialSC(e.proxyAddr, me)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.close()
			for time.Now().Before(end) {
				if _, err := findView(c, "no_such_view", me); err != nil {
					t.Errorf("reader %s: %v", me, err)
					return
				}
			}
			return
		}
		mine := fmt.Sprint("mine", w)
		rng := rand.New(rand.NewSource(int64(w)))
		c, err := dialSC(e.proxyAddr, me)
		if err != nil {
			t.Error(err)
			return
		}
		defer c.close()
		for time.Now().Before(end) {
			// own view: strict read-your-writes
			if res, err := c.run("vv", bson.D{{Key: "create", Value: mine}, {Key: "viewOn", Value: "base"},
				{Key: "pipeline", Value: bson.A{bson.M{"$match": bson.M{}}}}}); err != nil || !isOK(res) {
				t.Errorf("%s create %s: %v %v", me, mine, res, err)
				return
			}
			if n, err := findView(c, mine, me); err != nil || n != 20 {
				t.Errorf("%s: right after create, view %s has %d docs (err %v), want 20", me, mine, n, err)
				return
			}
			if res, err := c.run("vv", bson.D{{Key: "collMod", Value: mine}, {Key: "viewOn", Value: "base"},
				{Key: "pipeline", Value: bson.A{bson.M{"$limit": 5}}}}); err != nil || !isOK(res) {
				t.Errorf("%s collMod %s: %v %v", me, mine, res, err)
				return
			}
			if n, err := findView(c, mine, me); err != nil || n != 5 {
				t.Errorf("%s: right after collMod, view %s has %d docs (err %v), want 5", me, mine, n, err)
				return
			}
			if res, err := c.run("vv", bson.D{{Key: "drop", Value: mine}}); err != nil || !isOK(res) {
				t.Errorf("%s drop %s: %v %v", me, mine, res, err)
				return
			}
			if n, err := findView(c, mine, me); err != nil || n > 0 {
				t.Errorf("%s: view %s still readable after drop (%d docs, err %v)", me, mine, n, err)
				return
			}
			// contended names: only isolation and liveness are checked
			for i := 0; i < 6; i++ {
				name := fmt.Sprint("shared", rng.Intn(3))
				var err error
				switch rng.Intn(4) {
				case 0:
					_, err = c.run("vv", bson.D{{Key: "create", Value: name}, {Key: "viewOn", Value: "base"}, {Key: "pipeline", Value: bson.A{}}})
				case 1:
					_, err = c.run("vv", bson.D{{Key: "collMod", Value: name}, {Key: "viewOn", Value: "base"}, {Key: "pipeline", Value: bson.A{bson.M{"$limit": 3}}}})
				case 2:
					_, err = c.run("vv", bson.D{{Key: "drop", Value: name}})
				default:
					_, err = findView(c, name, me)
				}
				if err != nil {
					t.Errorf("%s contended op on %s: %v", me, name, err)
					return
				}
			}
		}
	})
	// listCollections must never expose the hidden physical views
	for _, tn := range tenants {
		c, err := dialSC(e.proxyAddr, tn)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.run("vv", bson.D{{Key: "listCollections", Value: 1}})
		c.close()
		if err != nil {
			t.Fatal(err)
		}
		_, batch, _ := cursorOf(res)
		for _, d := range batch {
			if n, _ := d["name"].(string); len(n) > 5 && n[:5] == "__mtp" {
				t.Errorf("tenant %s sees hidden collection %s", tn, n)
			}
		}
	}
}
