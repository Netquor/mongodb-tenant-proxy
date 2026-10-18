package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// saslStart/saslContinue over a raw connection, so tests can send what a
// driver never would.
func (r *atkRaw) saslStart(mech string, payload []byte) bson.M {
	r.t.Helper()
	return r.cmd("admin", bson.D{{Key: "saslStart", Value: 1}, {Key: "mechanism", Value: mech},
		{Key: "payload", Value: bson.Binary{Data: payload}}, {Key: "autoAuthorize", Value: 1}})
}

func (r *atkRaw) saslContinue(convID any, payload []byte) bson.M {
	r.t.Helper()
	return r.cmd("admin", bson.D{{Key: "saslContinue", Value: 1}, {Key: "conversationId", Value: convID},
		{Key: "payload", Value: bson.Binary{Data: payload}}})
}

func payloadOf(t testing.TB, res bson.M) string {
	b, ok := res["payload"].(bson.Binary)
	if !ok {
		t.Fatalf("no payload in %v", res)
	}
	return string(b.Data)
}

// scramLogin runs a full SCRAM-SHA-256 login on r. It returns the final reply.
func (r *atkRaw) scramLogin(user, pw string) bson.M {
	r.t.Helper()
	cl, err := scram.SHA256.NewClient(user, pw, "")
	if err != nil {
		r.t.Fatal(err)
	}
	conv := cl.NewConversation()
	first, _ := conv.Step("")
	res := r.saslStart(auth.MechSCRAM256, []byte(first))
	if !isOK(res) {
		return res
	}
	final, err := conv.Step(payloadOf(r.t, res))
	if err != nil {
		return bson.M{"ok": 0, "errmsg": err.Error()}
	}
	res = r.saslContinue(int32(1), []byte(final))
	if !isOK(res) {
		return res
	}
	if done, _ := res["done"].(bool); !done {
		res = r.saslContinue(int32(1), nil)
	}
	return res
}

func atkUsers(t *testing.T) []config.User {
	ua, err := auth.NewUser("alice", "tenant-a", "alice-pw")
	must(t, err)
	ub, err := auth.NewUser("bob", "tenant-b", "bob-pw")
	must(t, err)
	return []config.User{ua, ub}
}

func TestAttackSCRAMBruteForceLockout(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Auth = config.Auth{Mode: "scram", Users: atkUsers(t),
			BruteForce: config.BruteForce{MaxFailures: 5, Window: "1m", Lockout: "2s"}}
	}, nil)

	// Wrong passwords, spread over fresh connections: after the fifth the
	// address is locked, even for the right password.
	for i := 0; i < 5; i++ {
		r := e.atkDial(t)
		if res := r.scramLogin("alice", fmt.Sprintf("guess-%d", i)); isOK(res) {
			t.Fatal("wrong password accepted")
		}
	}
	r := e.atkDial(t)
	if res := r.scramLogin("alice", "alice-pw"); isOK(res) {
		t.Fatal("correct password accepted while locked out")
	}
	if !r.closedWithin(2 * time.Second) {
		t.Fatal("locked-out connection left open")
	}
	// The lockout is per address, not global.
	// (Everything here is 127.0.0.1, so prove the converse instead: it
	// expires, and the legitimate user gets in.)
	time.Sleep(2200 * time.Millisecond)
	r = e.atkDial(t)
	if res := r.scramLogin("alice", "alice-pw"); !isOK(res) {
		t.Fatalf("login after the lockout expired: %v", res)
	}
	e.noPanics(t)
}

// Many guesses on ONE connection are cut off too, and the connection closes.
func TestAttackSCRAMGuessesOnOneConnection(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Auth = config.Auth{Mode: "scram", Users: atkUsers(t), BruteForce: config.BruteForce{MaxFailures: 4, Lockout: "1m"}}
	}, nil)
	r := e.atkDial(t)
	attempts := 0
	for ; attempts < 50; attempts++ {
		r.nc.SetDeadline(time.Now().Add(5 * time.Second))
		cl, _ := scram.SHA256.NewClient("alice", "x", "")
		conv := cl.NewConversation()
		first, _ := conv.Step("")
		body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("admin", bson.D{{Key: "saslStart", Value: 1}, {Key: "mechanism", Value: "SCRAM-SHA-256"},
			{Key: "payload", Value: bson.Binary{Data: []byte(first)}}}))}).Encode()
		if _, err := r.nc.Write(atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body)); err != nil {
			break
		}
		_, res, err := r.readMsg()
		if err != nil {
			break
		}
		if isOK(res) {
			final, _ := conv.Step(payloadOf(t, res))
			r.saslContinueNoFail(final)
		}
	}
	if attempts >= 20 {
		t.Fatalf("%d guesses on one connection before being cut off (limit 4)", attempts)
	}
}

func (r *atkRaw) saslContinueNoFail(payload string) {
	body := (&wire.Msg{Body: mustBSON(r.t, atkCmdDoc("admin", bson.D{{Key: "saslContinue", Value: 1}, {Key: "conversationId", Value: int32(1)},
		{Key: "payload", Value: bson.Binary{Data: []byte(payload)}}}))}).Encode()
	r.nc.Write(atkFrame(int32(16+len(body)), 2, 0, wire.OpMsg, body))
	r.readMsg()
}

func TestAttackSCRAMProtocolAbuse(t *testing.T) {
	e := atkSetup(t, func(c *config.Config) {
		c.Auth = config.Auth{Mode: "scram", Users: atkUsers(t), BruteForce: config.BruteForce{MaxFailures: -1}}
	}, nil)

	t.Run("commands before authentication are refused", func(t *testing.T) {
		r := e.atkDial(t)
		for _, c := range []bson.D{
			{{Key: "find", Value: "c"}}, {{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"x": 1}}}},
			{{Key: "listCollections", Value: 1}}, {{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{}}, {Key: "cursor", Value: bson.M{}}},
			{{Key: "getMore", Value: int64(1)}, {Key: "collection", Value: "c"}}, {{Key: "killCursors", Value: "c"}, {Key: "cursors", Value: bson.A{int64(1)}}},
			{{Key: "endSessions", Value: bson.A{}}}, {{Key: "dropDatabase", Value: 1}}, {{Key: "serverStatus", Value: 1}},
		} {
			if res := r.cmd("atk", c); isOK(res) {
				t.Fatalf("%s accepted without authentication: %v", c[0].Key, res)
			}
		}
	})
	t.Run("conversation id confusion", func(t *testing.T) {
		r := e.atkDial(t)
		cl, _ := scram.SHA256.NewClient("alice", "alice-pw", "")
		conv := cl.NewConversation()
		first, _ := conv.Step("")
		res := r.saslStart("SCRAM-SHA-256", []byte(first))
		final, _ := conv.Step(payloadOf(t, res))
		for _, id := range []any{int32(0), int32(2), int32(-1), int64(1) << 40, "1", nil, 1.5, bson.A{}} {
			if res := r.saslContinue(id, []byte(final)); isOK(res) {
				t.Fatalf("conversationId %v accepted", id)
			}
		}
		// A wrong id ended that conversation: the right one no longer works.
		if res := r.saslContinue(int32(1), []byte(final)); isOK(res) {
			t.Fatal("conversation survived an id mismatch")
		}
	})
	t.Run("saslContinue without saslStart", func(t *testing.T) {
		r := e.atkDial(t)
		for i := 0; i < 5; i++ {
			if res := r.saslContinue(int32(1), []byte("c=biws,r=x,p=AAAA")); isOK(res) {
				t.Fatal("saslContinue without start accepted")
			}
		}
	})
	t.Run("hostile payloads", func(t *testing.T) {
		r := e.atkDial(t)
		for _, p := range [][]byte{nil, {}, []byte("n,,"), []byte("n,,n=alice"), []byte("n,,n=alice,r="), make([]byte, 200000), []byte("\xff\xfe\x00"),
			[]byte("n,,n=" + strings.Repeat("a", 100000) + ",r=x")} {
			if res := r.saslStart("SCRAM-SHA-256", p); isOK(res) {
				if d, _ := res["done"].(bool); d {
					t.Fatalf("payload %.20q completed", p)
				}
			}
		}
		for _, m := range []string{"", "PLAIN", "MONGODB-CR", "SCRAM-SHA-1", "SCRAM-SHA-512", "MONGODB-X509", "MONGODB-OIDC", "GSSAPI", strings.Repeat("M", 100000)} {
			if res := r.saslStart(m, []byte("n,,n=alice,r=x")); isOK(res) {
				if d, _ := res["done"].(bool); d || m != "" {
					t.Fatalf("mechanism %.20q accepted: %v", m, res)
				}
			}
		}
		// Missing / mistyped fields.
		for _, c := range []bson.D{
			{{Key: "saslStart", Value: 1}},
			{{Key: "saslStart", Value: 1}, {Key: "mechanism", Value: 5}, {Key: "payload", Value: "str"}},
			{{Key: "saslStart", Value: 1}, {Key: "mechanism", Value: "SCRAM-SHA-256"}, {Key: "payload", Value: "str"}},
			{{Key: "saslStart", Value: 1}, {Key: "mechanism", Value: "SCRAM-SHA-256"}, {Key: "payload", Value: bson.A{1, 2}}},
			{{Key: "saslContinue", Value: 1}},
			{{Key: "authenticate", Value: 1}},
			{{Key: "authenticate", Value: 1}, {Key: "mechanism", Value: "MONGODB-X509"}},
			{{Key: "getnonce", Value: 1}},
			{{Key: "logout", Value: 1}},
		} {
			if res := r.cmd("admin", c); isOK(res) && c[0].Key != "logout" && c[0].Key != "getnonce" {
				t.Fatalf("%v accepted: %v", c, res)
			}
		}
	})
	t.Run("auth after auth: no tenant switching", func(t *testing.T) {
		r := e.atkDial(t)
		if res := r.scramLogin("alice", "alice-pw"); !isOK(res) {
			t.Fatalf("alice: %v", res)
		}
		r.cmd("sw", bson.D{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"who": "alice-before"}}}})
		// Bob's valid credentials on Alice's connection.
		res := r.scramLogin("bob", "bob-pw")
		if isOK(res) {
			t.Fatalf("tenant switched to bob on an authenticated connection: %v", res)
		}
		// Whatever state the connection is in now, it must not act as tenant-b.
		r2 := r.cmd("sw", bson.D{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"who": "after-switch-attempt"}}}})
		_ = r2
		if n := count(t, e.direct.Database("sw").Collection("c"), bson.M{"tenantId": "tenant-b"}); n != 0 {
			t.Fatalf("%d documents landed in tenant-b through alice's connection", n)
		}
		// Re-authenticating as the same tenant is harmless.
		r3 := e.atkDial(t)
		if res := r3.scramLogin("alice", "alice-pw"); !isOK(res) {
			t.Fatal(res)
		}
		if res := r3.scramLogin("alice", "alice-pw"); !isOK(res) {
			t.Fatalf("same-tenant re-authentication refused: %v", res)
		}
	})
	t.Run("removing credentials with logout does not reset the tenant", func(t *testing.T) {
		r := e.atkDial(t)
		r.scramLogin("alice", "alice-pw")
		r.cmd("admin", bson.D{{Key: "logout", Value: 1}})
		res := r.cmd("sw", bson.D{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"who": "post-logout"}}}})
		if isOK(res) {
			if n := count(t, e.direct.Database("sw").Collection("c"), bson.M{"who": "post-logout", "tenantId": "tenant-a"}); n != 1 {
				t.Fatal("post-logout write is not confined to the tenant")
			}
		}
	})
	e.noPanics(t)
}
