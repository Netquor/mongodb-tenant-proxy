package test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// Credentials must never surface in logs, the audit trail, metrics or error
// messages sent to clients - not the ones that work, and not the ones an
// attacker supplies.
func TestAttackSecretsNeverLeak(t *testing.T) {
	const (
		clientPW  = "client-pw-SECRET-7f3a"
		appSecret = "appname-hmac-SECRET-91bc"
		jwtMarker = "jwt-bearer-SECRET-55de"
		badGuess  = "wrong-guess-SECRET-02aa"
		forgedMAC = "00112233445566778899aabbccddeeff"
	)
	u, err := auth.NewUser("alice", "tenant-a", clientPW)
	must(t, err)
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	e := atkSetupAuth(t, true, func(c *config.Config) {
		c.Auth = config.Auth{Mode: "scram", Users: []config.User{u}, AppNameSecret: appSecret,
			BruteForce: config.BruteForce{MaxFailures: -1}}
		c.Audit = config.Audit{Enabled: true, Sink: "file", Path: auditPath}
	}, nil)

	// Real logins, wrong logins, hostile payloads, hostile tokens.
	good := e.atkDial(t)
	if res := good.scramLogin("alice", clientPW); !isOK(res) {
		t.Fatalf("login: %v", res)
	}
	good.cmd("sec", bson.D{{Key: "insert", Value: "c"}, {Key: "documents", Value: bson.A{bson.M{"x": 1}}}})
	var replies []string
	collect := func(res bson.M) { replies = append(replies, bsonText(res)) }
	for i := 0; i < 3; i++ {
		collect(e.atkDial(t).scramLogin("alice", badGuess))
		collect(e.atkDial(t).scramLogin("mallory", badGuess))
	}
	r := e.atkDial(t)
	collect(r.saslStart("MONGODB-OIDC", mustBSON(t, bson.M{"jwt": "eyJhbGciOiJub25lIn0." + jwtMarker + "."})))
	collect(r.saslStart("SCRAM-SHA-256", []byte("n,,n="+badGuess+",r=x")))
	collect(r.saslStart("NOPE"+strings.Repeat("N", 100000), nil))
	collect(r.cmd("admin", bson.D{{Key: "hello", Value: 1}, {Key: "client", Value: bson.M{"application": bson.M{"name": "tenant-a." + forgedMAC}}}}))
	collect(r.cmd("sec", bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.M{"password": badGuess}}}))

	// Upstream credentials are also exposed by nothing the client can ask for.
	collect(good.cmd("admin", bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}))
	collect(good.cmd("admin", bson.D{{Key: "getCmdLineOpts", Value: 1}}))
	collect(good.cmd("admin", bson.D{{Key: "serverStatus", Value: 1}}))
	collect(good.cmd("admin", bson.D{{Key: "usersInfo", Value: 1}}))
	collect(good.cmd("admin", bson.D{{Key: "currentOp", Value: 1}}))
	collect(good.cmd("admin", bson.D{{Key: "hello", Value: 1}}))

	rec := httptest.NewRecorder()
	e.srv.M.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	auditRaw, _ := os.ReadFile(auditPath)

	surfaces := map[string]string{
		"proxy log":      e.log.String(),
		"audit log":      string(auditRaw),
		"metrics":        rec.Body.String(),
		"client replies": strings.Join(replies, "\n"),
	}
	for name, text := range surfaces {
		for _, secret := range []string{clientPW, appSecret, jwtMarker, badGuess, upstreamPassword, forgedMAC} {
			if strings.Contains(text, secret) {
				i := strings.Index(text, secret)
				t.Errorf("%s contains a secret (%.8q…): …%s…", name, secret, text[max(0, i-60):min(len(text), i+80)])
			}
		}
	}
	// The audit trail must still have recorded the attempts.
	for _, want := range []string{`"type":"auth.success"`, `"type":"auth.failure"`} {
		if !strings.Contains(surfaces["audit log"], want) {
			t.Errorf("audit log lacks %s", want)
		}
	}
	e.noPanics(t)
}

func bsonText(res bson.M) string {
	b, _ := bson.MarshalExtJSON(res, false, false)
	return string(b)
}
