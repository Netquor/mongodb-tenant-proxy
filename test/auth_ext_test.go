package test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
)

// plainUpstream starts a no-auth mongod and a direct client to it.
func plainUpstream(t testing.TB) (addr string, direct *mongo.Client) {
	addr = startMongod(t, false)
	direct = connect(t, fmt.Sprintf("mongodb://%s/?directConnection=true", addr))
	t.Cleanup(func() { direct.Disconnect(context.Background()) })
	return addr, direct
}

// pingErr connects with the options and reports whether the first operation
// (which triggers authentication) fails.
func opErr(t testing.TB, o *options.ClientOptions) error {
	o.SetServerSelectionTimeout(5 * time.Second)
	c, err := mongo.Connect(o)
	if err != nil {
		return err
	}
	defer c.Disconnect(context.Background())
	_, err = c.Database("s").Collection("c").InsertOne(context.Background(), bson.M{"probe": 1})
	return err
}

func stampedCount(t testing.TB, direct *mongo.Client, tenant string) int64 {
	n, err := direct.Database("s").Collection("c").CountDocuments(context.Background(), bson.M{"tenantId": tenant})
	must2(t, err)
	return n
}

// ---- SCRAM-SHA-1 / mechanism lists ----------------------------------------

func TestClientSCRAMSHA1AndMechanismList(t *testing.T) {
	alice, err := auth.NewUser("alice", "tenant-a", "alice-pw")
	must(t, err)
	alice.SHA1, err = auth.NewSHA1Credential("alice", "alice-pw")
	must(t, err)
	carol := config.User{Username: "carol", TenantID: "tenant-c"} // legacy-only user
	carol.SHA1, err = auth.NewSHA1Credential("carol", "carol-pw")
	must(t, err)

	up, direct := plainUpstream(t)
	start := func(mode config.Mode) string {
		addr, _ := startProxy(t, &config.Config{
			Upstream: config.Upstream{Addr: up}, Auth: config.Auth{Mode: mode, Users: []config.User{alice, carol}},
		})
		return addr
	}
	both := start("scram,scram-sha-1")
	uri := func(addr, user, pw, mech string) *options.ClientOptions {
		u := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=admin", user, pw, addr)
		if mech != "" {
			u += "&authMechanism=" + mech
		}
		return options.Client().ApplyURI(u)
	}

	for _, tc := range []struct {
		name, user, pw, mech string
		ok                   bool
	}{
		{"alice SHA-256", "alice", "alice-pw", "SCRAM-SHA-256", true},
		{"alice SHA-1", "alice", "alice-pw", "SCRAM-SHA-1", true},
		{"alice negotiated", "alice", "alice-pw", "", true},
		{"carol SHA-1", "carol", "carol-pw", "SCRAM-SHA-1", true},
		{"carol negotiated falls back to SHA-1", "carol", "carol-pw", "", true},
		{"carol has no SHA-256 credential", "carol", "carol-pw", "SCRAM-SHA-256", false},
		{"SHA-1 wrong password", "alice", "nope", "SCRAM-SHA-1", false},
		{"SHA-1 password digest is not the plain password", "alice", "alice-pw ", "SCRAM-SHA-1", false},
		{"unknown user", "mallory", "x", "SCRAM-SHA-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := opErr(t, uri(both, tc.user, tc.pw, tc.mech))
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && err == nil {
				t.Fatal("authentication unexpectedly succeeded")
			}
		})
	}
	if n := stampedCount(t, direct, "tenant-a"); n != 3 {
		t.Fatalf("tenant-a probes = %d, want 3", n)
	}
	if n := stampedCount(t, direct, "tenant-c"); n != 2 {
		t.Fatalf("tenant-c probes = %d, want 2", n)
	}

	t.Run("SHA-1 stays off unless listed", func(t *testing.T) {
		only256 := start("scram")
		if err := opErr(t, uri(only256, "alice", "alice-pw", "SCRAM-SHA-1")); err == nil {
			t.Fatal("SCRAM-SHA-1 accepted although only scram is enabled")
		}
		if err := opErr(t, uri(only256, "alice", "alice-pw", "SCRAM-SHA-256")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("saslSupportedMechs", func(t *testing.T) {
		r := dialRaw(t, both)
		for user, want := range map[string]string{
			"admin.alice":   "SCRAM-SHA-256,SCRAM-SHA-1",
			"admin.carol":   "SCRAM-SHA-1",
			"admin.nobody":  "SCRAM-SHA-256,SCRAM-SHA-1", // unknown users look like known ones
			"admin.mallory": "SCRAM-SHA-256,SCRAM-SHA-1",
		} {
			hello, _, _ := r.roundTrip(bson.D{{Key: "hello", Value: 1}, {Key: "$db", Value: "admin"},
				{Key: "saslSupportedMechs", Value: user}}, 0)
			vals, _ := hello.Lookup("saslSupportedMechs").Array().Values()
			got := ""
			for i, v := range vals {
				s, _ := v.StringValueOK()
				if i > 0 {
					got += ","
				}
				got += s
			}
			if got != want {
				t.Errorf("%s: saslSupportedMechs = %q, want %q", user, got, want)
			}
		}
	})
}

// ---- x.509 -------------------------------------------------------------------

func x509Client(addr string, ca string, l *leaf, extra string) *options.ClientOptions {
	q := url.Values{"tls": {"true"}, "tlsCAFile": {ca}}
	if l != nil {
		q.Set("tlsCertificateKeyFile", l.pemFile)
		q.Set("authMechanism", "MONGODB-X509")
		q.Set("authSource", "$external")
	}
	return options.Client().ApplyURI(fmt.Sprintf("mongodb://%s/?%s%s", addr, q.Encode(), extra))
}

func TestClientX509(t *testing.T) {
	ca := newPKI(t)
	server := ca.issue(t, "server", pkix.Name{CommonName: "proxy"}, true, nil, nil)
	alice := ca.issue(t, "alice", pkix.Name{CommonName: "alice", Organization: []string{"acme"}}, false, nil, nil)
	bob := ca.issue(t, "bob", pkix.Name{CommonName: "bob-svc"}, false, []string{"bob.svc.local"}, nil)
	mallory := ca.issue(t, "mallory", pkix.Name{CommonName: "mallory"}, false, nil, nil)
	rogueCA := newPKI(t)
	rogue := rogueCA.issue(t, "alice-rogue", pkix.Name{CommonName: "alice", Organization: []string{"acme"}}, false, nil, nil)

	up, direct := plainUpstream(t)
	rules := []config.X509Rule{
		{Subject: "CN=alice,O=acme", TenantID: "tenant-a"},
		{SAN: "bob.svc.local", TenantID: "tenant-b"},
	}
	tlsCfg := &config.ClientTLS{CertFile: server.certFile, KeyFile: server.keyFile, ClientCAFile: ca.caFile}

	t.Run("certificate subject and SAN map to tenants", func(t *testing.T) {
		addr, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, ClientTLS: tlsCfg,
			Auth: config.Auth{Mode: "x509", X509: rules}})
		must(t, opErr(t, x509Client(addr, ca.caFile, &alice, "")))
		must(t, opErr(t, x509Client(addr, ca.caFile, &bob, "")))
		if a, b := stampedCount(t, direct, "tenant-a"), stampedCount(t, direct, "tenant-b"); a != 1 || b != 1 {
			t.Fatalf("stamped a=%d b=%d, want 1 each", a, b)
		}
		// Isolation holds for x509-authenticated clients too.
		ca1, err := mongo.Connect(x509Client(addr, ca.caFile, &alice, ""))
		must(t, err)
		defer ca1.Disconnect(context.Background())
		n, err := ca1.Database("s").Collection("c").CountDocuments(context.Background(), bson.M{})
		must(t, err)
		if n != 1 {
			t.Fatalf("alice sees %d docs, want only her own 1", n)
		}

		if err := opErr(t, x509Client(addr, ca.caFile, &mallory, "")); err == nil {
			t.Error("valid certificate without a tenant mapping was accepted")
		}
		if err := opErr(t, x509Client(addr, ca.caFile, &rogue, "")); err == nil {
			t.Error("certificate from an untrusted CA with alice's subject was accepted")
		}
		// x509 is the only mode, so mutual TLS is mandatory.
		if err := opErr(t, x509Client(addr, ca.caFile, nil, "&appName=tenant-a")); err == nil {
			t.Error("connection without a client certificate was accepted")
		}
		// The user name, when sent (the driver never does), must be the
		// certificate subject.
		raw := func(l leaf, user string) bool {
			tc, err := tls.Dial("tcp", addr, ca.tlsClientConfig(t, &l))
			must(t, err)
			defer tc.Close()
			r := &compConn{t: t, nc: tc}
			reply, _, _ := r.roundTrip(bson.D{{Key: "authenticate", Value: 1}, {Key: "mechanism", Value: "MONGODB-X509"},
				{Key: "user", Value: user}, {Key: "$db", Value: "$external"}}, 0)
			ok, _ := reply.Lookup("ok").AsInt64OK()
			return ok == 1
		}
		if raw(alice, "CN=bob-svc") {
			t.Error("authenticate with a mismatched user name was accepted")
		}
		if !raw(alice, "cn=alice, o=acme") {
			t.Error("authenticate with the matching user name was refused")
		}
		if !raw(alice, "") {
			t.Error("authenticate without a user name was refused")
		}
	})

	t.Run("combined with SCRAM", func(t *testing.T) {
		u, err := auth.NewUser("dave", "tenant-d", "dave-pw")
		must(t, err)
		addr, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, ClientTLS: tlsCfg,
			Auth: config.Auth{Mode: "scram,x509", Users: []config.User{u}, X509: rules}})
		// Certificate optional: password users connect without one...
		must(t, opErr(t, options.Client().ApplyURI(fmt.Sprintf(
			"mongodb://dave:dave-pw@%s/?authSource=admin&authMechanism=SCRAM-SHA-256&tls=true&tlsCAFile=%s", addr, url.QueryEscape(ca.caFile)))))
		// ...and certificate users authenticate with x509.
		must(t, opErr(t, x509Client(addr, ca.caFile, &alice, "")))
		if n := stampedCount(t, direct, "tenant-d"); n != 1 {
			t.Fatalf("tenant-d probes = %d", n)
		}
		// x509 without a certificate on this connection fails cleanly.
		o := options.Client().ApplyURI(fmt.Sprintf(
			"mongodb://%s/?authMechanism=MONGODB-X509&authSource=%%24external&tls=true&tlsCAFile=%s", addr, url.QueryEscape(ca.caFile)))
		if err := opErr(t, o); err == nil {
			t.Error("MONGODB-X509 without a certificate succeeded")
		}
	})

	t.Run("config requires mutual TLS", func(t *testing.T) {
		cfg := &config.Config{Upstream: config.Upstream{Addr: up}, Auth: config.Auth{Mode: "x509", X509: rules},
			ClientTLS: &config.ClientTLS{CertFile: server.certFile, KeyFile: server.keyFile}}
		path := filepath.Join(t.TempDir(), "c.json")
		raw, _ := json.Marshal(cfg)
		must(t, os.WriteFile(path, raw, 0o600))
		if _, err := config.Load(path); err == nil {
			t.Fatal("x509 without clientCAFile passed validation")
		}
	})
}

// ---- OIDC / JWT ---------------------------------------------------------------

type jwtSigner struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newSigner(t testing.TB) *jwtSigner {
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	must2(t, err)
	return &jwtSigner{rsa: r, ec: mustKey(t)}
}

func (s *jwtSigner) jwks() []byte {
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	set := map[string]any{"keys": []any{
		map[string]string{"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256",
			"n": b64(s.rsa.N.Bytes()), "e": b64(big.NewInt(int64(s.rsa.E)).Bytes())},
		map[string]string{"kty": "EC", "kid": "ec1", "use": "sig", "alg": "ES256", "crv": "P-256",
			"x": b64(pad(s.ec.X.Bytes())), "y": b64(pad(s.ec.Y.Bytes()))},
	}}
	b, _ := json.Marshal(set)
	return b
}

// token signs claims; alg is RS256, ES256, none or HS256 (the last two exist
// to prove the verifier rejects them).
func (s *jwtSigner) token(t testing.TB, alg, kid string, claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	pl, _ := json.Marshal(claims)
	signing := b64(hdr) + "." + b64(pl)
	h := sha256.Sum256([]byte(signing))
	var sig []byte
	switch alg {
	case "RS256":
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, h[:])
		must2(t, err)
	case "ES256":
		r, ss, err := ecdsa.Sign(rand.Reader, s.ec, h[:])
		must2(t, err)
		sig = append(append(make([]byte, 32-len(r.Bytes())), r.Bytes()...), append(make([]byte, 32-len(ss.Bytes())), ss.Bytes()...)...)
	case "HS256":
		// "Algorithm confusion": MAC keyed with the public key material.
		sig = []byte("forged")
	case "none":
	}
	return signing + "." + b64(sig)
}

func oidcClient(addr, token string) *options.ClientOptions {
	return options.Client().ApplyURI("mongodb://" + addr + "/").SetAuth(options.Credential{
		AuthMechanism: "MONGODB-OIDC",
		OIDCMachineCallback: func(context.Context, *options.OIDCArgs) (*options.OIDCCredential, error) {
			return &options.OIDCCredential{AccessToken: token}, nil
		},
	})
}

func TestClientOIDC(t *testing.T) {
	up, direct := plainUpstream(t)
	sg := newSigner(t)
	other := newSigner(t)
	jwks := filepath.Join(t.TempDir(), "jwks.json")
	must(t, os.WriteFile(jwks, sg.jwks(), 0o600))

	addr, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, Auth: config.Auth{
		Mode: "oidc",
		OIDC: &config.OIDC{Issuer: "https://idp.test", Audience: "mtp", JWKSFile: jwks, TenantClaim: "https://example.com/tenant"},
	}})
	now := time.Now()
	claims := func(mut func(map[string]any)) map[string]any {
		m := map[string]any{"iss": "https://idp.test", "aud": "mtp", "sub": "svc",
			"exp": now.Add(time.Hour).Unix(), "https://example.com/tenant": "tenant-a"}
		if mut != nil {
			mut(m)
		}
		return m
	}

	good := []struct{ name, tok, tenant string }{
		{"RS256", sg.token(t, "RS256", "rsa1", claims(nil)), "tenant-a"},
		{"ES256", sg.token(t, "ES256", "ec1", claims(func(m map[string]any) { m["https://example.com/tenant"] = "tenant-b" })), "tenant-b"},
		{"audience list", sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["aud"] = []string{"x", "mtp"} })), "tenant-a"},
		{"no kid", sg.token(t, "ES256", "", claims(nil)), "tenant-a"},
		{"numeric tenant", sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["https://example.com/tenant"] = 42 })), "42"},
	}
	for _, g := range good {
		t.Run("accepts "+g.name, func(t *testing.T) {
			before := stampedCount(t, direct, g.tenant)
			must(t, opErr(t, oidcClient(addr, g.tok)))
			if stampedCount(t, direct, g.tenant) != before+1 {
				t.Fatalf("write was not stamped %q", g.tenant)
			}
		})
	}

	bad := map[string]string{
		"expired":           sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() })),
		"no exp":            sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { delete(m, "exp") })),
		"not yet valid":     sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["nbf"] = now.Add(time.Hour).Unix() })),
		"wrong audience":    sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["aud"] = "other" })),
		"wrong issuer":      sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["iss"] = "https://evil.test" })),
		"missing tenant":    sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { delete(m, "https://example.com/tenant") })),
		"empty tenant":      sg.token(t, "RS256", "rsa1", claims(func(m map[string]any) { m["https://example.com/tenant"] = "" })),
		"foreign signature": other.token(t, "RS256", "rsa1", claims(nil)),
		"alg none":          sg.token(t, "none", "rsa1", claims(nil)),
		"alg HS256":         sg.token(t, "HS256", "rsa1", claims(nil)),
		"RS key for ES alg": sg.token(t, "ES256", "rsa1", claims(nil)),
		"garbage":           "not.a.jwt",
		"empty":             "",
	}
	for name, tok := range bad {
		t.Run("rejects "+name, func(t *testing.T) {
			if tok == "" {
				t.Skip("the driver refuses to send an empty token itself")
			}
			if err := opErr(t, oidcClient(addr, tok)); err == nil {
				t.Fatal("token was accepted")
			}
		})
	}

	t.Run("jwks over http", func(t *testing.T) {
		srv := serveJSON(t, sg.jwks())
		a2, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, Auth: config.Auth{
			Mode: "oidc", OIDC: &config.OIDC{Issuer: "https://idp.test", Audience: "mtp", JWKSURI: srv, TenantClaim: "https://example.com/tenant"},
		}})
		must(t, opErr(t, oidcClient(a2, sg.token(t, "RS256", "rsa1", claims(nil)))))
		if err := opErr(t, oidcClient(a2, other.token(t, "RS256", "rsa1", claims(nil)))); err == nil {
			t.Fatal("foreign key accepted via JWKS URI")
		}
	})

	t.Run("combined with SCRAM", func(t *testing.T) {
		u, err := auth.NewUser("erin", "tenant-e", "erin-pw")
		must(t, err)
		a2, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, Auth: config.Auth{
			Mode: "scram,oidc", Users: []config.User{u},
			OIDC: &config.OIDC{Issuer: "https://idp.test", Audience: "mtp", JWKSFile: jwks, TenantClaim: "https://example.com/tenant"},
		}})
		must(t, opErr(t, options.Client().ApplyURI(fmt.Sprintf("mongodb://erin:erin-pw@%s/?authSource=admin", a2))))
		must(t, opErr(t, oidcClient(a2, sg.token(t, "RS256", "rsa1", claims(nil)))))
		// OIDC is not offered on a proxy where it is not enabled.
		a3, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, Auth: config.Auth{Mode: "scram", Users: []config.User{u}}})
		if err := opErr(t, oidcClient(a3, sg.token(t, "RS256", "rsa1", claims(nil)))); err == nil {
			t.Fatal("OIDC accepted although not enabled")
		}
	})
}

// ---- upstream authentication ------------------------------------------------

func TestUpstreamSCRAMSHA1(t *testing.T) {
	up := startMongod(t, true)
	root := connect(t, fmt.Sprintf("mongodb://proxy:%s@%s/?directConnection=true&authSource=admin", upstreamPassword, up))
	defer root.Disconnect(context.Background())
	// A user that only has a SCRAM-SHA-1 credential proves the mechanism used.
	must(t, root.Database("admin").RunCommand(context.Background(), bson.D{{Key: "createUser", Value: "legacy"},
		{Key: "pwd", Value: "legacy-pw"}, {Key: "mechanisms", Value: bson.A{"SCRAM-SHA-1"}},
		{Key: "roles", Value: bson.A{"root"}}}).Err())

	mk := func(mech string) *config.Config {
		return &config.Config{Auth: config.Auth{Mode: "appname"}, Tenant: config.Tenant{Field: "tenantId"},
			Upstream: config.Upstream{Addr: up, Username: "legacy", Password: "legacy-pw", AuthMechanism: mech}, MaxMessageBytes: 48 << 20}
	}
	if _, err := proxy.New(mk("SCRAM-SHA-256"), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("SCRAM-SHA-256 worked for a SHA-1-only user: the test would prove nothing")
	}
	addr, _ := startProxy(t, mk("SCRAM-SHA-1"))
	c := connect(t, fmt.Sprintf("mongodb://%s/?appName=tenant-a", addr))
	defer c.Disconnect(context.Background())
	_, err := c.Database("s").Collection("c").InsertOne(context.Background(), bson.M{"v": 1})
	must(t, err)
	n, err := root.Database("s").Collection("c").CountDocuments(context.Background(), bson.M{"tenantId": "tenant-a"})
	must(t, err)
	if n != 1 {
		t.Fatalf("stamped docs = %d", n)
	}
}

func TestUpstreamX509(t *testing.T) {
	ca := newPKI(t)
	server := ca.issue(t, "mongod", pkix.Name{CommonName: "localhost"}, true, nil, nil)
	subject := pkix.Name{CommonName: "proxy-x509", Organization: []string{"mtp"}}
	proxyCert := ca.issue(t, "proxy-x509", subject, false, nil, nil)
	stranger := ca.issue(t, "stranger", pkix.Name{CommonName: "stranger"}, false, nil, nil)
	addr, rootURI := startMongodTLS(t, mongodOpts{tls: ca, server: &server, x509User: "CN=proxy-x509,O=mtp"})

	mk := func(l leaf) *config.Config {
		return &config.Config{Auth: config.Auth{Mode: "appname"}, Tenant: config.Tenant{Field: "tenantId"}, MaxMessageBytes: 48 << 20,
			Upstream: config.Upstream{Addr: addr, TLS: true, CAFile: ca.caFile, CertFile: l.certFile, KeyFile: l.keyFile,
				AuthMechanism: "MONGODB-X509"}}
	}
	if _, err := proxy.New(mk(stranger), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("a certificate with no matching mongod user authenticated")
	}
	paddr, _ := startProxy(t, mk(proxyCert))
	c := connect(t, fmt.Sprintf("mongodb://%s/?appName=tenant-x", paddr))
	defer c.Disconnect(context.Background())
	_, err := c.Database("s").Collection("c").InsertOne(context.Background(), bson.M{"v": 1})
	must(t, err)
	root := connect(t, rootURI)
	defer root.Disconnect(context.Background())
	n, err := root.Database("s").Collection("c").CountDocuments(context.Background(), bson.M{"tenantId": "tenant-x"})
	must(t, err)
	if n != 1 {
		t.Fatalf("stamped docs = %d", n)
	}
}
