package auth

// Attacks on the authentication layer: JWT forgery and abuse, JWKS fetching,
// certificate identity spoofing, SCRAM user enumeration and appName forgery.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xdg-go/scram"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func oidcFixture(t *testing.T, mutate func(*config.OIDC)) (*oidcVerifier, rsaKey) {
	t.Helper()
	k := newRSA(t, "kid1")
	path := filepath.Join(t.TempDir(), "jwks.json")
	os.WriteFile(path, jwksOf(k), 0o600)
	c := &config.OIDC{Issuer: "https://idp", Audience: "mtp", JWKSFile: path, ClockSkew: "5s"}
	if mutate != nil {
		mutate(c)
	}
	v, err := newOIDCVerifier(c)
	if err != nil {
		t.Fatal(err)
	}
	return v, k
}

func goodClaims() map[string]any {
	return map[string]any{"iss": "https://idp", "aud": "mtp", "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(), "tenant": "tenant-a"}
}

func unsigned(hdr, claims map[string]any, sig string) string {
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	return b64(h) + "." + b64(c) + "." + sig
}

func TestJWTForgeries(t *testing.T) {
	v, k := oidcFixture(t, nil)
	now := time.Now()
	if got, err := v.Verify(k.sign(t, goodClaims()), now); err != nil || got != "tenant-a" {
		t.Fatalf("baseline token rejected: %q %v", got, err)
	}

	// HS256 "signed" with the RSA public key bytes as the HMAC secret: the
	// classic algorithm-confusion attack.
	pubDER := x509.MarshalPKCS1PublicKey(&k.key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubDER})
	hsSigned := func(secret []byte, alg string) string {
		hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": "kid1"})
		cl, _ := json.Marshal(goodClaims())
		in := b64(hdr) + "." + b64(cl)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(in))
		return in + "." + b64(m.Sum(nil))
	}
	other := newRSA(t, "kid1") // same kid, attacker's own key
	forged := other.sign(t, goodClaims())

	rsaN := b64(k.key.N.Bytes())
	cases := map[string]string{
		"alg none, empty signature":      unsigned(map[string]any{"alg": "none", "kid": "kid1"}, goodClaims(), ""),
		"alg None":                       unsigned(map[string]any{"alg": "None", "kid": "kid1"}, goodClaims(), ""),
		"alg NONE with junk signature":   unsigned(map[string]any{"alg": "NONE"}, goodClaims(), "AAAA"),
		"empty alg":                      unsigned(map[string]any{"alg": ""}, goodClaims(), "AAAA"),
		"missing alg":                    unsigned(map[string]any{"kid": "kid1"}, goodClaims(), "AAAA"),
		"HS256 keyed with public PEM":    hsSigned(pubPEM, "HS256"),
		"HS256 keyed with public DER":    hsSigned(pubDER, "HS256"),
		"HS256 keyed with modulus":       hsSigned([]byte(rsaN), "HS256"),
		"HS384":                          hsSigned(pubPEM, "HS384"),
		"RS256 signed by another key":    forged,
		"signature stripped":             strings.Join(strings.Split(k.sign(t, goodClaims()), ".")[:2], ".") + ".",
		"two segments":                   "a.b",
		"four segments":                  k.sign(t, goodClaims()) + ".x",
		"empty":                          "",
		"dots":                           "..",
		"huge token":                     strings.Repeat("A", 1<<20) + ".b.c",
		"alg header wrong type":          unsigned(map[string]any{"alg": 7}, goodClaims(), "AAAA"),
		"embedded jwk header ignored":    unsigned(map[string]any{"alg": "RS256", "jwk": map[string]string{"kty": "RSA", "n": b64(other.key.N.Bytes()), "e": "AQAB"}}, goodClaims(), b64(make([]byte, 256))),
		"jku header ignored":             unsigned(map[string]any{"alg": "RS256", "jku": "http://169.254.169.254/"}, goodClaims(), b64(make([]byte, 256))),
		"RS256 with ES-length signature": unsigned(map[string]any{"alg": "ES256"}, goodClaims(), b64(make([]byte, 64))),
	}
	for name, tok := range cases {
		if got, err := v.Verify(tok, now); err == nil {
			t.Errorf("%s: token accepted as tenant %q", name, got)
		}
	}
	// A different "alg" header on a token signed with RS256 must not verify
	// (the signature is over the exact header segment, so this just proves
	// there is no downgrade path to a weaker hash).
	hdr, _ := json.Marshal(map[string]string{"alg": "RS512", "kid": "kid1"})
	pl, _ := json.Marshal(goodClaims())
	in := b64(hdr) + "." + b64(pl)
	h := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, h[:])
	if _, err := v.Verify(in+"."+b64(sig), now); err == nil {
		t.Error("RS512 header over an RS256 signature accepted")
	}
}

func TestJWTKidInjection(t *testing.T) {
	v, k := oidcFixture(t, nil)
	for _, kid := range []string{"../../etc/passwd", "kid1' OR '1'='1", "kid1\x00evil", strings.Repeat("k", 100000), "*", "{}", "kid1/../kid1"} {
		hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
		cl, _ := json.Marshal(goodClaims())
		in := b64(hdr) + "." + b64(cl)
		h := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, h[:])
		// The kid only selects among configured keys; a kid that names none of
		// them must not fall back to "try everything" for a file-backed set
		// and, above all, must not be interpreted by anything.
		_, err := v.Verify(in+"."+b64(sig), time.Now())
		if err == nil {
			t.Errorf("kid %.20q: token with unknown kid accepted", kid)
		}
	}
}

func TestJWTClaimAttacks(t *testing.T) {
	v, k := oidcFixture(t, nil)
	now := time.Now()
	mod := func(f func(map[string]any)) string {
		c := goodClaims()
		f(c)
		return k.sign(t, c)
	}
	for name, tok := range map[string]string{
		"expired":                  mod(func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }),
		"expired just beyond skew": mod(func(c map[string]any) { c["exp"] = now.Add(-10 * time.Second).Unix() }),
		"no exp":                   mod(func(c map[string]any) { delete(c, "exp") }),
		"exp as string":            mod(func(c map[string]any) { c["exp"] = "9999999999" }),
		"exp null":                 mod(func(c map[string]any) { c["exp"] = nil }),
		"nbf in the future":        mod(func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }),
		"iat in the future":        mod(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }),
		"wrong issuer":             mod(func(c map[string]any) { c["iss"] = "https://evil" }),
		"issuer prefix":            mod(func(c map[string]any) { c["iss"] = "https://idp.evil" }),
		"no issuer":                mod(func(c map[string]any) { delete(c, "iss") }),
		"wrong audience":           mod(func(c map[string]any) { c["aud"] = "other" }),
		"audience list miss":       mod(func(c map[string]any) { c["aud"] = []string{"a", "b"} }),
		"audience number":          mod(func(c map[string]any) { c["aud"] = 5 }),
		"no audience":              mod(func(c map[string]any) { delete(c, "aud") }),
		"no tenant":                mod(func(c map[string]any) { delete(c, "tenant") }),
		"empty tenant":             mod(func(c map[string]any) { c["tenant"] = "" }),
		"tenant as object":         mod(func(c map[string]any) { c["tenant"] = map[string]string{"x": "y"} }),
		"tenant as list":           mod(func(c map[string]any) { c["tenant"] = []string{"tenant-a", "tenant-b"} }),
		"tenant fractional":        mod(func(c map[string]any) { c["tenant"] = 1.5 }),
		"tenant too long":          mod(func(c map[string]any) { c["tenant"] = strings.Repeat("t", 257) }),
	} {
		if got, err := v.Verify(tok, now); err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
	// Right audience in a list is fine; skew is honoured at the edge.
	if got, err := v.Verify(mod(func(c map[string]any) { c["aud"] = []string{"x", "mtp"} }), now); err != nil || got != "tenant-a" {
		t.Errorf("audience list with match: %q %v", got, err)
	}
	if _, err := v.Verify(mod(func(c map[string]any) { c["exp"] = now.Add(-3 * time.Second).Unix() }), now); err != nil {
		t.Errorf("expiry within skew rejected: %v", err)
	}
	// A claim that merely contains the claim name must not satisfy it.
	if got, err := v.Verify(mod(func(c map[string]any) { delete(c, "tenant"); c["tenant.x"] = "t" }), now); err == nil {
		t.Errorf("claim confusion accepted %q", got)
	}
}

// Replay: a bearer token is valid until it expires; nothing in the proxy can
// change that, but a captured token must not outlive its expiry, and every
// use is authenticated afresh.
func TestJWTReplayStopsAtExpiry(t *testing.T) {
	v, k := oidcFixture(t, nil)
	now := time.Now()
	tok := k.sign(t, func() map[string]any { c := goodClaims(); c["exp"] = now.Add(2 * time.Second).Unix(); return c }())
	if _, err := v.Verify(tok, now); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok, now.Add(time.Second)); err != nil {
		t.Fatal("token valid until exp must verify repeatedly")
	}
	if _, err := v.Verify(tok, now.Add(time.Minute)); err == nil {
		t.Fatal("replayed token accepted after expiry")
	}
}

func jwksServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	var hits atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s, &hits
}

func TestJWKSFetchHardening(t *testing.T) {
	k := newRSA(t, "kid1")
	good := jwksOf(k)

	t.Run("redirects are not followed (SSRF)", func(t *testing.T) {
		var internalHit atomic.Int64
		internal, _ := jwksServer(t, func(w http.ResponseWriter, r *http.Request) { internalHit.Add(1); w.Write(good) })
		redir, _ := jwksServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL, http.StatusFound)
		})
		v, err := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSURI: redir.URL})
		if err != nil {
			t.Fatal(err)
		}
		if err := v.reload(); err == nil {
			t.Fatal("JWKS fetch followed a redirect")
		}
		if internalHit.Load() != 0 {
			t.Fatal("the redirect target was contacted")
		}
	})
	t.Run("oversized response is cut off", func(t *testing.T) {
		big, _ := jwksServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"keys":[`))
			for i := 0; i < 1<<20; i++ { // would be tens of MiB
				if _, err := w.Write([]byte(`{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},`)); err != nil {
					return
				}
			}
		})
		v, _ := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSURI: big.URL})
		if err := v.reload(); err == nil {
			t.Fatal("oversized JWKS accepted")
		}
	})
	t.Run("non-200 and garbage keep the old keys", func(t *testing.T) {
		var mode atomic.Int32
		srv, _ := jwksServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch mode.Load() {
			case 0:
				w.Write(good)
			case 1:
				http.Error(w, "boom", 500)
			default:
				w.Write([]byte("<html>"))
			}
		})
		v, _ := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSURI: srv.URL})
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(v.reload())
		mode.Store(1)
		if v.reload() == nil {
			t.Fatal("500 accepted")
		}
		mode.Store(2)
		if v.reload() == nil {
			t.Fatal("garbage accepted")
		}
		if got, err := v.Verify(k.sign(t, goodClaims2("i", "a")), time.Now()); err != nil || got != "tenant-a" {
			t.Fatalf("keys lost after failed refresh: %q %v", got, err)
		}
	})
	t.Run("slow server times out", func(t *testing.T) {
		srv, _ := jwksServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(3 * time.Second) })
		v, _ := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSURI: srv.URL})
		v.client.Timeout = 300 * time.Millisecond
		start := time.Now()
		if v.reload() == nil {
			t.Fatal("expected a timeout")
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("slow JWKS server held the verifier")
		}
	})
	t.Run("forged tokens cannot make the proxy hammer the IdP", func(t *testing.T) {
		srv, hits := jwksServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(200 * time.Millisecond); w.Write(good) })
		v, _ := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSURI: srv.URL})
		var wg sync.WaitGroup
		for i := 0; i < 60; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": fmt.Sprintf("unknown-%d", i)})
				v.Verify(b64(hdr)+"."+b64([]byte("{}"))+"."+b64([]byte("sig")), time.Now())
			}(i)
		}
		wg.Wait()
		if n := hits.Load(); n > 2 {
			t.Fatalf("60 concurrent forged tokens caused %d JWKS fetches (the first load, plus at most one refresh)", n)
		}
	})
}

func goodClaims2(iss, aud string) map[string]any {
	c := goodClaims()
	c["iss"], c["aud"] = iss, aud
	return c
}

func TestECDSAAlgorithmConfusion(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jw, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "kid": "e1",
		"x": b64(ek.X.Bytes()), "y": b64(ek.Y.Bytes())}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	os.WriteFile(path, jw, 0o600)
	v, err := newOIDCVerifier(&config.OIDC{Issuer: "https://idp", Audience: "mtp", JWKSFile: path})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(alg string, h crypto.Hash) string {
		hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": "e1"})
		cl, _ := json.Marshal(goodClaims())
		in := b64(hdr) + "." + b64(cl)
		hh := h.New()
		hh.Write([]byte(in))
		r, s, _ := ecdsa.Sign(rand.Reader, ek, hh.Sum(nil))
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return in + "." + b64(sig)
	}
	if got, err := v.Verify(sign("ES256", crypto.SHA256), time.Now()); err != nil || got != "tenant-a" {
		t.Fatalf("ES256: %q %v", got, err)
	}
	// A P-256 key must not verify as ES384/ES512 or as an RSA algorithm.
	for _, alg := range []string{"ES384", "ES512", "RS256", "PS256"} {
		if _, err := v.Verify(sign(alg, crypto.SHA256), time.Now()); err == nil {
			t.Errorf("P-256 key accepted for %s", alg)
		}
	}
}

// ---- certificates ------------------------------------------------------------

func certState(t *testing.T, subj pkix.Name, dns []string, emails []string, verified bool) *tls.ConnectionState {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: subj, DNSNames: dns, EmailAddresses: emails,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	st := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	if verified {
		st.VerifiedChains = [][]*x509.Certificate{{c}}
	}
	return st
}

func x509Auth(t *testing.T, rules ...config.X509Rule) *Authenticator {
	a, err := New(config.Auth{Mode: "x509", X509: rules})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestX509IdentitySpoofing(t *testing.T) {
	a := x509Auth(t,
		config.X509Rule{Subject: "CN=alice,OU=acme,O=corp", TenantID: "tenant-a"},
		config.X509Rule{SAN: "bob.corp.example", TenantID: "tenant-b"},
	)
	if got, err := a.X509(certState(t, pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"acme"}, Organization: []string{"corp"}}, nil, nil, true), ""); err != nil || got != "tenant-a" {
		// pkix renders most-specific last: CN=alice,OU=acme,O=corp
		t.Fatalf("legitimate subject: %q %v", got, err)
	}
	if got, err := a.X509(certState(t, pkix.Name{CommonName: "whatever"}, []string{"bob.corp.example"}, nil, true), ""); err != nil || got != "tenant-b" {
		t.Fatalf("legitimate SAN: %q %v", got, err)
	}

	reject := map[string]*tls.ConnectionState{
		"chain not verified":              certState(t, pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"acme"}, Organization: []string{"corp"}}, nil, nil, false),
		"no certificate":                  {},
		"CN with comma injection":         certState(t, pkix.Name{CommonName: "alice,OU=acme,O=corp"}, nil, nil, true),
		"CN with escaped comma injection": certState(t, pkix.Name{CommonName: `alice\,OU=acme\,O=corp`}, nil, nil, true),
		"case-different CN":               certState(t, pkix.Name{CommonName: "ALICE", OrganizationalUnit: []string{"acme"}, Organization: []string{"corp"}}, nil, nil, true),
		"extra RDN":                       certState(t, pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"acme", "extra"}, Organization: []string{"corp"}}, nil, nil, true),
		"SAN as substring":                certState(t, pkix.Name{CommonName: "x"}, []string{"evilbob.corp.example"}, nil, true),
		"SAN as suffix":                   certState(t, pkix.Name{CommonName: "x"}, []string{"bob.corp.example.evil.com"}, nil, true),
		"SAN wildcard":                    certState(t, pkix.Name{CommonName: "x"}, []string{"*.corp.example"}, nil, true),
		"SAN only in subject CN":          certState(t, pkix.Name{CommonName: "bob.corp.example"}, nil, nil, true),
	}
	for name, st := range reject {
		if got, err := a.X509(st, ""); err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
	// The user named in the authenticate command must be the certificate's.
	st := certState(t, pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"acme"}, Organization: []string{"corp"}}, nil, nil, true)
	if _, err := a.X509(st, "CN=bob,OU=acme,O=corp"); err == nil {
		t.Error("authenticate user naming another subject accepted")
	}
	// Rule order must not be a tenant boundary: a certificate matching rules
	// of two tenants is refused.
	amb := x509Auth(t,
		config.X509Rule{Subject: "CN=carol", TenantID: "tenant-a"},
		config.X509Rule{SAN: "carol.example", TenantID: "tenant-b"},
	)
	if got, err := amb.X509(certState(t, pkix.Name{CommonName: "carol"}, []string{"carol.example"}, nil, true), ""); err == nil {
		t.Errorf("ambiguous certificate resolved to %q", got)
	}
	// Two rules for the same tenant agree, which is fine.
	same := x509Auth(t,
		config.X509Rule{Subject: "CN=carol", TenantID: "tenant-a"},
		config.X509Rule{SAN: "carol.example", TenantID: "tenant-a"},
	)
	if got, err := same.X509(certState(t, pkix.Name{CommonName: "carol"}, []string{"carol.example"}, nil, true), ""); err != nil || got != "tenant-a" {
		t.Errorf("agreeing rules: %q %v", got, err)
	}
}

// ---- SCRAM ---------------------------------------------------------------------

func scramAuth(t *testing.T) *Authenticator {
	u, err := NewUser("alice", "tenant-a", "alice-pw")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(config.Auth{Mode: "scram", Users: []config.User{u}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// scramFirst runs the client-first message and returns the server-first.
func scramFirst(t *testing.T, a *Authenticator, user, nonce string) (*SASL, string) {
	t.Helper()
	s, out, err := a.StartSASL(MechSCRAM256, []byte("n,,n="+user+",r="+nonce), false)
	if err != nil {
		t.Fatalf("saslStart for %q failed at the first message: %v", user, err)
	}
	return s, string(out)
}

func parseServerFirst(t *testing.T, s string) (salt string, iters string) {
	for _, kv := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(kv, "s="):
			salt = kv[2:]
		case strings.HasPrefix(kv, "i="):
			iters = kv[2:]
		}
	}
	if salt == "" || iters == "" {
		t.Fatalf("malformed server-first %q", s)
	}
	return
}

// Unknown users must be indistinguishable from known ones until the proof
// fails: same message shape, a stable salt (a random one per attempt would
// give them away) and the same iteration count.
func TestSCRAMUserEnumeration(t *testing.T) {
	a := scramAuth(t)
	_, known := scramFirst(t, a, "alice", "clientnonce1")
	ksalt, kiters := parseServerFirst(t, known)
	_, ghost1 := scramFirst(t, a, "ghost", "clientnonce1")
	_, ghost2 := scramFirst(t, a, "ghost", "clientnonce2")
	_, other := scramFirst(t, a, "nobody", "clientnonce1")
	g1s, g1i := parseServerFirst(t, ghost1)
	g2s, g2i := parseServerFirst(t, ghost2)
	os_, _ := parseServerFirst(t, other)
	if g1s != g2s {
		t.Error("unknown user's salt changes between attempts: user enumeration oracle")
	}
	if g1s == os_ {
		t.Error("distinct unknown users share a salt")
	}
	if len(g1s) != len(ksalt) || g1i != kiters || g2i != kiters {
		t.Errorf("unknown user's challenge differs in shape: salt %d vs %d bytes, iterations %s vs %s", len(g1s), len(ksalt), g1i, kiters)
	}
	// Finishing the conversation as an unknown user fails exactly like a
	// wrong password, whatever proof is sent.
	for _, user := range []string{"ghost", "alice"} {
		s, first := scramFirst(t, a, user, "nonce")
		_ = first
		_, done, err := s.Continue([]byte("c=biws,r=nonce,p=AAAA"))
		if err == nil || done {
			t.Errorf("%s: bogus proof accepted", user)
		}
		if s.Authenticated() {
			t.Errorf("%s: authenticated without the password", user)
		}
	}
	// And the real password still works.
	cl, _ := scram.SHA256.NewClient("alice", "alice-pw", "")
	conv := cl.NewConversation()
	first, _ := conv.Step("")
	s, sf, err := a.StartSASL(MechSCRAM256, []byte(first), false)
	if err != nil {
		t.Fatal(err)
	}
	final, _ := conv.Step(string(sf))
	out, _, err := s.Continue([]byte(final))
	if err != nil || s.Tenant() != "tenant-a" {
		t.Fatalf("legitimate login failed: %v (tenant %q)", err, s.Tenant())
	}
	if _, err := conv.Step(string(out)); err != nil {
		t.Fatalf("server signature rejected: %v", err)
	}
}

// A user who has no SHA-1 credential cannot be authenticated by asking for
// SCRAM-SHA-1 (downgrade), and a deployment without SHA-1 does not offer it.
func TestSCRAMDowngrade(t *testing.T) {
	a := scramAuth(t)
	if _, _, err := a.StartSASL(MechSCRAM1, []byte("n,,n=alice,r=x"), false); err != ErrMechanismUnavailable {
		t.Fatalf("SCRAM-SHA-1 offered by a SHA-256-only deployment: %v", err)
	}
	for _, mech := range []string{"PLAIN", "MONGODB-CR", "SCRAM-SHA-512", "", "scram-sha-256", MechX509, MechOIDC} {
		if _, _, err := a.StartSASL(mech, []byte("n,,n=alice,r=x"), false); err == nil {
			t.Errorf("mechanism %q accepted", mech)
		}
	}
	// Both enabled; alice only has a SHA-256 credential.
	u, _ := NewUser("alice", "tenant-a", "pw")
	u2, _ := NewUser("legacy", "tenant-a", "pw")
	sha1, _ := NewSHA1Credential("legacy", "pw")
	u2.SHA1 = sha1
	b, err := New(config.Auth{Mode: "scram,scram-sha-1", Users: []config.User{u, u2}})
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := b.StartSASL(MechSCRAM1, []byte("n,,n=alice,r=x"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Continue([]byte("c=biws,r=x,p=AAAA")); err == nil || s.Authenticated() {
		t.Fatal("alice authenticated over SCRAM-SHA-1 without a SHA-1 credential")
	}
}

// Replaying a recorded client-final message into a fresh conversation (same
// client nonce, same user) fails: the server nonce is fresh per conversation.
func TestSCRAMReplay(t *testing.T) {
	a := scramAuth(t)
	cl, _ := scram.SHA256.NewClient("alice", "alice-pw", "")
	conv := cl.NewConversation()
	first, _ := conv.Step("")
	s, sf, err := a.StartSASL(MechSCRAM256, []byte(first), false)
	if err != nil {
		t.Fatal(err)
	}
	final, _ := conv.Step(string(sf))
	if _, _, err := s.Continue([]byte(final)); err != nil {
		t.Fatal(err)
	}
	// Attacker replays both captured messages.
	s2, _, err := a.StartSASL(MechSCRAM256, []byte(first), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s2.Continue([]byte(final)); err == nil || s2.Authenticated() {
		t.Fatal("replayed client-final accepted")
	}
	// Continuing a finished conversation is not a second login.
	if _, done, _ := s.Continue([]byte(final)); !done {
		t.Fatal("finished conversation should only acknowledge")
	}
}

func TestSCRAMMalformedPayloads(t *testing.T) {
	a := scramAuth(t)
	for _, p := range [][]byte{nil, {}, []byte("n,,"), []byte("y,,n=alice,r=x"), []byte("p=tls-unique,,n=alice,r=x"),
		[]byte("n,,n=,r=x"), []byte("n,,r=x"), []byte("n,,n=alice"), []byte("n,,n=alice,r="), []byte(strings.Repeat("A", 1<<20)),
		[]byte("n,,n=alice,r=x,\x00"), []byte("\xff\xfe"), []byte("n,a=admin,n=alice,r=x"), []byte("m=ext,n,,n=alice,r=x"),
		[]byte("n,,n=" + strings.Repeat("a", 1<<16) + ",r=x")} {
		s, _, err := a.StartSASL(MechSCRAM256, p, false)
		if err != nil {
			continue
		}
		// Whatever the first message made of it, the conversation cannot finish.
		for _, fin := range []string{"", "c=biws", "c=biws,r=x,p=", "c=biws,r=x,p=AAAA", strings.Repeat("Z", 1<<16)} {
			if _, done, err := s.Continue([]byte(fin)); err == nil && done {
				t.Errorf("payload %.20q + %.10q completed a login", p, fin)
			}
			if s.Authenticated() {
				t.Errorf("payload %.20q authenticated", p)
			}
		}
	}
}

// ---- appName ----------------------------------------------------------------------

func TestAppNameForgery(t *testing.T) {
	const secret = "s3cret-s3cret"
	a, err := New(config.Auth{Mode: "appname", AppNameSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	good := SignTenant(secret, "tenant-a")
	if got, err := a.ResolveAppName(good); err != nil || got != "tenant-a" {
		t.Fatalf("valid appName: %q %v", got, err)
	}
	macOf := func(s string) string { return s[strings.LastIndexByte(s, '.')+1:] }
	mac := macOf(good)
	bad := []string{
		"", ".", "tenant-a", "tenant-a.", ".abc", "tenant-a." + mac[:31], "tenant-a." + mac[:1], "tenant-a." + mac + "0",
		"tenant-a." + strings.ToUpper(mac), "tenant-a." + strings.Repeat("0", 32), "tenant-b." + mac,
		"tenant-a.tenant-a", "tenant-a..", "tenant-a." + mac + ".", SignTenant("wrong-secret", "tenant-a"),
		SignTenant(secret, "tenant-b")[:len("tenant-b.")] + mac, "tenant-a\x00." + mac, "tenant-a." + mac + "\x00",
		strings.Repeat("a", 1<<16) + "." + mac,
		// The tenant may itself contain dots; the MAC is the last segment, so
		// a signed "a.b" is not a signed "a".
		"tenant." + macOf(SignTenant(secret, "tenant.a")),
	}
	for _, name := range bad {
		if got, err := a.ResolveAppName(name); err == nil {
			t.Errorf("forged appName %.40q accepted as %q", name, got)
		}
	}
	// Dots in tenant ids work when signed correctly.
	if got, err := a.ResolveAppName(SignTenant(secret, "org.team")); err != nil || got != "org.team" {
		t.Errorf("dotted tenant: %q %v", got, err)
	}
	// Secret rotation takes effect immediately.
	a.SetAppNameSecret("new-secret")
	if _, err := a.ResolveAppName(good); err == nil {
		t.Error("old secret still honoured after rotation")
	}
	// Removing the secret means unsigned names are accepted (documented, and
	// warned about at startup); an empty name never is.
	a.SetAppNameSecret("")
	if _, err := a.ResolveAppName(""); err == nil {
		t.Error("empty appName accepted without a secret")
	}
}

// ---- brute force --------------------------------------------------------------------

func TestThrottle(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	th := NewThrottle(3, time.Minute, 10*time.Second)
	th.SetClock(func() time.Time { return now })
	for i := 0; i < 2; i++ {
		th.Fail("1.2.3.4")
		if ok, _ := th.Allowed("1.2.3.4"); !ok {
			t.Fatalf("locked after %d failures (limit 3)", i+1)
		}
	}
	th.Fail("1.2.3.4")
	if ok, wait := th.Allowed("1.2.3.4"); ok || wait <= 0 || wait > 10*time.Second {
		t.Fatalf("not locked after 3 failures: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := th.Allowed("5.6.7.8"); !ok {
		t.Fatal("another address is locked out too")
	}
	now = now.Add(11 * time.Second)
	if ok, _ := th.Allowed("1.2.3.4"); !ok {
		t.Fatal("still locked after the lockout elapsed")
	}
	// A repeat offender is locked longer each time.
	for i := 0; i < 3; i++ {
		th.Fail("1.2.3.4")
	}
	if ok, wait := th.Allowed("1.2.3.4"); ok || wait <= 10*time.Second {
		t.Fatalf("second lockout should be longer: ok=%v wait=%v", ok, wait)
	}
	// Failures spread outside the window do not accumulate.
	slow := NewThrottle(3, time.Minute, time.Minute)
	slow.SetClock(func() time.Time { return now })
	for i := 0; i < 20; i++ {
		slow.Fail("slow")
		now = now.Add(40 * time.Second)
	}
	if ok, _ := slow.Allowed("slow"); !ok {
		t.Fatal("a slow trickle of failures locked the key out")
	}
	// Bounded memory: rotating keys cannot grow the table without limit.
	small := NewThrottle(3, time.Minute, time.Minute)
	small.cap = 100
	for i := 0; i < 10000; i++ {
		small.Fail(fmt.Sprint("k", i))
	}
	if small.Len() > 100 {
		t.Fatalf("table grew to %d entries (cap 100)", small.Len())
	}
	// A nil throttle (disabled) never blocks.
	var off *Throttle
	off.Fail("x")
	if ok, _ := off.Allowed("x"); !ok {
		t.Fatal("disabled throttle blocked")
	}
}
