package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xdg-go/scram"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type rsaKey struct {
	kid string
	key *rsa.PrivateKey
}

func newRSA(t *testing.T, kid string) rsaKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return rsaKey{kid, k}
}

func jwksOf(keys ...rsaKey) []byte {
	var ks []any
	for _, k := range keys {
		ks = append(ks, map[string]string{"kty": "RSA", "kid": k.kid, "n": b64(k.key.N.Bytes()), "e": b64(big.NewInt(int64(k.key.E)).Bytes())})
	}
	b, _ := json.Marshal(map[string]any{"keys": ks})
	return b
}

func (k rsaKey) sign(t *testing.T, claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": k.kid})
	pl, _ := json.Marshal(claims)
	in := b64(hdr) + "." + b64(pl)
	h := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func TestJWKSRotationAndRefresh(t *testing.T) {
	k1, k2 := newRSA(t, "k1"), newRSA(t, "k2")
	path := filepath.Join(t.TempDir(), "jwks.json")
	os.WriteFile(path, jwksOf(k1), 0o600)
	v, err := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSFile: path})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "i", "aud": "a", "exp": time.Now().Add(time.Hour).Unix(), "tenant": "t1"}
	if got, err := v.Verify(k1.sign(t, claims), time.Now()); err != nil || got != "t1" {
		t.Fatalf("k1: %q %v", got, err)
	}
	// New key published, but the retry limiter holds the reload back...
	os.WriteFile(path, jwksOf(k1, k2), 0o600)
	if _, err := v.Verify(k2.sign(t, claims), time.Now()); err == nil {
		t.Fatal("unknown kid refreshed immediately: JWKS endpoint can be hammered")
	}
	// ...until the minimum interval has passed.
	v.mu.Lock()
	v.lastTry = time.Now().Add(-2 * minJWKSRetry)
	v.mu.Unlock()
	if got, err := v.Verify(k2.sign(t, claims), time.Now()); err != nil || got != "t1" {
		t.Fatalf("k2 after rotation: %q %v", got, err)
	}
}

func TestVerifyClockSkewAndClaims(t *testing.T) {
	k := newRSA(t, "k")
	path := filepath.Join(t.TempDir(), "jwks.json")
	os.WriteFile(path, jwksOf(k), 0o600)
	v, _ := newOIDCVerifier(&config.OIDC{Issuer: "i", Audience: "a", JWKSFile: path, ClockSkew: "10s", TenantClaim: "org.id"})
	now := time.Now()
	mk := func(exp time.Time) string {
		return k.sign(t, map[string]any{"iss": "i", "aud": "a", "exp": exp.Unix(), "org": map[string]any{"id": "nested"}})
	}
	if got, err := v.Verify(mk(now.Add(-5*time.Second)), now); err != nil || got != "nested" {
		t.Fatalf("within skew (dotted claim path): %q %v", got, err)
	}
	if _, err := v.Verify(mk(now.Add(-30*time.Second)), now); err == nil {
		t.Fatal("token expired beyond skew accepted")
	}
}

func TestParseJWKSRejectsWeakAndMalformed(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	weak, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "n": b64(small.N.Bytes()), "e": "AQAB"}}})
	if _, err := ParseJWKS(weak); err == nil {
		t.Error("1024-bit RSA key accepted")
	}
	if _, err := ParseJWKS([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}]}`)); err == nil {
		t.Error("EC point not on curve accepted")
	}
	if _, err := ParseJWKS([]byte(`nope`)); err == nil {
		t.Error("non-JSON accepted")
	}
}

func TestSHA1Credential(t *testing.T) {
	cred, err := NewSHA1Credential("bob", "pw")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(config.Auth{Mode: "scram-sha-1", Users: []config.User{{Username: "bob", TenantID: "t", SHA1: cred}}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(password string) error {
		client, _ := scram.SHA1.NewClient("bob", SHA1Password("bob", password), "")
		conv := client.NewConversation()
		first, _ := conv.Step("")
		s, out, err := a.StartSASL(MechSCRAM1, []byte(first), true)
		if err != nil {
			return err
		}
		final, err := conv.Step(string(out))
		if err != nil {
			return err
		}
		out, done, err := s.Continue([]byte(final))
		if err != nil {
			return err
		}
		if _, err := conv.Step(string(out)); err != nil || !conv.Valid() || !done || s.Tenant() != "t" {
			return ErrAuthFailed
		}
		return nil
	}
	if err := run("pw"); err != nil {
		t.Fatalf("correct password: %v", err)
	}
	if err := run("wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, _, err := a.StartSASL(MechSCRAM256, []byte("n,,n=bob,r=x"), true); err != ErrMechanismUnavailable {
		t.Fatalf("SCRAM-SHA-256 on a SHA-1-only proxy: %v", err)
	}
	// The MD5 digest is the documented legacy form.
	if got := SHA1Password("user", "pencil"); got != "1c33006ec1ffd90f9cadcbcc0e118200" {
		t.Fatalf("digest %q", got)
	}
}

func TestSupportedMechs(t *testing.T) {
	both, _ := NewUser("both", "t", "p")
	both.SHA1, _ = NewSHA1Credential("both", "p")
	legacy := config.User{Username: "legacy", TenantID: "t"}
	legacy.SHA1, _ = NewSHA1Credential("legacy", "p")
	a, err := New(config.Auth{Mode: "scram,scram-sha-1", Users: []config.User{both, legacy}})
	if err != nil {
		t.Fatal(err)
	}
	for who, want := range map[string]string{
		"admin.both": "SCRAM-SHA-256,SCRAM-SHA-1", "admin.legacy": "SCRAM-SHA-1", "x.unknown": "SCRAM-SHA-256,SCRAM-SHA-1",
	} {
		got := ""
		for i, m := range a.SupportedMechs(who) {
			if i > 0 {
				got += ","
			}
			got += m
		}
		if got != want {
			t.Errorf("%s: %q want %q", who, got, want)
		}
	}
}
