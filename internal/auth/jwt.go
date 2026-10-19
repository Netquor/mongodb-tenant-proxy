package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // register hashes for crypto.Hash.New
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

// oidcVerifier validates JWTs for MONGODB-OIDC and extracts the tenant claim.
type oidcVerifier struct {
	cfg     config.OIDC
	claim   string
	skew    time.Duration
	refresh time.Duration
	client  *http.Client

	mu        sync.Mutex
	keys      []jwkKey
	fetchedAt time.Time
	lastTry   time.Time
}

type jwkKey struct {
	kid string
	key crypto.PublicKey
}

const (
	minJWKSRetry = 30 * time.Second
	maxJWKSBytes = 1 << 20
	// maxTokenBytes bounds a bearer token. Real access tokens are a few KB;
	// without a cap a client could make the proxy base64- and JSON-decode
	// tens of megabytes per attempt before authenticating.
	maxTokenBytes = 16 * 1024
)

// jwksRedirect keeps a redirecting JWKS endpoint from downgrading to cleartext
// or chaining indefinitely.
func jwksRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("jwks fetch: too many redirects")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("jwks fetch: refusing https -> http redirect")
	}
	return nil
}

func newOIDCVerifier(c *config.OIDC) (*oidcVerifier, error) {
	if c == nil {
		return nil, errors.New("auth.oidc is required")
	}
	v := &oidcVerifier{cfg: *c, claim: c.TenantClaim, skew: 30 * time.Second, refresh: 10 * time.Minute,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// The key set is fetched from the configured URL only: a
			// redirect would let whoever controls that host point the
			// proxy at internal services (SSRF).
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
	if v.claim == "" {
		v.claim = "tenant"
	}
	if d, err := time.ParseDuration(c.ClockSkew); err == nil {
		v.skew = d
	}
	if d, err := time.ParseDuration(c.JWKSRefresh); err == nil && d > 0 {
		v.refresh = d
	}
	if c.JWKSFile != "" {
		if err := v.reload(); err != nil {
			return nil, fmt.Errorf("auth.oidc.jwksFile: %w", err)
		}
	}
	return v, nil
}

// reload fetches the key set. Callers must not hold v.mu.
func (v *oidcVerifier) reload() error {
	var raw []byte
	var err error
	if v.cfg.JWKSFile != "" {
		raw, err = os.ReadFile(v.cfg.JWKSFile)
	} else {
		var resp *http.Response
		// #nosec G704 -- jwksUri is operator configuration (scheme-checked in config.Validate), never taken from a token
		resp, err = v.client.Get(v.cfg.JWKSURI)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("jwks fetch: %s", resp.Status)
			} else {
				raw, err = io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
			}
		}
	}
	var keys []jwkKey
	if err == nil {
		keys, err = ParseJWKS(raw)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lastTry = time.Now()
	if err != nil {
		return err
	}
	v.keys, v.fetchedAt = keys, time.Now()
	return nil
}

// ParseJWKS decodes a JSON Web Key Set containing RSA and EC public keys.
func ParseJWKS(raw []byte) ([]jwkKey, error) {
	var set struct {
		Keys []struct {
			Kty, Kid, Crv, N, E, X, Y, Use string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("invalid JWKS: %w", err)
	}
	var out []jwkKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, e := b64Int(k.N), b64Int(k.E)
			if n == nil || e == nil || !e.IsInt64() || n.BitLen() < 2048 {
				continue
			}
			out = append(out, jwkKey{k.Kid, &rsa.PublicKey{N: n, E: int(e.Int64())}})
		case "EC":
			var curve elliptic.Curve
			switch k.Crv {
			case "P-256":
				curve = elliptic.P256()
			case "P-384":
				curve = elliptic.P384()
			case "P-521":
				curve = elliptic.P521()
			default:
				continue
			}
			x, y := b64Int(k.X), b64Int(k.Y)
			if x == nil || y == nil {
				continue
			}
			size := (curve.Params().BitSize + 7) / 8
			if x.BitLen() > size*8 || y.BitLen() > size*8 {
				continue
			}
			pt := make([]byte, 1+2*size)
			pt[0] = 4 // uncompressed point; ParseUncompressedPublicKey rejects points not on the curve
			x.FillBytes(pt[1 : 1+size])
			y.FillBytes(pt[1+size:])
			pub, err := ecdsa.ParseUncompressedPublicKey(curve, pt)
			if err != nil {
				continue
			}
			out = append(out, jwkKey{k.Kid, pub})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS contains no usable RSA (>=2048 bit) or EC keys")
	}
	return out, nil
}

func b64Int(s string) *big.Int {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(b)
}

func (v *oidcVerifier) candidates(kid string) []crypto.PublicKey {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []crypto.PublicKey
	for _, k := range v.keys {
		if kid == "" || k.kid == "" || k.kid == kid {
			out = append(out, k.key)
		}
	}
	return out
}

// keysFor returns the keys that may verify a token, refreshing the set when
// it is stale or the key id is unknown (rotation), at most every 30s.
func (v *oidcVerifier) keysFor(kid string) []crypto.PublicKey {
	ks := v.candidates(kid)
	v.mu.Lock()
	stale := v.keys == nil || time.Since(v.fetchedAt) > v.refresh
	// Claim the retry slot before fetching: otherwise every connection that
	// arrives while a slow fetch is in flight starts its own.
	canTry := (stale || len(ks) == 0) && (v.lastTry.IsZero() || time.Since(v.lastTry) > minJWKSRetry)
	if canTry {
		v.lastTry = time.Now()
	}
	v.mu.Unlock()
	if canTry && v.reload() == nil {
		ks = v.candidates(kid)
	}
	return ks
}

var jwtAlgs = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512,
}

// Verify checks signature, issuer, audience and validity window, and returns
// the tenant id from the configured claim.
func (v *oidcVerifier) Verify(token string, now time.Time) (string, error) {
	if len(token) > maxTokenBytes {
		return "", ErrAuthFailed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrAuthFailed
	}
	var hdr struct{ Alg, Kid string }
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return "", ErrAuthFailed
	}
	hash, ok := jwtAlgs[hdr.Alg] // "none" and HMAC algorithms are never accepted
	if !ok {
		return "", ErrAuthFailed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrAuthFailed
	}
	h := hash.New()
	h.Write([]byte(parts[0] + "." + parts[1]))
	digest := h.Sum(nil)
	verified := false
	for _, k := range v.keysFor(hdr.Kid) {
		if verifySig(hdr.Alg, hash, k, digest, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return "", ErrAuthFailed
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return "", ErrAuthFailed
	}
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return "", ErrAuthFailed
	}
	if !audMatches(claims["aud"], v.cfg.Audience) {
		return "", ErrAuthFailed
	}
	exp, ok := claims["exp"].(float64)
	if !ok || now.After(time.Unix(int64(exp), 0).Add(v.skew)) {
		return "", ErrAuthFailed
	}
	if nbf, ok := claims["nbf"].(float64); ok && now.Add(v.skew).Before(time.Unix(int64(nbf), 0)) {
		return "", ErrAuthFailed
	}
	if iat, ok := claims["iat"].(float64); ok && now.Add(v.skew).Before(time.Unix(int64(iat), 0)) {
		return "", ErrAuthFailed // issued in the future
	}
	tenant := claimString(claims, v.claim)
	if tenant == "" || len(tenant) > 256 {
		return "", ErrAuthFailed
	}
	return tenant, nil
}

func verifySig(alg string, hash crypto.Hash, key crypto.PublicKey, digest, sig []byte) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") && rsa.VerifyPKCS1v15(k, hash, digest, sig) == nil
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return false
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		want := map[string]int{"ES256": 256, "ES384": 384, "ES512": 521}[alg]
		if k.Curve.Params().BitSize != want || len(sig) != 2*size {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest, r, s)
	}
	return false
}

func decodeSegment(seg string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func audMatches(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}

// claimString reads a claim by exact name, then as a dotted path.
func claimString(claims map[string]any, name string) string {
	val, ok := claims[name]
	if !ok && strings.Contains(name, ".") {
		var cur any = claims
		for _, p := range strings.Split(name, ".") {
			m, isMap := cur.(map[string]any)
			if !isMap {
				return ""
			}
			cur = m[p]
		}
		val = cur
	}
	switch t := val.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
	}
	return ""
}

// OIDC validates a MONGODB-OIDC bearer token and returns its tenant.
func (a *Authenticator) OIDC(token string) (string, error) {
	if a.oidc == nil {
		return "", ErrMechanismUnavailable
	}
	return a.oidc.Verify(token, time.Now())
}
