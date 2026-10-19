package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/audit"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/metrics"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
	"github.com/netquor/mongodb-tenant-proxy/internal/tenants"
)

type fake struct {
	reg    *tenants.Registry
	killed []int64
}

func (f *fake) Registry() *tenants.Registry { return f.reg }
func (f *fake) Audit() *audit.Logger        { return nil }
func (f *fake) Connections(t string) []proxy.ConnInfo {
	return []proxy.ConnInfo{{ID: 7, Tenant: "acme"}}
}
func (f *fake) KillConnection(id int64) (proxy.ConnInfo, bool) {
	f.killed = append(f.killed, id)
	return proxy.ConnInfo{ID: id}, id == 7
}
func (f *fake) KillTenant(string) int                    { return 1 }
func (f *fake) TenantStats(t string) metrics.TenantStats { return metrics.TenantStats{Tenant: t} }
func (f *fake) Reload() (*proxy.ReloadResult, error)     { return &proxy.ReloadResult{}, nil }

func newFake(t *testing.T) *fake {
	reg, err := tenants.NewRegistry(context.Background(), tenants.NewFileStore(filepath.Join(t.TempDir(), "t.json")))
	if err != nil {
		t.Fatal(err)
	}
	reg.SetStatic([]config.TenantEntry{{ID: "fixed"}}, nil)
	return &fake{reg: reg}
}

func do(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRoutesAndStatusCodes(t *testing.T) {
	const tok = "0123456789abcdef-token"
	s, err := New(newFake(t), config.Admin{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/v1/tenants", "", 200},
		{"POST", "/v1/tenants", `{"id":"acme"}`, 201},
		{"POST", "/v1/tenants", `{"id":"acme"}`, 409},
		{"POST", "/v1/tenants", `{"id":"bad id"}`, 400},
		{"POST", "/v1/tenants", `{"id":"x","unknown":1}`, 400},
		{"GET", "/v1/tenants/acme", "", 200},
		{"GET", "/v1/tenants/nope", "", 404},
		{"POST", "/v1/tenants/fixed/disable", "", 409}, // config tenants are read-only
		{"POST", "/v1/tenants/fixed/users", `{"username":"zed"}`, 409},
		{"POST", "/v1/tenants/acme/users", `{"username":"ann","password":"pw-1"}`, 201},
		{"PUT", "/v1/tenants/acme/users/ann", `{}`, 200},
		{"GET", "/v1/tenants/acme/users", "", 200},
		{"DELETE", "/v1/tenants/acme/users/ann", "", 204},
		{"DELETE", "/v1/tenants/acme/users/ann", "", 404},
		{"PATCH", "/v1/tenants/acme", `{"maxConns":3}`, 200},
		{"GET", "/v1/tenants/acme/stats", "", 200},
		{"GET", "/v1/connections", "", 200},
		{"DELETE", "/v1/connections/7", "", 204},
		{"DELETE", "/v1/connections/8", "", 404},
		{"DELETE", "/v1/connections/zz", "", 400},
		{"POST", "/v1/reload", "", 200},
		{"DELETE", "/v1/tenants/acme", "", 204},
	}
	for _, c := range cases {
		if rec := do(t, h, c.method, c.path, c.body, tok); rec.Code != c.want {
			t.Errorf("%s %s = %d, want %d: %s", c.method, c.path, rec.Code, c.want, rec.Body)
		}
	}
	if rec := do(t, h, "GET", "/v1/tenants", "", "wrong"); rec.Code != 401 {
		t.Errorf("bad token = %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/healthz", "", ""); rec.Code != 200 {
		t.Errorf("/healthz must be open, got %d", rec.Code)
	}
	// secrets are never listed
	do(t, h, "POST", "/v1/tenants/fixed2/users", `{"username":"q","password":"pw"}`, tok)
	rec := do(t, h, "POST", "/v1/tenants", `{"id":"leak"}`, tok)
	_ = rec
	do(t, h, "POST", "/v1/tenants/leak/users", `{"username":"leaky","password":"hunter2hunter2"}`, tok)
	body := do(t, h, "GET", "/v1/tenants/leak/users", "", tok).Body.String()
	for _, bad := range []string{"storedKey", "serverKey", "salt", "hunter2"} {
		if strings.Contains(body, bad) {
			t.Errorf("user listing exposes %q: %s", bad, body)
		}
	}
}

func TestTokenValidation(t *testing.T) {
	if _, err := New(newFake(t), config.Admin{}); err == nil {
		t.Error("no auth configured must be refused")
	}
	if _, err := New(newFake(t), config.Admin{Token: "short"}); err == nil {
		t.Error("short token must be refused")
	}
	p := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(p, []byte("file-token-0123456789\n"), 0o600)
	s, err := New(newFake(t), config.Admin{TokenFile: p})
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(t, s.Handler(), "GET", "/v1/tenants", "", "file-token-0123456789"); rec.Code != 200 {
		t.Errorf("token from file rejected: %d", rec.Code)
	}
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(cn string, usage x509.ExtKeyUsage, serial int64) (certPath, keyPath string, tc tls.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		certPath, keyPath = filepath.Join(dir, cn+".crt"), filepath.Join(dir, cn+".key")
		writePEM(t, certPath, "CERTIFICATE", der)
		writePEM(t, keyPath, "EC PRIVATE KEY", kd)
		tc, _ = tls.LoadX509KeyPair(certPath, keyPath)
		return
	}
	caPath := filepath.Join(dir, "ca.crt")
	writePEM(t, caPath, "CERTIFICATE", caDER)
	srvCert, srvKey, _ := issue("server", x509.ExtKeyUsageServerAuth, 2)
	_, _, clientCert := issue("ops-bot", x509.ExtKeyUsageClientAuth, 3)

	s, err := New(newFake(t), config.Admin{TLS: &config.AdminTLS{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: caPath}})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, ln)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	get := func(certs []tls.Certificate) int {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: certs}}, Timeout: 5 * time.Second}
		resp, err := c.Get("https://" + ln.Addr().String() + "/v1/tenants")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get([]tls.Certificate{clientCert}); code != 200 {
		t.Errorf("valid client cert = %d", code)
	}
	if code := get(nil); code != 401 {
		t.Errorf("no client cert = %d", code)
	}
}

func TestTokenEqualAndOriginGuard(t *testing.T) {
	want := []byte("0123456789abcdef-token")
	if !tokenEqual("0123456789abcdef-token", want) || tokenEqual("0123456789abcdef-toke", want) || tokenEqual("", want) {
		t.Fatal("tokenEqual")
	}
	s, err := New(newFake(t), config.Admin{Token: string(want)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer "+string(want))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("cross-origin POST = %d, want 403", rec.Code)
	}
	if rec := do(t, s.Handler(), "POST", "/v1/reload", "", string(want)); rec.Code != 200 {
		t.Fatalf("same-origin POST = %d, want 200", rec.Code)
	}
}
