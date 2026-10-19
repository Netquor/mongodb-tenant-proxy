package admin

// A hostile caller of the admin API, and a stolen admin token: authentication
// bypass attempts, CSRF, request smuggling, oversized and slow bodies, brute
// force, rate limiting, and what ends up in the audit trail.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/audit"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

const atkToken = "correct-horse-battery-staple-0123"

// audited is a fake backend that writes to a real audit file.
type audited struct {
	*fake
	log *audit.Logger
}

func (a *audited) Audit() *audit.Logger { return a.log }

func newAudited(t *testing.T) (*audited, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.New(config.Audit{Enabled: true, Sink: "file", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &audited{fake: newFake(t), log: l}, path
}

func newServer(t *testing.T, cfg config.Admin) (*Server, *audited, string) {
	t.Helper()
	b, path := newAudited(t)
	if cfg.Token == "" {
		cfg.Token = atkToken
	}
	s, err := New(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, b, path
}

var nextIP atomic.Uint32

// req sends from a fresh client address each time, so the failed-attempt
// lockout does not mask what is being tested; reqFrom pins the address.
func req(h http.Handler, method, path string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	n := nextIP.Add(1)
	return reqFrom(h, fmt.Sprintf("10.%d.%d.%d:5555", n>>16&255, n>>8&255, n&255), method, path, hdr, body)
}

func reqFrom(h http.Handler, addr, method, path string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = addr
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func TestAdminAuthBypass(t *testing.T) {
	s, _, _ := newServer(t, config.Admin{RatePerSec: -1})
	h := s.Handler()
	paths := []string{"/v1/tenants", "/v1/tenants/", "//v1/tenants", "/v1/tenants/fixed", "/v1/connections", "/v1/reload",
		"/v1/../v1/tenants", "/v1/tenants/../tenants", "/V1/TENANTS", "/v1/tenants/fixed/users", "/v1/tenants/%2e%2e/users",
		"/v1/tenants/fixed%2fusers", "/healthz/", "/healthz/../v1/tenants", "/healthz%2f..%2fv1%2ftenants", "/", "/metrics", "/debug/pprof/",
		"/v1/tenants?token=" + atkToken, "/v1/tenants#" + atkToken}
	headers := []map[string]string{
		nil,
		{"Authorization": ""},
		{"Authorization": "Bearer"},
		{"Authorization": "Bearer "},
		{"Authorization": "bearer " + atkToken},
		{"Authorization": "BEARER " + atkToken},
		{"Authorization": "Basic " + atkToken},
		{"Authorization": atkToken},
		{"Authorization": "Bearer " + atkToken + " "},
		{"Authorization": "Bearer  " + atkToken},
		{"Authorization": "Bearer " + atkToken[:len(atkToken)-1]},
		{"Authorization": "Bearer " + atkToken + "x"},
		{"Authorization": "Bearer " + strings.Repeat("A", 100000)},
		{"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
		{"X-Forwarded-User": "admin", "X-Authenticated-User": "admin"},
		{"Cookie": "token=" + atkToken},
		{"Authorization": "Negotiate abc"},
		{"X-HTTP-Method-Override": "GET"},
	}
	for _, p := range paths {
		for _, hd := range headers {
			w := req(h, "GET", p, hd, "")
			// Only /healthz (exactly) is open; nothing else may answer 2xx
			// to a caller without the token.
			if w.Code < 400 {
				t.Errorf("GET %s with %v = %d: %.80s", p, hd, w.Code, w.Body.String())
			}
		}
	}
	// The one open path reveals nothing.
	if w := req(h, "GET", "/healthz", nil, ""); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "ok" {
		t.Errorf("/healthz = %d %q", w.Code, w.Body.String())
	}
	// Every method without credentials is refused.
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD", "PROPFIND"} {
		if w := req(h, m, "/v1/tenants", nil, `{"id":"x"}`); w.Code < 400 {
			t.Errorf("%s without a token = %d", m, w.Code)
		}
	}
	if _, ok := s.b.Registry().Tenant("x"); ok {
		t.Fatal("a tenant was created without authentication")
	}
}

// A hostile token comparison must never succeed by length or prefix games.
func TestAdminTokenComparison(t *testing.T) {
	s, _, _ := newServer(t, config.Admin{RatePerSec: -1, Token: atkToken})
	h := s.Handler()
	if w := req(h, "GET", "/v1/tenants", bearer(atkToken), ""); w.Code != 200 {
		t.Fatalf("correct token: %d", w.Code)
	}
	for _, tok := range []string{"", "a", atkToken[:16], atkToken + atkToken, strings.ToUpper(atkToken), atkToken + "\x00", "\x00" + atkToken} {
		hdr := bearer(tok)
		if tok == "" || strings.ContainsRune(tok, 0) {
			hdr = map[string]string{"Authorization": "Bearer " + strings.ReplaceAll(tok, "\x00", "%00")}
		}
		if w := req(h, "GET", "/v1/tenants", hdr, ""); w.Code != 401 && w.Code != 429 {
			t.Errorf("token %.20q = %d", tok, w.Code)
		}
	}
}

func TestAdminBruteForceLockout(t *testing.T) {
	s, _, path := newServer(t, config.Admin{RatePerSec: -1})
	h := s.Handler()
	var last int
	locked := false
	for i := 0; i < 30; i++ {
		last = reqFrom(h, "203.0.113.9:4444", "GET", "/v1/tenants", bearer(fmt.Sprintf("guess-%d-xxxxxxxxxxxxxxxx", i)), "").Code
		if last == 429 {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatalf("30 wrong tokens in a row never triggered a lockout (last status %d)", last)
	}
	// The right token is refused too while the address is locked out ...
	w := reqFrom(h, "203.0.113.9:4444", "GET", "/v1/tenants", bearer(atkToken), "")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("locked-out address with the right token = %d (Retry-After %q)", w.Code, w.Header().Get("Retry-After"))
	}
	// ... but another address is unaffected.
	r := httptest.NewRequest("GET", "/v1/tenants", nil)
	r.RemoteAddr = "198.51.100.1:1"
	r.Header.Set("Authorization", "Bearer "+atkToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("other address = %d", rec.Code)
	}
	// Failed attempts are audited, the guessed tokens are not.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"outcome":"unauthorized"`) {
		t.Error("failed admin authentication not audited")
	}
	if strings.Contains(string(raw), "guess-3-") || strings.Contains(string(raw), atkToken) {
		t.Error("a token value reached the audit log")
	}
}

func TestAdminRateLimit(t *testing.T) {
	s, _, _ := newServer(t, config.Admin{RatePerSec: 20})
	h := s.Handler()
	ok, limited := 0, 0
	for i := 0; i < 200; i++ {
		switch req(h, "GET", "/v1/tenants", bearer(atkToken), "").Code {
		case 200:
			ok++
		case 429:
			limited++
		default:
			t.Fatal("unexpected status")
		}
	}
	if limited < 100 || ok < 20 || ok > 80 {
		t.Fatalf("200 instant requests at 20/s: %d served, %d limited", ok, limited)
	}
	time.Sleep(1200 * time.Millisecond)
	if w := req(h, "GET", "/v1/tenants", bearer(atkToken), ""); w.Code != 200 {
		t.Fatalf("no recovery after the burst: %d", w.Code)
	}
}

func TestAdminCSRF(t *testing.T) {
	s, _, _ := newServer(t, config.Admin{RatePerSec: -1})
	h := s.Handler()
	// A browser always labels cross-origin writes; the API refuses them even
	// though a client-certificate-holding browser would add credentials.
	for _, hd := range []map[string]string{
		{"Origin": "https://evil.example"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": "https://evil.example", "Content-Type": "text/plain"},
		{"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
	} {
		hd["Authorization"] = "Bearer " + atkToken
		for _, c := range []struct{ m, p, b string }{
			{"POST", "/v1/tenants", `{"id":"csrf"}`},
			{"POST", "/v1/reload", ""},
			{"DELETE", "/v1/tenants/fixed/connections", ""},
			{"POST", "/v1/tenants/fixed/disable", ""},
		} {
			if w := req(h, c.m, c.p, hd, c.b); w.Code != 403 {
				t.Errorf("%s %s with %v = %d, want 403", c.m, c.p, hd, w.Code)
			}
		}
	}
	if _, ok := s.b.Registry().Tenant("csrf"); ok {
		t.Fatal("cross-origin request created a tenant")
	}
	// Same-origin / non-browser callers are unaffected.
	if w := req(h, "POST", "/v1/tenants", map[string]string{"Authorization": "Bearer " + atkToken, "Sec-Fetch-Site": "same-origin"}, `{"id":"ok"}`); w.Code != 201 {
		t.Errorf("legitimate create = %d", w.Code)
	}
}

func TestAdminInputAbuse(t *testing.T) {
	s, _, path := newServer(t, config.Admin{RatePerSec: -1})
	h := s.Handler()
	auth := bearer(atkToken)

	// Oversized body: refused, nothing created.
	huge := `{"id":"` + strings.Repeat("a", 2<<20) + `"}`
	if w := req(h, "POST", "/v1/tenants", auth, huge); w.Code < 400 || w.Code >= 500 {
		t.Errorf("2 MiB body = %d", w.Code)
	}
	// Garbage, wrong types, unknown fields, trailing data, deep nesting.
	for _, body := range []string{"", "{", "[]", "null", `{"id":5}`, `{"id":"x","extra":1}`, `{"id":"a"}{"id":"b"}`, `{"id":""}`,
		`{"id":"` + strings.Repeat("a", 5000) + `"}`, strings.Repeat("[", 100000), `{"id":"../etc"}`, `{"id":"a/b"}`, `{"id":"a b"}`,
		`{"id":"x\u0000y"}`, `{"id":"x","maxConns":-5}`, `{"id":"x","maxConns":1e99}`, `{"id":"$where"}`, `{"id":"` + strings.Repeat("é", 300) + `"}`} {
		w := req(h, "POST", "/v1/tenants", auth, body)
		if w.Code == 201 {
			if strings.Contains(body, "..") || strings.Contains(body, "/") || strings.Contains(body, "\\u0000") || strings.Contains(body, "$") {
				t.Errorf("hostile tenant id accepted: %.60s", body)
			}
		} else if w.Code >= 500 {
			t.Errorf("body %.40q caused a server error: %d", body, w.Code)
		}
	}
	// Path traversal in identifiers never touches anything.
	for _, p := range []string{"/v1/tenants/..%2f..%2fetc%2fpasswd", "/v1/tenants/%2e%2e", "/v1/tenants/fixed/users/..%2f..", "/v1/tenants/%00",
		"/v1/tenants/" + strings.Repeat("a", 100000), "/v1/connections/abc", "/v1/connections/-1", "/v1/connections/99999999999999999999"} {
		for _, m := range []string{"GET", "DELETE", "PUT"} {
			if w := req(h, m, p, auth, `{}`); w.Code >= 500 || w.Code == 200 || w.Code == 204 {
				t.Errorf("%s %.50s = %d", m, p, w.Code)
			}
		}
	}
	// Audit lines stay small however long the hostile identifiers are.
	raw, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(raw), "\n") {
		if len(line) > 4096 {
			t.Fatalf("audit line of %d bytes", len(line))
		}
	}
}

// Passwords: neither the ones callers send nor the generated ones are written
// to the audit trail, and the generated one is shown exactly once.
func TestAdminSecretsStayOutOfAudit(t *testing.T) {
	s, _, path := newServer(t, config.Admin{RatePerSec: -1})
	h := s.Handler()
	auth := bearer(atkToken)
	req(h, "POST", "/v1/tenants", auth, `{"id":"acme"}`)
	const pw = "hunter2-very-secret-pw"
	if w := req(h, "POST", "/v1/tenants/acme/users", auth, `{"username":"ann","password":"`+pw+`"}`); w.Code != 201 {
		t.Fatalf("create user: %d %s", w.Code, w.Body)
	}
	w := req(h, "POST", "/v1/tenants/acme/users", auth, `{"username":"gen"}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"password"`) {
		t.Fatalf("generated password not returned once: %d %s", w.Code, w.Body)
	}
	gen := w.Body.String()
	req(h, "PUT", "/v1/tenants/acme/users/ann", auth, `{"password":"`+pw+`-2"}`)
	if w := req(h, "GET", "/v1/tenants/acme/users", auth, ""); strings.Contains(w.Body.String(), pw) || strings.Contains(w.Body.String(), "password") ||
		strings.Contains(strings.ToLower(w.Body.String()), "storedkey") || strings.Contains(strings.ToLower(w.Body.String()), "serverkey") {
		t.Errorf("user listing exposes credential material: %s", w.Body)
	}
	raw, _ := os.ReadFile(path)
	for _, secret := range []string{pw, atkToken, gen[strings.Index(gen, `"password"`)+13 : strings.Index(gen, `"password"`)+13+8]} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("secret %.6q… found in the audit log", secret)
		}
	}
	for _, want := range []string{`"action":"tenant.create"`, `"action":"user.create"`, `"action":"user.reset-password"`, `"actor":"token"`, `"remote":"10.`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("audit log lacks %s", want)
		}
	}
}

// A failing store's error text (which can carry connection strings) is not
// echoed to the caller.
func TestAdminInternalErrorsAreNotEchoed(t *testing.T) {
	rec := httptest.NewRecorder()
	fail(rec, errors.New("dial mongodb://svc:s3cr3t-pw@10.0.0.5:27017: connection refused"))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "s3cr3t") || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("internal error leaked: %d %s", rec.Code, rec.Body)
	}
}

// ---- over a real socket -------------------------------------------------------------

func serveReal(t *testing.T, cfg config.Admin) (string, string) {
	t.Helper()
	s, _, path := newServer(t, cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), path
}

func rawHTTP(t *testing.T, addr, payload string) string {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(700 * time.Millisecond))
	nc.Write([]byte(payload))
	b, _ := io.ReadAll(bufio.NewReader(nc)) // ends at close or at the deadline
	return string(b)
}

func TestAdminRequestSmuggling(t *testing.T) {
	addr, _ := serveReal(t, config.Admin{RatePerSec: -1})
	auth := "Authorization: Bearer " + atkToken + "\r\n"
	body := `{"id":"smuggled"}`
	cases := map[string]string{
		"CL and TE together": "POST /v1/tenants HTTP/1.1\r\nHost: x\r\n" + auth + "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" +
			fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\nGET /v1/tenants HTTP/1.1\r\nHost: x\r\n\r\n", len(body), body),
		"conflicting Content-Length":   "POST /v1/tenants HTTP/1.1\r\nHost: x\r\n" + auth + "Content-Length: 5\r\nContent-Length: 50\r\n\r\n" + body,
		"obfuscated Transfer-Encoding": "POST /v1/tenants HTTP/1.1\r\nHost: x\r\n" + auth + "Transfer-Encoding: xchunked\r\nContent-Length: 17\r\n\r\n" + body,
		"space before colon":           "POST /v1/tenants HTTP/1.1\r\nHost: x\r\n" + auth + "Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
		"bare LF headers":              "GET /v1/tenants HTTP/1.1\nHost: x\nX: y\r\n\r\n",
		"absolute-form to health":      "GET http://x/healthz/../v1/tenants HTTP/1.1\r\nHost: x\r\n\r\n",
	}
	for name, payload := range cases {
		out := rawHTTP(t, addr, payload)
		if strings.Contains(out, "200 OK") && strings.Contains(out, `"tenants"`) {
			t.Errorf("%s: unauthenticated data returned: %.200s", name, out)
		}
		if strings.Count(out, "HTTP/1.1 2") > 1 {
			t.Errorf("%s: more than one successful response (smuggled request): %.300s", name, out)
		}
	}
	// A second pipelined request on an authenticated connection is authenticated
	// on its own merits.
	out := rawHTTP(t, addr, "GET /v1/tenants HTTP/1.1\r\nHost: x\r\n"+auth+"\r\nGET /v1/tenants HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if strings.Count(out, "HTTP/1.1 200") != 1 || !strings.Contains(out, "HTTP/1.1 401") {
		t.Errorf("pipelined second request inherited authentication: %.300s", out)
	}
	if out := rawHTTP(t, addr, "GET /v1/tenants HTTP/1.1\r\nHost: x\r\n"+auth+"X-Big: "+strings.Repeat("a", 200000)+"\r\n\r\n"); strings.Contains(out, "200 OK") {
		t.Errorf("200 KiB header accepted")
	}
}

func TestAdminSlowClients(t *testing.T) {
	old1, old2 := readHeaderTimeout, readTimeout
	readHeaderTimeout, readTimeout = time.Second, time.Second
	defer func() { readHeaderTimeout, readTimeout = old1, old2 }()
	addr, _ := serveReal(t, config.Admin{RatePerSec: -1})

	dropped := func(name string, first string, drip string) {
		nc, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer nc.Close()
		nc.Write([]byte(first))
		start := time.Now()
		go func() {
			for i := 0; i < 20; i++ {
				if _, err := nc.Write([]byte(drip)); err != nil {
					return
				}
				time.Sleep(300 * time.Millisecond)
			}
		}()
		nc.SetReadDeadline(time.Now().Add(6 * time.Second))
		io.Copy(io.Discard, nc) // returns when the server closes
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: connection survived %v", name, d)
		}
	}
	dropped("slow headers", "GET /v1/tenants HTTP/1.1\r\nHost: x\r\n", "X: y\r\n")
	dropped("slow body", "POST /v1/tenants HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+atkToken+"\r\nContent-Length: 100000\r\n\r\n", "a")
}
