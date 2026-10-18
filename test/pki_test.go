package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/proxy"
)

// pki is a throwaway certificate authority for TLS / x.509 tests.
type pki struct {
	dir    string
	caFile string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	serial int64
}

type leaf struct {
	certFile, keyFile string
	pemFile           string // cert + key in one file (mongod, driver)
}

func newPKI(t testing.TB) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir()}
	p.key = mustKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca", Organization: []string{"mtp"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &p.key.PublicKey, p.key)
	must2(t, err)
	p.cert, err = x509.ParseCertificate(der)
	must2(t, err)
	p.caFile = filepath.Join(p.dir, "ca.pem")
	must2(t, os.WriteFile(p.caFile, pemBlock("CERTIFICATE", der), 0o600))
	return p
}

func mustKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must2(t, err)
	return k
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// issue creates a certificate signed by the CA. server certs get 127.0.0.1 and
// localhost as SANs; client certs get the extra DNS/e-mail SANs.
func (p *pki) issue(t testing.TB, name string, subj pkix.Name, server bool, dns, emails []string) leaf {
	t.Helper()
	p.serial++
	key := mustKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100 + p.serial), Subject: subj,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns, EmailAddresses: emails,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} // mongod members also act as clients
		tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	must2(t, err)
	kder, err := x509.MarshalECPrivateKey(key)
	must2(t, err)
	l := leaf{
		certFile: filepath.Join(p.dir, name+".crt"),
		keyFile:  filepath.Join(p.dir, name+".key"),
		pemFile:  filepath.Join(p.dir, name+".pem"),
	}
	c, k := pemBlock("CERTIFICATE", der), pemBlock("EC PRIVATE KEY", kder)
	must2(t, os.WriteFile(l.certFile, c, 0o600))
	must2(t, os.WriteFile(l.keyFile, k, 0o600))
	must2(t, os.WriteFile(l.pemFile, append(append([]byte{}, c...), k...), 0o600))
	return l
}

// tlsClientConfig is for raw TLS dials against a proxy listener.
func (p *pki) tlsClientConfig(t testing.TB, l *leaf) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	tc := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}
	if l != nil {
		c, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
		must2(t, err)
		tc.Certificates = []tls.Certificate{c}
	}
	return tc
}

// startProxy runs an in-process proxy in front of upstream and returns its
// address. It honours cfg.ClientTLS exactly like cmd/mongodb-tenant-proxy.
func startProxy(t testing.TB, cfg *config.Config) (addr string, srv *proxy.Server) {
	t.Helper()
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 48 << 20
	}
	if cfg.Tenant.Field == "" {
		cfg.Tenant.Field = "tenantId"
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("MTP_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv, err := proxy.New(cfg, log)
	must2(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must2(t, err)
	if cfg.ClientTLS != nil {
		tc, err := cfg.ListenerTLS()
		must2(t, err)
		ln = tls.NewListener(ln, tc)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), srv
}

// mongodOpts selects the flavour of throwaway mongod.
type mongodOpts struct {
	tls      *pki  // require TLS with this CA
	server   *leaf // server certificate when tls != nil
	x509User string
}

// startMongodTLS starts an auth-enabled, TLS-only replica-set member with a
// root user ("root"/rootPW) and, optionally, a MONGODB-X509 user.
func startMongodTLS(t testing.TB, o mongodOpts) (addr, rootURI string) {
	t.Helper()
	bin, err := exec.LookPath("mongod")
	if err != nil {
		t.Skip("mongod not found in PATH")
	}
	dir := t.TempDir()
	port := freePort(t)
	kf := filepath.Join(dir, "keyfile")
	must2(t, os.WriteFile(kf, []byte("testkeyfilecontents0123456789AB"), 0o600))
	cmd := exec.Command(bin, "--dbpath", dir, "--port", fmt.Sprint(port), "--bind_ip", "127.0.0.1",
		"--replSet", "rs0", "--logpath", filepath.Join(dir, "mongod.log"), "--quiet",
		"--auth", "--keyFile", kf,
		"--tlsMode", "requireTLS", "--tlsCertificateKeyFile", o.server.pemFile, "--tlsCAFile", o.tls.caFile,
		"--tlsAllowConnectionsWithoutCertificates")
	must2(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr = fmt.Sprintf("127.0.0.1:%d", port)
	q := url.Values{"tls": {"true"}, "tlsCAFile": {o.tls.caFile}, "directConnection": {"true"}}
	plain := fmt.Sprintf("mongodb://%s/?%s", addr, q.Encode())
	rootURI = fmt.Sprintf("mongodb://root:root-pw@%s/?authSource=admin&%s", addr, q.Encode())

	bg, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := connect(t, plain)
	defer c.Disconnect(context.Background())
	for c.Ping(bg, nil) != nil {
		if bg.Err() != nil {
			lg, _ := os.ReadFile(filepath.Join(dir, "mongod.log"))
			if len(lg) > 3000 {
				lg = lg[len(lg)-3000:]
			}
			t.Fatalf("mongod did not start: %s", lg)
		}
		time.Sleep(200 * time.Millisecond)
	}
	must2(t, c.Database("admin").RunCommand(bg, bson.D{{Key: "replSetInitiate", Value: bson.D{
		{Key: "_id", Value: "rs0"},
		{Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: addr}}}},
	}}}).Err())
	for {
		var res bson.M
		if err := c.Database("admin").RunCommand(bg, bson.D{{Key: "hello", Value: 1}}).Decode(&res); err == nil && res["isWritablePrimary"] == true {
			break
		}
		if bg.Err() != nil {
			t.Fatal("no primary elected")
		}
		time.Sleep(200 * time.Millisecond)
	}
	must2(t, c.Database("admin").RunCommand(bg, bson.D{{Key: "createUser", Value: "root"}, {Key: "pwd", Value: "root-pw"},
		{Key: "roles", Value: bson.A{"root"}}}).Err())
	if o.x509User != "" {
		rc := connect(t, rootURI)
		defer rc.Disconnect(context.Background())
		must2(t, rc.Database("$external").RunCommand(bg, bson.D{{Key: "createUser", Value: o.x509User},
			{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: "root"}, {Key: "db", Value: "admin"}}}}}).Err())
	}
	return addr, rootURI
}

var _ = mongo.Connect

// serveJSON serves body at a local URL for the lifetime of the test.
func serveJSON(t testing.TB, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
