package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// One member speaks TLS (self-signed, so verification is skipped for that host
// only), the other plaintext: TLS settings are per host.
func TestTLSPerHost(t *testing.T) {
	secure := startFakeTLS(t, selfSigned(t))
	plain := startFake(t)
	yes := true
	cfg := &config.Config{MaxMessageBytes: 1 << 20, Upstream: config.Upstream{
		HeartbeatInterval: "200ms",
		Hosts: []config.Host{
			{Addr: secure.ln.Addr().String(), TLS: &yes, InsecureSkipVerify: &yes},
			{Addr: plain.ln.Addr().String()},
		},
	}}
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		known := 0
		for _, m := range d.Stats().Members {
			if m.Type != "Unknown" {
				known++
			}
		}
		if known == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("members not both reachable: %+v", d.Stats().Members)
		}
		time.Sleep(50 * time.Millisecond)
	}
	ping := bsoncore.BuildDocument(nil, bsoncore.AppendInt32Element(nil, "ping", 1))
	for _, f := range []*fakeMongod{secure, plain} {
		c, err := d.DialMember(context.Background(), f.ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.RunCommand(c, "admin", ping); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	// Without the override the secure member is unreachable (plaintext into TLS).
	cfg.Upstream.Hosts[0].TLS = nil
	d2, _ := NewDialer(cfg)
	defer d2.Close()
	c, err := d2.DialMember(context.Background(), secure.ln.Addr().String())
	if err == nil {
		c.SetDeadline(time.Now().Add(time.Second))
		_, err = d2.RunCommand(c, "admin", ping)
		c.Close()
	}
	if err == nil {
		t.Fatal("plaintext to a TLS member should fail")
	}
}
