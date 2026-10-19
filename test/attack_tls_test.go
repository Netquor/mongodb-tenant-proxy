package test

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/wire"
)

// TLS policy of the client listener: no protocol or cipher downgrade, no
// plaintext on a TLS port, and client certificates are chain-verified.
func TestAttackTLSPolicy(t *testing.T) {
	ca := newPKI(t)
	server := ca.issue(t, "server", pkix.Name{CommonName: "proxy"}, true, nil, nil)
	alice := ca.issue(t, "alice", pkix.Name{CommonName: "alice"}, false, nil, nil)
	rogue := newPKI(t).issue(t, "alice-rogue", pkix.Name{CommonName: "alice"}, false, nil, nil)
	up, _ := plainUpstream(t)
	addr, _ := startProxy(t, &config.Config{Upstream: config.Upstream{Addr: up}, ConnLimits: config.ConnLimits{HandshakeTimeout: "2s"},
		ClientTLS: &config.ClientTLS{CertFile: server.certFile, KeyFile: server.keyFile, ClientCAFile: ca.caFile},
		Auth:      config.Auth{Mode: "x509", X509: []config.X509Rule{{Subject: "CN=alice", TenantID: "tenant-a"}}}})

	dial := func(mutate func(*tls.Config), l *leaf) error {
		tc := ca.tlsClientConfig(t, l)
		mutate(tc)
		d := net.Dialer{Timeout: 5 * time.Second}
		c, err := tls.DialWithDialer(&d, "tcp", addr, tc)
		if err != nil {
			return err
		}
		defer c.Close()
		// TLS 1.3 reports a rejected client certificate only on first use, so
		// talk to the server: a ping that gets any answer proves the session.
		body := (&wire.Msg{Body: mustBSON(t, atkCmdDoc("admin", bson.D{{Key: "ping", Value: 1}}))}).Encode()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write(atkFrame(int32(16+len(body)), 1, 0, wire.OpMsg, body)); err != nil {
			return err
		}
		_, _, err = wire.ReadFrame(c, 1<<20)
		return err
	}

	t.Run("baseline", func(t *testing.T) {
		if err := dial(func(*tls.Config) {}, &alice); err != nil {
			t.Fatalf("legitimate TLS client refused: %v", err)
		}
	})
	t.Run("TLS 1.0 and 1.1 are refused", func(t *testing.T) {
		for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
			err := dial(func(c *tls.Config) { c.MinVersion, c.MaxVersion = v, v }, &alice)
			if err == nil {
				t.Errorf("TLS %#x accepted", v)
			}
		}
	})
	t.Run("legacy cipher suites are refused", func(t *testing.T) {
		var weak []uint16
		for _, s := range tls.InsecureCipherSuites() {
			weak = append(weak, s.ID)
		}
		err := dial(func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12; c.CipherSuites = weak }, &alice)
		if err == nil {
			t.Error("a handshake using only insecure cipher suites succeeded")
		}
	})
	t.Run("plaintext on the TLS port", func(t *testing.T) {
		nc, err := net.Dial("tcp", addr)
		must(t, err)
		defer nc.Close()
		nc.Write(atkFrame(16, 1, 0, 2013, nil))
		r := &atkRaw{t: t, nc: nc}
		if !r.closedWithin(5 * time.Second) {
			t.Fatal("plaintext connection held open on a TLS listener")
		}
	})
	t.Run("client certificate chain is verified", func(t *testing.T) {
		if err := dial(func(*tls.Config) {}, &rogue); err == nil {
			t.Error("certificate from an untrusted CA accepted")
		}
		if err := dial(func(*tls.Config) {}, nil); err == nil {
			t.Error("x509-only listener accepted a client without a certificate")
		}
	})
	t.Run("slow TLS handshake is dropped", func(t *testing.T) {
		nc, err := net.Dial("tcp", addr)
		must(t, err)
		defer nc.Close()
		nc.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00}) // TLS record header, then nothing
		r := &atkRaw{t: t, nc: nc}
		if !r.closedWithin(8 * time.Second) {
			t.Fatal("stalled TLS handshake never dropped")
		}
	})
}
