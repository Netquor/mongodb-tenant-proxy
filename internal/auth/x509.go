package auth

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// normDN canonicalises a distinguished name for comparison.
func normDN(s string) string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(p))
	}
	return strings.Join(parts, ",")
}

// X509 maps the verified client certificate of a TLS connection to a tenant.
// user is the optional name from the authenticate command; if given it must
// be the certificate subject, as with mongod.
func (a *Authenticator) X509(state *tls.ConnectionState, user string) (string, error) {
	if !a.Has("x509") || state == nil || len(state.PeerCertificates) == 0 {
		return "", ErrAuthFailed
	}
	// The listener verified the chain (tls.Config.ClientAuth); a connection
	// whose chain was not verified must not authenticate.
	if len(state.VerifiedChains) == 0 {
		return "", ErrAuthFailed
	}
	cert := state.PeerCertificates[0]
	subject := normDN(cert.Subject.String())
	if user != "" && normDN(user) != subject {
		return "", ErrAuthFailed
	}
	for _, r := range a.x509 {
		if r.Subject != "" && normDN(r.Subject) == subject {
			return r.TenantID, nil
		}
		if r.SAN != "" && certHasSAN(cert, r.SAN) {
			return r.TenantID, nil
		}
	}
	return "", ErrAuthFailed
}

func certHasSAN(c *x509.Certificate, san string) bool {
	for _, d := range c.DNSNames {
		if strings.EqualFold(d, san) {
			return true
		}
	}
	for _, e := range c.EmailAddresses {
		if strings.EqualFold(e, san) {
			return true
		}
	}
	for _, u := range c.URIs {
		if u.String() == san {
			return true
		}
	}
	for _, ip := range c.IPAddresses {
		if ip.String() == san {
			return true
		}
	}
	return false
}
