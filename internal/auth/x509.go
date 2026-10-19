package auth

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

// normDN canonicalises a distinguished name for comparison. Attribute types
// (CN, OU, ...) are case-insensitive; values are compared exactly, because two
// certificates whose names differ only in case are different identities.
// Escaped commas (\,) inside a value never split an RDN.
func normDN(s string) string {
	var parts []string
	start, esc := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case esc:
			esc = false
		case s[i] == '\\':
			esc = true
		case s[i] == ',':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if k := strings.IndexByte(p, '='); k > 0 {
			p = strings.ToUpper(strings.TrimSpace(p[:k])) + "=" + strings.TrimSpace(p[k+1:])
		}
		parts[i] = p
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
	// Every matching rule must agree: a certificate that one rule maps to
	// tenant A (say by subject) and another to tenant B (by SAN) is
	// ambiguous, and picking the first by file order would make rule
	// order a tenant boundary.
	tenant := ""
	for _, r := range a.x509 {
		if (r.Subject != "" && normDN(r.Subject) == subject) || (r.SAN != "" && certHasSAN(cert, r.SAN)) {
			if tenant != "" && tenant != r.TenantID {
				return "", ErrAuthFailed
			}
			tenant = r.TenantID
		}
	}
	if tenant == "" {
		return "", ErrAuthFailed
	}
	return tenant, nil
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
