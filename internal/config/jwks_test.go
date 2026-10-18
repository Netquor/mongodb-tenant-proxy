package config

import "testing"

func TestCheckJWKSURI(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://idp.example.com/keys":    true,
		"http://127.0.0.1:8080/keys":      true,
		"http://localhost/keys":           true,
		"http://idp.example.com/keys":     false,
		"https://user:pw@idp.example/k":   false,
		"file:///etc/passwd":              false,
		"ftp://idp.example.com/keys":      false,
		"/relative":                       false,
		"https:///nohost":                 false,
		"http://[::1]:9/keys":             true,
		"http://169.254.169.254/latest/x": false,
	} {
		if err := checkJWKSURI(u); (err == nil) != ok {
			t.Errorf("checkJWKSURI(%q) = %v, want ok=%v", u, err, ok)
		}
	}
}
