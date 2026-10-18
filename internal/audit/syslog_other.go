//go:build windows || plan9

package audit

import "errors"

func newSyslog(string) (Sink, error) {
	return nil, errors.New("syslog sink is not supported on this platform")
}
