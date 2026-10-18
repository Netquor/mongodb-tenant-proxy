//go:build !windows && !plan9

package audit

import (
	"log/syslog"
	"strings"
)

type syslogSink struct{ w *syslog.Writer }

// newSyslog dials syslog. addr is "" (local daemon) or "udp://host:514" / "tcp://host:514".
func newSyslog(addr string) (Sink, error) {
	network, raddr := "", ""
	if addr != "" {
		if i := strings.Index(addr, "://"); i > 0 {
			network, raddr = addr[:i], addr[i+3:]
		} else {
			network, raddr = "udp", addr
		}
	}
	w, err := syslog.Dial(network, raddr, syslog.LOG_INFO|syslog.LOG_AUTH, "mongodb-tenant-proxy")
	if err != nil {
		return nil, err
	}
	return syslogSink{w}, nil
}

func (s syslogSink) Write(p []byte) (int, error) {
	if err := s.w.Info(strings.TrimRight(string(p), "\n")); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s syslogSink) Close() error { return s.w.Close() }
