package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Quota counts a rejection of a tenant's command by a quota (reason is one of
// the limits.Reason* values) and Session counts session-binding rejections.
func (r *Registry) Quota(tenant, reason string) {
	r.quotaCounter("quota\x00" + tenant + "\x00" + reason).Add(1)
}

// SessionRejected counts a command rejected for using another tenant's lsid.
func (r *Registry) SessionRejected(tenant string) { r.quotaCounter("session\x00" + tenant).Add(1) }

// Gauge returns a per-tenant gauge exported as mtp_<name>{tenant="..."}.
func (r *Registry) Gauge(name, tenant string) *Gauge {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := name + "\x00" + tenant
	g := r.gauges[k]
	if g == nil {
		if r.gauges == nil {
			r.gauges = map[string]*Gauge{}
		}
		g = &Gauge{}
		r.gauges[k] = g
	}
	return g
}

func (r *Registry) quotaCounter(k string) *Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.quotas == nil {
		r.quotas = map[string]*Counter{}
	}
	c := r.quotas[k]
	if c == nil {
		c = &Counter{}
		r.quotas[k] = c
	}
	return c
}

// writeQuota is called with r.mu held.
func (r *Registry) writeQuota(w io.Writer) {
	keys := make([]string, 0, len(r.quotas))
	for k := range r.quotas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "# TYPE mtp_quota_rejections_total counter\n")
	for _, k := range keys {
		if p := strings.Split(k, "\x00"); p[0] == "quota" {
			fmt.Fprintf(w, "mtp_quota_rejections_total{tenant=%q,reason=%q} %d\n", p[1], p[2], r.quotas[k].v.Load())
		}
	}
	fmt.Fprintf(w, "# TYPE mtp_session_rejections_total counter\n")
	for _, k := range keys {
		if p := strings.Split(k, "\x00"); p[0] == "session" {
			fmt.Fprintf(w, "mtp_session_rejections_total{tenant=%q} %d\n", p[1], r.quotas[k].v.Load())
		}
	}
	gk := make([]string, 0, len(r.gauges))
	for k := range r.gauges {
		gk = append(gk, k)
	}
	sort.Strings(gk)
	for _, k := range gk {
		p := strings.Split(k, "\x00")
		fmt.Fprintf(w, "mtp_%s{tenant=%q} %d\n", p[0], p[1], r.gauges[k].v.Load())
	}
}
