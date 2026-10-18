package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQuotaMetricsExported(t *testing.T) {
	r := New()
	r.Quota("a", "ops_rate")
	r.Quota("a", "ops_rate")
	r.Quota("b", "open_cursors")
	r.SessionRejected("a")
	r.Gauge("open_cursors", "a").Add(3)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		`mtp_quota_rejections_total{tenant="a",reason="ops_rate"} 2`,
		`mtp_quota_rejections_total{tenant="b",reason="open_cursors"} 1`,
		`mtp_session_rejections_total{tenant="a"} 1`,
		`mtp_open_cursors{tenant="a"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}
