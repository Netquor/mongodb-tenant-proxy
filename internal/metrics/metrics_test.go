package metrics

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func scrape(r *Registry) string {
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func TestLegacySeriesStillExposed(t *testing.T) {
	r := New()
	r.ConnsTotal.Add(2)
	r.Command("find", "ok")
	out := scrape(r)
	for _, want := range []string{"mtp_connections_total 2", "mtp_connections_active 0", `mtp_client_bytes_total{direction="in"} 0`, `mtp_commands_total{command="find",outcome="ok"} 1`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestPerTenantSeries(t *testing.T) {
	r := New()
	a := r.Tenant("acme")
	a.Command("find", "ok", 3*time.Millisecond)
	a.Command("insert", "denied", time.Millisecond)
	a.Command("find", "error", 20*time.Second)
	a.BytesIn.Add(10)
	a.BytesOut.Add(20)
	r.SetGaugeSource(func() []TenantGauges {
		return []TenantGauges{{Tenant: "acme", Conns: 2, Cursors: 3, Streams: 1}}
	})
	out := scrape(r)
	for _, want := range []string{
		`mtp_tenant_commands_total{tenant="acme",command="find",outcome="ok"} 1`,
		`mtp_tenant_denials_total{tenant="acme"} 1`,
		`mtp_tenant_errors_total{tenant="acme"} 1`,
		`mtp_tenant_client_bytes_total{tenant="acme",direction="out"} 20`,
		`mtp_tenant_connections_active{tenant="acme"} 2`,
		`mtp_tenant_open_cursors{tenant="acme"} 3`,
		`mtp_tenant_changestream_subscribers{tenant="acme"} 1`,
		`mtp_tenant_command_duration_seconds_bucket{tenant="acme",le="0.005"} 2`,
		`mtp_tenant_command_duration_seconds_bucket{tenant="acme",le="+Inf"} 3`,
		`mtp_tenant_command_duration_seconds_count{tenant="acme"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	st := r.Stats("acme")
	if st.Denials != 1 || st.Errors != 1 || st.Connections != 2 || st.Commands["find|ok"] != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestTopNFoldsOverflowIntoOther(t *testing.T) {
	r := NewWith(config.TenantLabel{Mode: "top", TopN: 2})
	r.PinTenants([]string{"vip"})
	for _, id := range []string{"a", "b", "c", "d"} {
		r.Tenant(id).Command("find", "ok", time.Millisecond)
	}
	out := scrape(r)
	if !strings.Contains(out, `mtp_tenant_commands_total{tenant="a",command="find",outcome="ok"} 1`) {
		t.Fatalf("first-seen tenant must keep its label:\n%s", out)
	}
	if !strings.Contains(out, `mtp_tenant_commands_total{tenant="other",command="find",outcome="ok"} 3`) {
		t.Fatalf("expected folded 'other' series:\n%s", out)
	}
	for _, id := range []string{"b", "c", "d"} {
		if strings.Contains(out, `tenant="`+id+`"`) {
			t.Fatalf("cardinality not bounded (%s):\n%s", id, out)
		}
	}
}

func TestHashModeBoundsLabels(t *testing.T) {
	r := NewWith(config.TenantLabel{Mode: "hash", HashBuckets: 4})
	for i := 0; i < 200; i++ {
		r.Tenant(fmt.Sprintf("t%d", i)).Command("find", "ok", time.Millisecond)
	}
	out := scrape(r)
	n := strings.Count(out, "mtp_tenant_errors_total{")
	if n < 1 || n > 4 {
		t.Fatalf("%d label values for 4 buckets", n)
	}
	if strings.Contains(out, `tenant="t1"`) {
		t.Fatal("raw tenant id exposed in hash mode")
	}
}

func TestOffMode(t *testing.T) {
	r := NewWith(config.TenantLabel{Mode: "off"})
	r.Tenant("x").Command("find", "ok", 0)
	if strings.Contains(scrape(r), "mtp_tenant_") {
		t.Fatal("per-tenant series emitted while off")
	}
}
