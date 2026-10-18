package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/netquor/mongodb-tenant-proxy/internal/tenants"
)

// TestMongoTenantStore runs the registry over the MongoDB-backed store and
// checks that a second registry (another replica) sees the same data.
func TestMongoTenantStore(t *testing.T) {
	addr := startMongod(t, false)
	uri := fmt.Sprintf("mongodb://%s/?directConnection=true", addr)
	c := context.Background()
	st, err := tenants.NewMongoStore(c, uri, "mtp_control_test", "t")
	must(t, err)
	defer st.Close()
	reg, err := tenants.NewRegistry(c, st)
	must(t, err)
	_, err = reg.CreateTenant(c, "m1", 4, false)
	must(t, err)
	_, pw, err := reg.SetUser(c, "m1", "mia", "", false)
	must(t, err)
	if pw == "" {
		t.Fatal("no password generated")
	}
	off := true
	_, err = reg.UpdateTenant(c, "m1", &off, nil)
	must(t, err)

	st2, err := tenants.NewMongoStore(c, uri, "mtp_control_test", "t")
	must(t, err)
	defer st2.Close()
	reg2, err := tenants.NewRegistry(c, st2)
	must(t, err)
	if !reg2.Disabled("m1") || reg2.MaxConns("m1") != 4 {
		t.Fatal("tenant not shared through the store")
	}
	if u, ok := reg2.LookupUser("mia"); !ok || u.TenantID != "m1" || u.StoredKey == "" {
		t.Fatalf("user not shared: %+v %v", u, ok)
	}
	must(t, reg.DeleteTenant(c, "m1"))
	must(t, reg2.Refresh(c))
	if _, ok := reg2.LookupUser("mia"); ok {
		t.Fatal("deleted tenant's user still present after refresh")
	}
}
