package tenants

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

func TestRegistryFileStorePersistsAndMerges(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tenants.json")
	reg, err := NewRegistry(ctx, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	var changes atomic.Int32
	reg.OnChange(func() { changes.Add(1) })
	reg.SetStatic([]config.TenantEntry{{ID: "fixed", MaxConns: 3}}, []config.User{{Username: "fixed-u", TenantID: "fixed", Salt: "c2FsdA==", Iterations: 1, StoredKey: "a", ServerKey: "b"}})

	if _, err := reg.CreateTenant(ctx, "acme", 5, false); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.CreateTenant(ctx, "acme", 0, false); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	if _, err := reg.CreateTenant(ctx, "bad id!", 0, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid id: %v", err)
	}
	info, pw, err := reg.SetUser(ctx, "acme", "alice", "", false)
	if err != nil || pw == "" || info.TenantID != "acme" {
		t.Fatalf("SetUser: %v %q %+v", err, pw, info)
	}
	if _, ok := reg.LookupUser("alice"); !ok {
		t.Fatal("alice not found")
	}
	if _, _, err := reg.SetUser(ctx, "acme", "alice", "x", false); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate user: %v", err)
	}
	if _, _, err := reg.SetUser(ctx, "acme", "fixed-u", "x", false); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("config user must be read-only: %v", err)
	}
	off := true
	if _, err := reg.UpdateTenant(ctx, "acme", &off, nil); err != nil {
		t.Fatal(err)
	}
	if !reg.Disabled("acme") || reg.MaxConns("acme") != 5 || reg.MaxConns("fixed") != 3 {
		t.Fatal("tenant settings not applied")
	}
	if _, err := reg.UpdateTenant(ctx, "fixed", &off, nil); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("config tenant must be read-only: %v", err)
	}
	if changes.Load() < 3 {
		t.Fatalf("OnChange fired %d times", changes.Load())
	}

	// A second registry over the same file sees the persisted state.
	reg2, err := NewRegistry(ctx, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	if !reg2.Disabled("acme") {
		t.Fatal("disabled flag lost")
	}
	u, ok := reg2.LookupUser("alice")
	if !ok || u.TenantID != "acme" || u.StoredKey == "" {
		t.Fatalf("persisted user: %+v %v", u, ok)
	}
	if got := reg2.Users("acme"); len(got) != 1 || got[0].Source != SourceDynamic {
		t.Fatalf("users: %+v", got)
	}

	if err := reg.DeleteUser(ctx, "acme", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.LookupUser("alice"); ok {
		t.Fatal("alice should be gone")
	}
	if err := reg.DeleteTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := reg.DeleteTenant(ctx, "fixed"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("delete config tenant: %v", err)
	}
	if err := reg.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Tenant("acme"); ok {
		t.Fatal("acme should be deleted")
	}
}

func TestStaticUsersImplyTenants(t *testing.T) {
	reg, _ := NewRegistry(context.Background(), nil)
	reg.SetStatic(nil, []config.User{{Username: "u", TenantID: "t1"}})
	if _, ok := reg.Tenant("t1"); !ok {
		t.Fatal("tenant implied by user missing")
	}
	reg.SetStatic([]config.TenantEntry{{ID: "t1", Disabled: true}}, nil)
	if !reg.Disabled("t1") {
		t.Fatal("declared tenant should be disabled")
	}
}
