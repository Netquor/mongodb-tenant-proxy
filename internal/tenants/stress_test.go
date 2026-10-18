package tenants

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Admin-API style CRUD from many goroutines against lock-free readers, config
// reloads (SetStatic) and store refreshes. Readers must always see a
// self-consistent snapshot: every user's tenant exists in the same snapshot.
func TestStressRegistry(t *testing.T) {
	defer stresstest.Watchdog(t, 2*time.Minute)()
	for name, mk := range map[string]func(t *testing.T) Store{
		"memory": func(*testing.T) Store { return nil },
		"file":   func(t *testing.T) Store { return NewFileStore(filepath.Join(t.TempDir(), "tenants.json")) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			r, err := NewRegistry(ctx, mk(t))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var changes atomic.Int64
			r.OnChange(func() { changes.Add(1) })

			iters := stresstest.N(5, 200)
			var wg, readers sync.WaitGroup
			stop := make(chan struct{})
			for i := 0; i < 4; i++ {
				readers.Add(1)
				go func() {
					defer readers.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						snap := r.cur.Load()
						for _, u := range snap.users {
							if _, ok := snap.tenants[u.TenantID]; !ok {
								t.Errorf("snapshot has user %s without tenant %s", u.Username, u.TenantID)
							}
						}
						r.Tenants()
						r.Users("t0")
						r.Disabled("t1")
						r.MaxConns("t2")
						r.LookupUser("u0")
					}
				}()
			}
			for w := 0; w < 6; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					ten := fmt.Sprint("t", w%3) // contended: workers share tenants
					user := fmt.Sprint("u", w)
					yes := true
					for i := 0; i < iters; i++ {
						r.CreateTenant(ctx, ten, 5, false)
						r.UpdateTenant(ctx, ten, &yes, nil)
						no := false
						r.UpdateTenant(ctx, ten, &no, nil)
						r.SetUser(ctx, ten, user, "pw", false)
						r.SetUser(ctx, ten, user, "pw2", true) // password rotation
						r.DeleteUser(ctx, ten, user)
						if i%10 == 0 {
							r.DeleteTenant(ctx, ten)
						}
					}
				}(w)
			}
			wg.Add(2)
			go func() { // hot reload
				defer wg.Done()
				for i := 0; i < iters; i++ {
					r.SetStatic([]config.TenantEntry{{ID: fmt.Sprint("cfg", i%3)}}, nil)
				}
			}()
			go func() { // other replicas' changes
				defer wg.Done()
				for i := 0; i < iters; i++ {
					r.Refresh(ctx)
				}
			}()
			wg.Wait()
			close(stop)
			readers.Wait()
			if changes.Load() == 0 {
				t.Error("no change notifications")
			}
		})
	}
}
