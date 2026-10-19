package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/netquor/mongodb-tenant-proxy/internal/admin"
	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
	"github.com/netquor/mongodb-tenant-proxy/internal/stresstest"
)

// Hot reload (admin endpoint and "SIGHUP" - both call Server.Reload), tenants
// being disabled/enabled, users rotated, and admin-API CRUD, all while
// connections issue commands, metrics are scraped and audit events written.
//
// Invariants: no deadlock, no recovered panic, a tenant never reads another
// tenant's documents, and once the chaos stops the system converges: every
// enabled tenant can log in with its final password, a disabled one cannot
// and has no live connections, and no goroutine / descriptor leaks.
func TestStressReloadAdminChurn(t *testing.T) {
	defer stresstest.Watchdog(t, 5*time.Minute)()
	t.Cleanup(stresstest.NoLeak(t, 12))

	const nT = 4
	var gen [nT]atomic.Int64 // password generation per config user
	pw := func(i int, g int64) string { return fmt.Sprintf("pw-%d-%d", i, g) }
	var userCache sync.Map // password -> config.User (PBKDF2 is slow under -race)
	mkUsers := func() []config.User {
		us := make([]config.User, nT)
		for i := range us {
			p := pw(i, gen[i].Load())
			if v, ok := userCache.Load(p); ok {
				us[i] = v.(config.User)
				continue
			}
			u, err := auth.NewUser(fmt.Sprint("u", i), fmt.Sprint("t", i), p)
			if err != nil {
				t.Fatal(err)
			}
			userCache.Store(p, u)
			us[i] = u
		}
		return us
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	e := setupOps(t, func(c *config.Config) {
		c.Auth.Users = mkUsers()
		c.Auth.BruteForce.MaxFailures = -1 // this test deliberately provokes auth failures from one address
		c.Audit = config.Audit{Enabled: true, Sink: "file", Path: auditPath, SampleReads: 1}
		c.Admin = config.Admin{Token: "0123456789abcdef-token"}
	})
	adm, err := admin.New(e.srv, e.cfg.Admin)
	must(t, err)
	hs := httptest.NewServer(adm.Handler())
	defer hs.Close()
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	call := func(method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, hs.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer 0123456789abcdef-token")
		resp, err := hc.Do(req)
		if err != nil {
			t.Errorf("admin %s %s: %v", method, path, err)
			return 0, nil
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	var cfgMu sync.Mutex // serialises config-file rewrites
	disabled := map[string]bool{}
	var deny atomic.Bool
	rewrite := func() {
		cfgMu.Lock()
		defer cfgMu.Unlock()
		e.cfg.Auth.Users = mkUsers()
		e.cfg.Tenants = nil
		for id, d := range disabled {
			e.cfg.Tenants = append(e.cfg.Tenants, config.TenantEntry{ID: id, Disabled: d})
		}
		e.cfg.DenyCommands = nil
		if deny.Load() {
			e.cfg.DenyCommands = []string{"collStats"}
		}
		b, _ := json.Marshal(e.cfg)
		tmp := e.cfg.Path + ".tmp"
		os.WriteFile(tmp, b, 0o600)
		os.Rename(tmp, e.cfg.Path) // atomic: Reload never sees half a file
	}

	end := time.Now().Add(stresstest.D(5*time.Second, 90*time.Second))
	var wg sync.WaitGroup
	spawn := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }

	// reload driver: disable/enable tenants, rotate passwords, flip deny list
	spawn(func() {
		rng := rand.New(rand.NewSource(1))
		for time.Now().Before(end) {
			cfgMu.Lock()
			// t0 and t2 stay enabled with stable passwords so that real work
			// keeps flowing while t1 and t3 are disabled, enabled and rotated.
			switch r := rng.Intn(10); {
			case r < 3:
				disabled[fmt.Sprint("t", 1+2*rng.Intn(2))] = rng.Intn(2) == 0
			case r < 5:
				gen[1+2*rng.Intn(2)].Add(1)
			default:
				deny.Store(!deny.Load())
			}
			cfgMu.Unlock()
			rewrite()
			if _, err := e.srv.Reload(); err != nil {
				t.Errorf("reload: %v", err)
				return
			}
			time.Sleep(time.Duration(10+rng.Intn(40)) * time.Millisecond)
		}
	})
	// SIGHUP-style and admin-endpoint reloads racing the driver
	spawn(func() {
		for time.Now().Before(end) {
			e.srv.Reload()
			time.Sleep(30 * time.Millisecond)
		}
	})
	spawn(func() {
		for time.Now().Before(end) {
			call("POST", "/v1/reload", "")
			time.Sleep(40 * time.Millisecond)
		}
	})
	// admin CRUD on dynamic tenants/users plus kills
	var dynPW sync.Map // tenant -> password
	spawn(func() {
		rng := rand.New(rand.NewSource(2))
		for time.Now().Before(end) {
			id := fmt.Sprint("dyn", rng.Intn(3))
			switch rng.Intn(9) {
			case 0:
				call("POST", "/v1/tenants", fmt.Sprintf(`{"id":%q}`, id))
			case 1:
				code, b := call("POST", "/v1/tenants/"+id+"/users", `{"username":"du-`+id+`"}`)
				if code == 201 {
					var r struct {
						Password string `json:"password"`
					}
					json.Unmarshal(b, &r)
					dynPW.Store(id, r.Password)
				}
			case 2:
				call("POST", "/v1/tenants/"+id+"/disable", "")
			case 3:
				call("POST", "/v1/tenants/"+id+"/enable", "")
			case 4:
				call("DELETE", "/v1/tenants/"+id+"/users/du-"+id, "")
			case 5:
				call("DELETE", "/v1/tenants/"+id, "")
			case 6:
				call("DELETE", "/v1/tenants/"+id+"/connections", "")
			case 7:
				call("GET", "/v1/connections", "")
				call("GET", "/v1/tenants/"+id+"/stats", "")
			default:
				if code, b := call("PUT", "/v1/tenants/"+id+"/users/du-"+id, `{}`); code == 200 {
					var r struct {
						Password string `json:"password"`
					}
					json.Unmarshal(b, &r)
					dynPW.Store(id, r.Password)
				}
			}
		}
	})
	// metrics + connection inspection
	spawn(func() {
		for time.Now().Before(end) {
			rec := httptest.NewRecorder()
			e.srv.M.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			e.srv.Connections("")
			e.srv.TenantStats("t0")
			time.Sleep(2 * time.Millisecond)
		}
	})

	// clients
	var okOps, rejected atomic.Int64
	client := func(user, tenant, password string) *mongo.Client {
		uri := fmt.Sprintf("mongodb://%s:%s@%s/?authMechanism=SCRAM-SHA-256&authSource=admin", user, password, e.proxyAddr)
		c, err := mongo.Connect(options.Client().ApplyURI(uri).SetMaxPoolSize(2).SetServerSelectionTimeout(3 * time.Second))
		if err != nil {
			return nil
		}
		return c
	}
	for w := 0; w < nT*2; w++ {
		w := w
		spawn(func() {
			i := w % nT
			tenant := fmt.Sprint("t", i)
			for time.Now().Before(end) {
				c := client(fmt.Sprint("u", i), tenant, pw(i, gen[i].Load()))
				if c == nil {
					continue
				}
				coll := c.Database("rl").Collection("c")
				for k := 0; k < 15 && time.Now().Before(end); k++ {
					cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_, err := coll.InsertOne(cx, bson.M{"o": tenant, "k": k})
					if err == nil {
						var got []bson.M
						cur, ferr := coll.Find(cx, bson.M{})
						if ferr == nil {
							cur.All(cx, &got)
						}
						for _, d := range got {
							if d["o"] != tenant {
								t.Errorf("tenant %s read %v", tenant, d)
							}
						}
						okOps.Add(1)
					} else {
						rejected.Add(1)
					}
					cancel()
				}
				cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				c.Disconnect(cx)
				cancel()
			}
		})
	}
	for w := 0; w < 3; w++ {
		w := w
		spawn(func() {
			id := fmt.Sprint("dyn", w)
			for time.Now().Before(end) {
				p, ok := dynPW.Load(id)
				if !ok {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				c := client("du-"+id, id, p.(string))
				if c == nil {
					continue
				}
				cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				c.Database("rl").Collection("c").InsertOne(cx, bson.M{"o": id})
				var got []bson.M
				if cur, err := c.Database("rl").Collection("c").Find(cx, bson.M{}); err == nil {
					cur.All(cx, &got)
				}
				for _, d := range got {
					if d["o"] != id {
						t.Errorf("dynamic tenant %s read %v", id, d)
					}
				}
				c.Disconnect(cx)
				cancel()
			}
		})
	}
	wg.Wait()

	// ---- convergence ------------------------------------------------------
	cfgMu.Lock()
	for k := range disabled {
		disabled[k] = false
	}
	disabled["t1"] = true
	deny.Store(false)
	cfgMu.Unlock()
	rewrite()
	if _, err := e.srv.Reload(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, "t1's connections to be gone", func() bool { return len(e.srv.Connections("t1")) == 0 })
	for i := 0; i < nT; i++ {
		c := client(fmt.Sprint("u", i), fmt.Sprint("t", i), pw(i, gen[i].Load()))
		cx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, err := c.Database("rl").Collection("c").InsertOne(cx, bson.M{"o": fmt.Sprint("t", i), "final": true})
		cancel()
		if (i == 1) == (err == nil) {
			t.Errorf("t%d (disabled=%v): insert err=%v", i, i == 1, err)
		}
		c.Disconnect(context.Background())
	}
	eventually(t, 20*time.Second, "all connections to close", func() bool { return len(e.srv.Connections("")) == 0 })
	hc.CloseIdleConnections()
	t.Logf("ok ops=%d rejected=%d", okOps.Load(), rejected.Load())
	if st, _ := os.Stat(auditPath); st == nil || st.Size() == 0 {
		t.Error("audit log is empty")
	}
}
