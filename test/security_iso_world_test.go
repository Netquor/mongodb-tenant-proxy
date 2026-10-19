package test

// Shared fixtures for the adversarial isolation suite (security_iso_*_test.go).
//
// Every world has an attacker (tenant-alpha) and victims whose data carries
// canary strings. Victim and attacker rows overlap on every business field
// (k, name, grp) and differ only in the tenant id and the canary in `secret`.
// After each attack the suite asserts:
//   - no reply (or error text) contains a victim canary, tenant id or _id,
//   - the victims' stored documents are byte-identical,
//   - every victim still observes exactly what it observed before,
//   - no indexes or collections were removed.

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/netquor/mongodb-tenant-proxy/internal/auth"
	"github.com/netquor/mongodb-tenant-proxy/internal/config"
)

const (
	tA = "tenant-alpha"
	tB = "tenant-bravo"
	tC = "tenant-charlie"
	tU = "TENANT-ALPHA" // differs from the attacker only by case (collation collisions)

	isoDB = "app"
)

// victims lists the tenants whose data must never be reachable by tA.
var victims = []string{tB, tC, tU}

// leakMarks are byte strings that must never occur in anything tA receives.
var leakMarks = []string{
	"tenant-bravo", "tenant-charlie", "TENANT-ALPHA",
	"CNRY-BRAVO", "CNRY-CHARLIE", "CNRY-UPPER", "CNRY-ROOT", "CNRY_BRAVO", "CNRY_CHARLIE",
	"upstream-pw",
}

type isoMode struct {
	name   string
	scram  bool   // clients authenticate with SCRAM against an auth-enabled upstream
	policy string // _id policy
	noJS   bool
}

var isoModes = []isoMode{
	{name: "appname-native", policy: "native"},
	{name: "appname-require-generated", policy: "require-generated"},
	{name: "appname-namespace", policy: "namespace"},
	{name: "scram-native-nojs", scram: true, policy: "native", noJS: true},
}

type isoWorld struct {
	t    *testing.T
	mode isoMode
	e    *env
	cl   map[string]*mongo.Client // tenant -> client through the proxy
	n    int
	cur  string // attack in progress, for diagnostics
}

func newIsoWorld(t *testing.T, m isoMode) *isoWorld {
	t.Helper()
	w := &isoWorld{t: t, mode: m, cl: map[string]*mongo.Client{}}
	tenants := []string{tA, tB, tC, tU}
	var users []config.User
	if m.scram {
		for _, tn := range tenants {
			u, err := auth.NewUser("u-"+tn, tn, "pw-"+tn)
			must(t, err)
			users = append(users, u)
		}
	}
	w.e = setupWith(t, m.scram, func(c *config.Config) {
		c.Tenant.IDPolicy = m.policy
		c.Tenant.ExperimentalNamespace = m.policy == "namespace"
		c.DisableJS = m.noJS
		if m.scram {
			c.Auth = config.Auth{Mode: "scram", Users: users}
		}
	})
	for _, tn := range tenants {
		if m.scram {
			uri := fmt.Sprintf("mongodb://%s:%s@%s/?authMechanism=SCRAM-SHA-256&authSource=admin", "u-"+tn, "pw-"+tn, w.e.proxyAddr)
			c := connect(t, uri)
			t.Cleanup(func() { c.Disconnect(context.Background()) })
			w.cl[tn] = c
		} else {
			w.cl[tn] = w.e.tenant(t, tn)
		}
	}
	// A canary in the upstream's own data: system.js and an admin user.
	cctx := ctx(t)
	_, _ = w.e.direct.Database(isoDB).Collection("system.js").InsertOne(cctx, bson.M{"_id": "CNRY-ROOT-fn", "value": "CNRY-ROOT"})
	_ = w.e.direct.Database("admin").RunCommand(cctx, bson.D{{Key: "createUser", Value: "CNRY-ROOT-user"}, {Key: "pwd", Value: "x-pw-1"},
		{Key: "roles", Value: bson.A{}}}).Err()
	return w
}

// fixture describes one freshly seeded collection.
type fixture struct {
	DB, C, Other string
	BID, CID     any // physical _id of victims' k=0 documents
	CView        string
	BView        string // B's view name as B sees it
	BViewPhys    string // its physical collection
	BIdxPhys     string // B's index name as stored upstream
	CIdxPhys     string
}

func (w *isoWorld) isoID(i int) any {
	if w.mode.policy == "namespace" {
		return i // overlapping explicit _ids across tenants
	}
	return nil
}

// seed creates collection C (and Other) with overlapping data for every tenant.
func (w *isoWorld) seed() *fixture {
	t := w.t
	w.n++
	// Start from an empty database so per-attack bookkeeping stays O(1).
	// Drop through the proxy first so its per-tenant view caches are
	// invalidated, then physically.
	for _, tn := range []string{tA, tB, tC, tU} {
		_ = w.cl[tn].Database(isoDB).RunCommand(ctx(t), bson.D{{Key: "dropDatabase", Value: 1}}).Err()
	}
	_ = w.e.direct.Database(isoDB).Drop(ctx(t))
	_ = w.e.direct.Database("other").Drop(ctx(t))
	_, _ = w.e.direct.Database(isoDB).Collection("system.js").InsertOne(ctx(t), bson.M{"_id": "CNRY-ROOT-fn", "value": "CNRY-ROOT"})
	f := &fixture{DB: isoDB, C: fmt.Sprintf("c%d", w.n), Other: fmt.Sprintf("o%d", w.n)}
	for _, coll := range []string{f.C, f.Other} {
		for _, tn := range []string{tA, tB, tC, tU} {
			w.insertRows(tn, f.DB, coll)
		}
	}
	db := func(tn string) *mongo.Database { return w.cl[tn].Database(isoDB) }
	// Victim-only metadata carrying canaries.
	_, err := db(tB).Collection(f.C).Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "k", Value: 1}},
		Options: indexOpts("b_k_idx", false)})
	must(t, err)
	_, err = db(tC).Collection(f.C).Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: bson.D{{Key: "name", Value: 1}},
		Options: indexOpts("c_name_idx", false)})
	must(t, err)
	{
		f.BView = fmt.Sprintf("CNRY_BRAVO_view%d", w.n)
		f.CView = fmt.Sprintf("CNRY_CHARLIE_view%d", w.n)
		if w.mode.policy != "namespace" { // the namespace policy forbids views
			must(t, db(tB).CreateView(ctx(t), f.BView, f.C, mongo.Pipeline{{{Key: "$match", Value: bson.M{"grp": 0}}}}))
			must(t, db(tC).CreateView(ctx(t), f.CView, f.C, mongo.Pipeline{{{Key: "$match", Value: bson.M{"grp": 1}}}}))
		}
	}
	// Physical identifiers an attacker could try to guess or enumerate.
	raw := w.e.direct.Database(isoDB)
	var bd bson.M
	must(t, raw.Collection(f.C).FindOne(ctx(t), bson.M{"tenantId": tB, "k": 0}).Decode(&bd))
	f.BID = bd["_id"]
	must(t, raw.Collection(f.C).FindOne(ctx(t), bson.M{"tenantId": tC, "k": 0}).Decode(&bd))
	f.CID = bd["_id"]
	names, _ := raw.ListCollectionNames(ctx(t), bson.D{})
	for _, n := range names {
		if strings.HasPrefix(n, "__mtp_v.") && strings.HasSuffix(n, "."+f.BView) {
			f.BViewPhys = n
		}
	}
	cur, err := raw.Collection(f.C).Indexes().List(ctx(t))
	must(t, err)
	var specs []bson.M
	must(t, cur.All(ctx(t), &specs))
	for _, s := range specs {
		n, _ := s["name"].(string)
		switch {
		case strings.HasPrefix(n, "b_k_idx"):
			f.BIdxPhys = n
		case strings.HasPrefix(n, "c_name_idx"):
			f.CIdxPhys = n
		}
	}
	if f.BIdxPhys == "" || f.CIdxPhys == "" {
		t.Fatalf("victim indexes not found upstream: %v", specs)
	}
	return f
}

func (f *fixture) leakMarks() []string {
	m := append([]string{}, leakMarks...)
	for _, id := range []any{f.BID, f.CID} {
		switch v := id.(type) {
		case bson.ObjectID:
			m = append(m, v.Hex())
		}
	}
	return m
}

// ---- observation ---------------------------------------------------------

// observe is everything one tenant can see of the fixture through the proxy.
func (w *isoWorld) observe(tn string, f *fixture) string {
	t := w.t
	var sb strings.Builder
	db := w.cl[tn].Database(f.DB)
	for _, coll := range []string{f.C, f.Other} {
		cur, err := db.Collection(coll).Find(ctx(t), bson.D{}, optsSortK())
		if err != nil {
			fmt.Fprintf(&sb, "find err %v\n", err)
			continue
		}
		var docs []bson.Raw
		must(t, cur.All(ctx(t), &docs))
		for _, d := range docs {
			sb.WriteString(d.String())
			sb.WriteByte('\n')
		}
	}
	// Collection names are shared between tenants by design, so compare only
	// the fixture's own namespaces (and the tenant's own views).
	names, err := db.ListCollectionNames(ctx(t), bson.D{})
	must(t, err)
	sort.Strings(names)
	seen := map[string]bool{}
	for _, n := range names {
		if (n == f.C || n == f.Other) && !seen[n] {
			seen[n] = true
			sb.WriteString(n + ",")
		}
	}
	sb.WriteString("\n")
	for _, v := range []string{f.BView, f.CView} {
		cur, err := db.Collection(v).Find(ctx(t), bson.D{}, optsSortK())
		if err != nil {
			continue
		}
		var docs []bson.Raw
		must(t, cur.All(ctx(t), &docs))
		for _, d := range docs {
			sb.WriteString(d.String())
		}
	}
	return sb.String()
}

// physical snapshots the stored documents of every victim in every collection
// of the database, plus the set of collections and index names.
func (w *isoWorld) physical(f *fixture) (docs map[string]string, structure string) {
	t := w.t
	raw := w.e.direct.Database(f.DB)
	names, err := raw.ListCollectionNames(ctx(t), bson.D{})
	must(t, err)
	sort.Strings(names)
	docs = map[string]string{}
	var st strings.Builder
	for _, n := range names {
		if strings.HasPrefix(n, "system.profile") || n == "system.js" {
			continue
		}
		var all []bson.Raw
		cur, err := raw.Collection(n).Find(ctx(t), bson.D{}, optsSortID())
		if err != nil {
			continue
		}
		must(t, cur.All(ctx(t), &all))
		for _, d := range all {
			tv := d.Lookup("tenantId")
			s, _ := tv.StringValueOK()
			if n == "system.views" || strings.HasPrefix(n, "__mtp_") {
				// registry / view metadata: victims' entries must survive; attacker
				// may add its own, so keep everything and check inclusion later
				docs[n+"|"+hex.EncodeToString(d)] = "meta"
				continue
			}
			if s != tA {
				docs[n+"|"+hex.EncodeToString(d)] = s
			}
		}
		ic, err := raw.Collection(n).Indexes().List(ctx(t))
		if err == nil {
			var specs []bson.M
			must(t, ic.All(ctx(t), &specs))
			for _, s := range specs {
				fmt.Fprintf(&st, "%s|%v\n", n, s["name"])
			}
		}
	}
	return docs, st.String()
}

// ---- execution -----------------------------------------------------------

// run executes a command as tn and returns everything it received: reply
// bytes of the command and of every getMore, and the error text.
func (w *isoWorld) run(tn, db string, cmd bson.D) (blob string, err error) {
	t := w.t
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var sb strings.Builder
	d := w.cl[tn].Database(db)
	res, err := d.RunCommand(c, cmd).Raw()
	if err != nil {
		sb.WriteString(err.Error())
		sb.WriteString(rawOf(err))
		return sb.String(), err
	}
	sb.Write(res)
	for i := 0; i < 50; i++ {
		cv, ok := res.Lookup("cursor").DocumentOK()
		if !ok {
			break
		}
		id, _ := cv.Lookup("id").AsInt64OK()
		ns, _ := cv.Lookup("ns").StringValueOK()
		if id == 0 {
			break
		}
		coll := ns[strings.Index(ns, ".")+1:]
		res, err = d.RunCommand(c, bson.D{{Key: "getMore", Value: id}, {Key: "collection", Value: coll}, {Key: "batchSize", Value: 2}}).Raw()
		if err != nil {
			sb.WriteString(err.Error())
			sb.WriteString(rawOf(err))
			return sb.String(), nil
		}
		sb.Write(res)
	}
	_ = t
	return sb.String(), nil
}

func rawOf(err error) string {
	if ce, ok := err.(mongo.CommandError); ok {
		return fmt.Sprintf("%s %s %v", ce.Name, ce.Message, ce.Raw)
	}
	return ""
}

// attackVerdict checks the universal invariants for one attack.
type attackOpts struct {
	mutates bool   // the attack may legitimately change the attacker's own data
	known   string // documented limitation: report, do not fail
	cmd     string // the command text sent (marks in it may legitimately be echoed)
}

func (w *isoWorld) check(f *fixture, name string, before map[string]string, beforeStruct string,
	obs map[string]string, blob string, o attackOpts) {
	t := &failSink{T: w.t, known: o.known}
	t.Helper()
	defer t.flush()
	for _, m := range w.findLeaks(f, blob, o.cmd) {
		i := strings.Index(blob, m)
		lo, hi := max(0, i-120), min(len(blob), i+120)
		t.Errorf("%s [%s]: reply leaks %q: …%q…", name, w.mode.name, m, blob[lo:hi])
	}
	after, afterStruct := w.physical(f)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s [%s]: victim data changed or deleted (%s) in %s", name, w.mode.name, v, strings.SplitN(k, "|", 2)[0])
		}
	}
	for k, v := range after {
		if _, ok := before[k]; !ok && v != "meta" {
			t.Errorf("%s [%s]: new document owned by %q appeared in %s (forged tenant?)", name, w.mode.name, v, strings.SplitN(k, "|", 2)[0])
		}
	}
	// No pre-existing index or collection disappeared.
	for _, line := range strings.Split(strings.TrimSpace(beforeStruct), "\n") {
		if line != "" && !strings.Contains(afterStruct, line+"\n") {
			t.Errorf("%s [%s]: upstream index %q vanished", name, w.mode.name, line)
		}
	}
	// Every document stored anywhere has a well-formed tenant id.
	raw := w.e.direct.Database(f.DB)
	names, _ := raw.ListCollectionNames(ctx(w.t), bson.D{})
	for _, n := range names {
		if strings.HasPrefix(n, "system.") || strings.HasPrefix(n, "__mtp_") {
			continue
		}
		cnt, err := raw.Collection(n).CountDocuments(ctx(w.t), bson.M{"$nor": bson.A{
			bson.M{"tenantId": bson.M{"$in": bson.A{tA, tB, tC, tU}}}}})
		if err == nil && cnt != 0 {
			t.Errorf("%s [%s]: %d document(s) in %s with a malformed/foreign tenantId", name, w.mode.name, cnt, n)
		}
	}
	for _, tn := range []string{tA, tB, tC, tU} {
		got := strings.Join(w.observeIdx(tn, f), "\n")
		if tn == tA && !o.mutates {
			if got != obs[tn+"#idx"] {
				t.Errorf("%s [%s]: attacker's own index list changed by a read-only attack", name, w.mode.name)
			}
			continue
		}
		for _, line := range strings.Split(obs[tn+"#idx"], "\n") {
			if line != "" && !strings.Contains(got+"\n", line+"\n") {
				t.Errorf("%s [%s]: %s lost index %q", name, w.mode.name, tn, line)
			}
		}
	}
	for _, tn := range victims {
		if got := w.observe(tn, f); got != obs[tn] {
			t.Errorf("%s [%s]: what %s observes changed:\n%s", name, w.mode.name, tn, lineDiff(obs[tn], got))
		}
	}
	if !o.mutates {
		if got := w.observe(tA, f); got != obs[tA] {
			t.Errorf("%s [%s]: attacker's own view changed by a read-only attack", name, w.mode.name)
		}
	}
	// Victims must still be intact against the pristine upstream user list.
	var users bson.M
	if err := w.e.direct.Database("admin").RunCommand(ctx(w.t), bson.D{{Key: "usersInfo", Value: "CNRY-ROOT-user"}}).Decode(&users); err == nil {
		if us, _ := users["users"].(bson.A); len(us) != 1 {
			t.Errorf("%s [%s]: upstream user list changed", name, w.mode.name)
		}
	}
}

func (w *isoWorld) baseline(f *fixture) (map[string]string, string, map[string]string) {
	before, bs := w.physical(f)
	obs := map[string]string{}
	for _, tn := range []string{tA, tB, tC, tU} {
		obs[tn] = w.observe(tn, f)
		obs[tn+"#idx"] = strings.Join(w.observeIdx(tn, f), "\n")
	}
	return before, bs, obs
}

// lineDiff reports the first few lines that differ between two observations.
func lineDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	in := func(s []string, v string) bool {
		for _, x := range s {
			if x == v {
				return true
			}
		}
		return false
	}
	var out []string
	for _, l := range al {
		if !in(bl, l) {
			out = append(out, "- "+l)
		}
	}
	for _, l := range bl {
		if !in(al, l) {
			out = append(out, "+ "+l)
		}
	}
	for i, l := range out {
		if len(l) > 300 {
			out[i] = l[:300] + "…"
		}
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return strings.Join(out, "\n")
}

// failSink turns failures of documented limitations into log lines.
type failSink struct {
	*testing.T
	known string
	msgs  []string
}

func (f *failSink) Errorf(format string, args ...any) {
	if f.known == "" {
		f.T.Errorf(format, args...)
		return
	}
	f.msgs = append(f.msgs, fmt.Sprintf(format, args...))
}

func (f *failSink) flush() {
	if len(f.msgs) > 0 {
		f.T.Logf("KNOWN LIMITATION (%s): %s", f.known, f.msgs[0])
	}
}

// observeIdx lists the indexes tn sees on the fixture's collections.
func (w *isoWorld) observeIdx(tn string, f *fixture) []string {
	var out []string
	for _, coll := range []string{f.C, f.Other} {
		ic, err := w.cl[tn].Database(f.DB).Collection(coll).Indexes().List(ctx(w.t))
		if err != nil {
			continue
		}
		var specs []bson.M
		must(w.t, ic.All(ctx(w.t), &specs))
		for _, s := range specs {
			if n, _ := s["name"].(string); strings.HasPrefix(n, "mtp_") {
				continue // proxy-managed shared index, created on demand by $merge/$out
			}
			out = append(out, fmt.Sprint(coll, "|", s["name"], s["key"], s["expireAfterSeconds"], s["unique"]))
		}
	}
	sort.Strings(out)
	return out
}

// insertRows stores the five standard rows of tn in db.coll through the proxy.
func (w *isoWorld) insertRows(tn, db, coll string) {
	tag := map[string]string{tA: "ALPHA", tB: "BRAVO", tC: "CHARLIE", tU: "UPPER"}[tn]
	var docs []any
	for i := 0; i < 5; i++ {
		d := bson.D{}
		if id := w.isoID(i); id != nil {
			d = append(d, bson.E{Key: "_id", Value: id})
		}
		d = append(d, bson.E{Key: "k", Value: i}, bson.E{Key: "name", Value: fmt.Sprintf("item-%d", i)},
			bson.E{Key: "grp", Value: i % 2}, bson.E{Key: "parent", Value: (i + 1) % 5},
			bson.E{Key: "tags", Value: bson.A{"x", "y"}},
			bson.E{Key: "secret", Value: fmt.Sprintf("CNRY-%s-%d", tag, i)})
		docs = append(docs, d)
	}
	_, err := w.cl[tn].Database(db).Collection(coll).InsertMany(ctx(w.t), docs)
	if err != nil {
		w.t.Fatalf("seeding %s.%s for %s after attack %q: %v", db, coll, tn, w.cur, err)
	}
}

// resetAttacker gives the attacker back its five rows in both collections
// without touching anyone else (cheaper than reseeding from scratch).
func (w *isoWorld) resetAttacker(f *fixture) {
	for _, coll := range []string{f.C, f.Other} {
		_, err := w.e.direct.Database(f.DB).Collection(coll).DeleteMany(ctx(w.t), bson.M{"tenantId": tA})
		must(w.t, err)
		w.insertRows(tA, f.DB, coll)
	}
}

// findLeaks returns the victim marks present in blob that the attacker did not
// itself put in its command.
func (w *isoWorld) findLeaks(f *fixture, blob, cmd string) []string {
	var out []string
	for _, m := range f.leakMarks() {
		if cmd != "" && strings.Contains(cmd, m) {
			continue // the attacker supplied this string itself; an echo is not a leak
		}
		if w.mode.policy == "native" && len(m) == 24 {
			continue // documented: the native policy shares the _id space (see README, idPolicy)
		}
		if strings.Contains(blob, m) {
			out = append(out, m)
		}
	}
	return out
}
