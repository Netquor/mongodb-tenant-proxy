package test

// Differential testing: a random benign workload generated from a small
// grammar is replayed (a) by tenant-alpha through the proxy, while tenants
// bravo and charlie replay the very same workload so their rows overlap with
// alpha's on every business field, and (b) directly against a private
// database holding only alpha's data. Every observable result must be
// identical; a difference is either a leak (extra rows) or over-filtering
// (missing rows / spurious errors).

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type diffGen struct {
	r      *rand.Rand
	nextU  map[string]int
	stepNo int
}

type diffOp struct {
	desc   string
	sorted bool // compare as a sequence rather than a multiset
	run    func(db *mongo.Database) (any, error)
}

var diffColls = []string{"items", "other"}

func (g *diffGen) pick(n int) int { return g.r.Intn(n) }

func (g *diffGen) leaf() bson.D {
	r := g.r
	switch r.Intn(14) {
	case 0:
		return d("k", r.Intn(10))
	case 1:
		return d("grp", d("$gt", r.Intn(3)))
	case 2:
		return d("v", d("$gte", r.Intn(100), "$lt", 50+r.Intn(60)))
	case 3:
		return d("name", d("$ne", fmt.Sprintf("item-%d", r.Intn(10))))
	case 4:
		return d("tags", d("$in", arr("x", "z")))
	case 5:
		return d("u", d("$in", arr(r.Intn(40), r.Intn(40), r.Intn(40))))
	case 6:
		return d("name", d("$exists", r.Intn(2) == 0))
	case 7:
		return d("name", d("$regex", fmt.Sprintf("^item-%d", r.Intn(10))))
	case 8:
		return d("v", d("$mod", arr(3, r.Intn(3))))
	case 9:
		return d("tags", d("$size", r.Intn(4)))
	case 10:
		return d("tags", d("$all", arr("x")))
	case 11:
		return d("$expr", d("$gt", arr("$v", r.Intn(100))))
	case 12:
		return d("k", d("$nin", arr(r.Intn(10), r.Intn(10))))
	default:
		return d("tags", d("$elemMatch", d("$eq", "y")))
	}
}

func (g *diffGen) filter(depth int) bson.D {
	if depth <= 0 || g.r.Intn(3) == 0 {
		return g.leaf()
	}
	switch g.r.Intn(5) {
	case 0:
		return d("$and", arr(g.filter(depth-1), g.filter(depth-1)))
	case 1:
		return d("$or", arr(g.filter(depth-1), g.filter(depth-1)))
	case 2:
		return d("$nor", arr(g.filter(depth-1)))
	case 3:
		return d("$and", arr(g.leaf(), d("$or", arr(g.leaf(), g.leaf()))))
	default:
		return g.leaf()
	}
}

func (g *diffGen) doc(coll string) bson.D {
	g.nextU[coll]++
	r := g.r
	tags := bson.A{}
	for _, tg := range []string{"x", "y", "z"} {
		if r.Intn(2) == 0 {
			tags = append(tags, tg)
		}
	}
	k := r.Intn(10)
	return d("u", g.nextU[coll], "k", k, "grp", r.Intn(3), "v", r.Intn(100), "name", fmt.Sprintf("item-%d", k),
		"tags", tags, "parent", r.Intn(10))
}

func (g *diffGen) coll() string { return diffColls[g.r.Intn(len(diffColls))] }

func (g *diffGen) update() any {
	r := g.r
	switch r.Intn(12) {
	case 0:
		return d("$set", d("v", r.Intn(100)))
	case 1:
		return d("$inc", d("v", r.Intn(5)-2))
	case 2:
		return d("$unset", d("name", ""))
	case 3:
		return d("$push", d("tags", "z"))
	case 4:
		return d("$addToSet", d("tags", "x"))
	case 5:
		return d("$pull", d("tags", "y"))
	case 6:
		return d("$min", d("v", r.Intn(100)))
	case 7:
		return d("$mul", d("v", 2))
	case 8:
		return d("$rename", d("name", "nm"))
	case 9:
		return arr(d("$set", d("v", d("$add", arr("$v", 1)))))
	case 10:
		return d("$set", d("tags.0", "q"))
	default:
		return d("$set", d("grp", r.Intn(3)), "$inc", d("k", 0))
	}
}

func (g *diffGen) stage(coll string, last bool) bson.D {
	r := g.r
	other := diffColls[(diffIndexOf(diffColls, coll)+1)%len(diffColls)]
	switch r.Intn(20) {
	case 0:
		return d("$match", g.filter(2))
	case 1:
		return d("$project", d("u", 1, "k", 1, "v", 1, "grp", 1))
	case 2:
		return d("$project", d("name", 0, "tags", 0))
	case 3:
		return d("$addFields", d("w", d("$add", arr("$v", "$k"))))
	case 4:
		return d("$unwind", d("path", "$tags", "preserveNullAndEmptyArrays", true))
	case 5:
		return d("$limit", 1+r.Intn(30))
	case 6:
		return d("$skip", r.Intn(10))
	case 7:
		return d("$lookup", d("from", other, "localField", "k", "foreignField", "k", "as", "j",
			"pipeline", arr(d("$sort", d("u", 1)), d("$project", d("u", 1, "v", 1)))))
	case 8:
		return d("$lookup", d("from", other, "let", d("kk", "$k"), "as", "j",
			"pipeline", arr(d("$match", d("$expr", d("$eq", arr("$k", "$$kk")))), d("$sort", d("u", 1)), d("$limit", 3))))
	case 9:
		return d("$unionWith", d("coll", other, "pipeline", arr(d("$match", g.filter(1)), d("$project", d("u", 1, "k", 1, "v", 1, "grp", 1)))))
	case 10:
		return d("$facet", d("a", arr(d("$match", g.filter(1)), d("$count", "n")), "b", arr(d("$group", d("_id", "$grp", "s", d("$sum", "$v"))))))
	case 11:
		return d("$bucket", d("groupBy", "$v", "boundaries", arr(0, 25, 50, 75, 100), "default", "other", "output", d("n", d("$sum", 1))))
	case 12:
		return d("$sortByCount", "$grp")
	case 13:
		return d("$graphLookup", d("from", coll, "startWith", "$parent", "connectFromField", "parent", "connectToField", "k", "as", "g", "maxDepth", 2))
	case 14:
		return d("$set", d("z", d("$size", d("$ifNull", arr("$tags", arr())))))
	case 15:
		return d("$replaceRoot", d("newRoot", d("$mergeObjects", arr(d("tag", "r"), "$$ROOT"))))
	case 16:
		return d("$sort", d("v", -1, "u", 1))
	case 17:
		return d("$count", "total")
	case 18:
		return d("$setWindowFields", d("partitionBy", "$grp", "sortBy", d("u", 1), "output", d("run", d("$sum", "$v", "window", d("documents", arr("unbounded", "current"))))))
	default:
		return d("$group", d("_id", "$grp", "n", d("$sum", 1), "avg", d("$avg", "$v"), "mx", d("$max", "$k"), "us", d("$push", "$u")))
	}
}

func diffIndexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return 0
}

func (g *diffGen) next() diffOp {
	r := g.r
	c := g.coll()
	g.stepNo++
	switch r.Intn(16) {
	case 0, 1, 2:
		var docs []any
		for i := 0; i < 1+r.Intn(5); i++ {
			docs = append(docs, g.doc(c))
		}
		return diffOp{desc: "insertMany " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).InsertMany(context.Background(), docs)
			if err != nil {
				return nil, err
			}
			return len(res.InsertedIDs), nil
		}}
	case 3, 4:
		f := g.filter(3)
		sortSpec := d("u", 1)
		lim, skip := int64(r.Intn(15)), int64(r.Intn(5))
		return diffOp{desc: fmt.Sprintf("find %s %v", c, f), sorted: true, run: func(db *mongo.Database) (any, error) {
			o := options.Find().SetSort(sortSpec).SetSkip(skip)
			if lim > 0 {
				o.SetLimit(lim)
			}
			if r2 := skip % 2; r2 == 0 {
				o.SetProjection(d("u", 1, "v", 1, "k", 1))
			}
			cur, err := db.Collection(c).Find(context.Background(), f, o.SetBatchSize(3))
			if err != nil {
				return nil, err
			}
			var out []bson.M
			if err := cur.All(context.Background(), &out); err != nil {
				return nil, err
			}
			return out, nil
		}}
	case 5:
		f := g.filter(3)
		return diffOp{desc: "count " + c, run: func(db *mongo.Database) (any, error) {
			return db.Collection(c).CountDocuments(context.Background(), f)
		}}
	case 6:
		f := g.filter(2)
		key := []string{"k", "grp", "tags", "name", "v"}[r.Intn(5)]
		return diffOp{desc: "distinct " + c + "." + key, run: func(db *mongo.Database) (any, error) {
			var vals bson.A
			err := db.Collection(c).Distinct(context.Background(), key, f).Decode(&vals)
			sort.Slice(vals, func(i, j int) bool { return fmt.Sprint(vals[i]) < fmt.Sprint(vals[j]) })
			return vals, err
		}}
	case 7:
		f, u := g.filter(2), g.update()
		return diffOp{desc: "updateMany " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).UpdateMany(context.Background(), f, u)
			if err != nil {
				return nil, err
			}
			return [2]int64{res.MatchedCount, res.ModifiedCount}, nil
		}}
	case 8:
		uu := 1 + r.Intn(g.nextU[c]+1)
		up := g.update()
		return diffOp{desc: "updateOne by u " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).UpdateOne(context.Background(), d("u", uu), up)
			if err != nil {
				return nil, err
			}
			return [2]int64{res.MatchedCount, res.ModifiedCount}, nil
		}}
	case 9:
		g.nextU[c]++
		uu := g.nextU[c]
		v := r.Intn(100)
		return diffOp{desc: "upsert " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).UpdateOne(context.Background(), d("u", uu), d("$set", d("v", v), "$setOnInsert", d("k", 1, "grp", 0)), options.UpdateOne().SetUpsert(true))
			if err != nil {
				return nil, err
			}
			return [3]int64{res.MatchedCount, res.UpsertedCount, res.ModifiedCount}, nil
		}}
	case 10:
		f := g.filter(2)
		return diffOp{desc: "deleteMany " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).DeleteMany(context.Background(), d("$and", arr(f, d("v", d("$lt", 30)))))
			if err != nil {
				return nil, err
			}
			return res.DeletedCount, nil
		}}
	case 11:
		uu := 1 + r.Intn(g.nextU[c]+1)
		return diffOp{desc: "deleteOne by u " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).DeleteOne(context.Background(), d("u", uu))
			if err != nil {
				return nil, err
			}
			return res.DeletedCount, nil
		}}
	case 12:
		f := g.filter(1)
		up := g.update()
		rem := r.Intn(2) == 0
		return diffOp{desc: "findAndModify " + c, run: func(db *mongo.Database) (any, error) {
			var res *mongo.SingleResult
			if rem {
				res = db.Collection(c).FindOneAndDelete(context.Background(), d("$and", arr(f, d("v", d("$gt", 70)))), options.FindOneAndDelete().SetSort(d("u", 1)))
			} else {
				res = db.Collection(c).FindOneAndUpdate(context.Background(), f, up, options.FindOneAndUpdate().SetSort(d("u", 1)).SetReturnDocument(options.After))
			}
			var out bson.M
			err := res.Decode(&out)
			if err == mongo.ErrNoDocuments {
				return "none", nil
			}
			return out, err
		}}
	case 13:
		f := g.filter(1)
		rep := d("u", g.nextU[c]+1000, "k", 1, "grp", 1, "v", 5, "name", "replaced", "tags", arr())
		uu := 1 + r.Intn(g.nextU[c]+1)
		_ = f
		return diffOp{desc: "replaceOne " + c, run: func(db *mongo.Database) (any, error) {
			res, err := db.Collection(c).ReplaceOne(context.Background(), d("u", uu), d("u", uu, "k", 1, "grp", 1, "v", 5, "name", "replaced", "tags", arr()))
			_ = rep
			if err != nil {
				return nil, err
			}
			return [2]int64{res.MatchedCount, res.ModifiedCount}, nil
		}}
	default:
		n := 1 + r.Intn(4)
		var p bson.A
		endsSorted := false
		for i := 0; i < n; i++ {
			st := g.stage(c, i == n-1)
			if i == 0 && (st[0].Key == "$group" || st[0].Key == "$unwind") {
				p = append(p, d("$sort", d("u", 1)))
			}
			if st[0].Key == "$group" || st[0].Key == "$facet" {
				p = append(p, d("$sort", d("u", 1)))
			}
			p = append(p, st)
		}
		if r.Intn(2) == 0 {
			p = append(p, d("$sort", d("u", 1, "_id", 1)))
			endsSorted = false
		}
		_ = endsSorted
		return diffOp{desc: fmt.Sprintf("aggregate %s %v", c, p), run: func(db *mongo.Database) (any, error) {
			cur, err := db.Collection(c).Aggregate(context.Background(), p, options.Aggregate().SetBatchSize(4))
			if err != nil {
				return nil, err
			}
			var out []bson.M
			if err := cur.All(context.Background(), &out); err != nil {
				return nil, err
			}
			return out, nil
		}}
	}
}

// canon renders a result without the proxy-added tenant field or generated _ids.
// deepSort makes canon order-insensitive inside arrays (set by the caller for
// operations whose result order the server does not define).
func sortArrays(x any) any {
	switch t := x.(type) {
	case []any:
		out := make([]any, len(t))
		strs := make([]string, len(t))
		for i, e := range t {
			out[i] = sortArrays(e)
		}
		idx := make([]int, len(t))
		for i := range idx {
			b, _ := json.Marshal(out[i])
			strs[i] = string(b)
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool { return strs[idx[a]] < strs[idx[b]] })
		res := make([]any, len(t))
		for i, j := range idx {
			res[i] = out[j]
		}
		return res
	case map[string]any:
		for k, v := range t {
			t[k] = sortArrays(v)
		}
	}
	return x
}

func sortedJSON(v any, deepSort bool) string {
	b, _ := bson.MarshalExtJSON(bson.M{"v": v}, true, false)
	var x any
	if json.Unmarshal(b, &x) != nil {
		return string(b)
	}
	if deepSort {
		x = sortArrays(x)
	}
	out, _ := json.Marshal(x)
	return string(out)
}

func canon(v any) []string { return canonOpt(v, false) }

func canonOpt(v any, deepSort bool) []string {
	var strip func(x any) any
	strip = func(x any) any {
		switch t := x.(type) {
		case bson.M:
			m := bson.M{}
			for k, vv := range t {
				if k == "tenantId" {
					continue
				}
				if k == "_id" {
					if _, ok := vv.(bson.ObjectID); ok {
						continue
					}
				}
				m[k] = strip(vv)
			}
			return m
		case bson.D:
			m := bson.M{}
			for _, e := range t {
				m[e.Key] = strip(e.Value)
			}
			return strip(m)
		case bson.A:
			out := make(bson.A, len(t))
			for i, e := range t {
				out[i] = strip(e)
			}
			return out
		case []bson.M:
			out := make([]any, len(t))
			for i, e := range t {
				out[i] = strip(e)
			}
			return out
		}
		return x
	}
	switch t := strip(v).(type) {
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, sortedJSON(e, deepSort))
		}
		return out
	default:
		return []string{sortedJSON(t, deepSort)}
	}
}

func errCode(err error) string {
	if err == nil {
		return ""
	}
	if ce, ok := err.(mongo.CommandError); ok {
		return fmt.Sprintf("code %d", ce.Code)
	}
	if mongo.IsDuplicateKeyError(err) {
		return "dup"
	}
	return "err"
}

func TestDifferentialProxyVsPrivateDB(t *testing.T) {
	seeds := []int64{1, 2, 3, 4, 5}
	steps := 250
	if testing.Short() {
		seeds, steps = seeds[:1], 80
	}
	for _, m := range isoModes[:3] {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			w := newIsoWorld(t, m)
			for _, seed := range seeds {
				seed := seed
				dbName := fmt.Sprintf("diff%d", seed)
				priv := w.e.direct.Database(fmt.Sprintf("priv%d", seed))
				_ = priv.Drop(ctx(t))
				gen := &diffGen{r: rand.New(rand.NewSource(seed)), nextU: map[string]int{}}
				var ops []diffOp
				for i := 0; i < steps; i++ {
					ops = append(ops, gen.next())
				}
				// Index parity: both sides get the same index so hints/plans agree.
				for _, tn := range []string{tB, tC, tA} {
					for _, c := range diffColls {
						_, err := w.cl[tn].Database(dbName).Collection(c).Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: d("u", 1), Options: indexOpts("u_1", true)})
						must(t, err)
					}
				}
				for _, c := range diffColls {
					_, err := priv.Collection(c).Indexes().CreateOne(ctx(t), mongo.IndexModel{Keys: d("u", 1), Options: indexOpts("u_1", true)})
					must(t, err)
				}
				bothErr, rows := 0, 0
				for i, op := range ops {
					for _, tn := range []string{tB, tC} { // noisy neighbours with identical data
						op.run(w.cl[tn].Database(dbName))
					}
					got, gerr := op.run(w.cl[tA].Database(dbName))
					want, werr := op.run(priv)
					if gerr != nil && m.policy == "namespace" && strings.Contains(gerr.Error(), "idPolicy") {
						continue // documented limit of the experimental namespace policy
					}
					if errCode(gerr) != errCode(werr) {
						t.Fatalf("seed %d step %d %s: proxy err=%v, private err=%v", seed, i, op.desc, gerr, werr)
					}
					if gerr != nil {
						bothErr++
						continue
					}
					g, wt := canonOpt(got, !op.sorted), canonOpt(want, !op.sorted)
					rows += len(g)
					if !op.sorted {
						sort.Strings(g)
						sort.Strings(wt)
					}
					if strings.Join(g, "\n") != strings.Join(wt, "\n") {
						t.Fatalf("seed %d step %d %s:\nproxy:   %s\nprivate: %s", seed, i, op.desc, strings.Join(g, "\n"), strings.Join(wt, "\n"))
					}
				}
				t.Logf("seed %d: %d ops, %d failed identically on both sides, %d result rows compared", seed, steps, bothErr, rows)
				if bothErr > steps/3 {
					t.Errorf("seed %d: %d/%d operations failed; the workload is not exercising the proxy", seed, bothErr, steps)
				}
				// Final state of every collection matches too.
				for _, c := range diffColls {
					dump := func(db *mongo.Database) []string {
						cur, err := db.Collection(c).Find(ctx(t), bson.D{})
						must(t, err)
						var docs []bson.M
						must(t, cur.All(ctx(t), &docs))
						out := canon(docs)
						sort.Strings(out)
						return out
					}
					g, wt := dump(w.cl[tA].Database(dbName)), dump(priv)
					if strings.Join(g, "\n") != strings.Join(wt, "\n") {
						t.Fatalf("seed %d: final state of %s differs (%d vs %d docs)", seed, c, len(g), len(wt))
					}
					// Neighbours kept their own, identical-looking data.
					for _, tn := range []string{tB, tC} {
						if got := dump(w.cl[tn].Database(dbName)); strings.Join(got, "\n") != strings.Join(wt, "\n") {
							t.Fatalf("seed %d: %s's final state of %s differs from the private reference", seed, tn, c)
						}
					}
				}
			}
		})
	}
}
