package test

// Table-driven attack catalogue. Each entry is run by tenant-alpha through the
// proxy against a freshly seeded collection; the universal invariants in
// security_iso_world_test.go decide pass/fail. See docs/security-testing.md for
// the class each group maps to.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func indexOpts(name string, unique bool) *options.IndexOptionsBuilder {
	o := options.Index().SetName(name)
	if unique {
		o.SetUnique(true)
	}
	return o
}
func optsSortK() *options.FindOptionsBuilder {
	return options.Find().SetSort(bson.D{{Key: "k", Value: 1}, {Key: "name", Value: 1}})
}
func optsSortID() *options.FindOptionsBuilder {
	return options.Find().SetSort(bson.D{{Key: "_id", Value: 1}})
}

// d builds an ordered document from alternating keys and values.
func d(kv ...any) bson.D {
	out := make(bson.D, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, bson.E{Key: kv[i].(string), Value: kv[i+1]})
	}
	return out
}

func arr(v ...any) bson.A { return append(bson.A{}, v...) }

type attack struct {
	class   string // vulnerability class (docs/security-testing.md)
	name    string
	db      string // default: the fixture database
	mutates bool
	known   string // documented limitation: failures are logged, not fatal
	cmd     func(f *fixture) bson.D
}

func jsFn(body string) bson.D {
	return d("$function", d("body", body, "args", bson.A{}, "lang", "js"))
}

func deepNot(n int) bson.D {
	var cur any = d("k", 1)
	for i := 0; i < n; i++ {
		cur = d("$and", arr(cur))
	}
	return cur.(bson.D)
}

func deepExpr(n int) any {
	var cur any = "$k"
	for i := 0; i < n; i++ {
		cur = d("$abs", arr(cur))
	}
	return cur
}

func find(filter any, extra ...any) func(f *fixture) bson.D {
	return func(f *fixture) bson.D {
		return append(d("find", f.C, "filter", filter, "batchSize", 1), d(extra...)...)
	}
}

func agg(pipeline func(f *fixture) bson.A, extra ...any) func(f *fixture) bson.D {
	return func(f *fixture) bson.D {
		return append(d("aggregate", f.C, "pipeline", pipeline(f), "cursor", d("batchSize", 1)), d(extra...)...)
	}
}

func stages(s ...any) func(f *fixture) bson.A { return func(*fixture) bson.A { return bson.A(s) } }

func upd(q, u any, extra ...any) func(f *fixture) bson.D {
	return func(f *fixture) bson.D {
		st := append(d("q", q, "u", u), d(extra...)...)
		return d("update", f.C, "updates", arr(st))
	}
}

func del(q any, limit int) func(f *fixture) bson.D {
	return func(f *fixture) bson.D { return d("delete", f.C, "deletes", arr(d("q", q, "limit", limit))) }
}

func ins(docs ...any) func(f *fixture) bson.D {
	return func(f *fixture) bson.D { return d("insert", f.C, "documents", bson.A(docs)) }
}

func fam(extra ...any) func(f *fixture) bson.D {
	return func(f *fixture) bson.D { return append(d("findAndModify", f.C), d(extra...)...) }
}

// reservedNames are collection names a tenant must never reach.
func reservedNames(f *fixture) []string {
	return []string{"system.js", "system.views", "system.profile", "system.users", "system.buckets." + f.C,
		"__mtp_views", "__mtp_validators", f.BViewPhys, "__mtp_out_deadbeef", "__mtp_mr_deadbeef", "SYSTEM.JS",
		"system.js ", " system.js", "system.js.", "System.Views", "__MTP_views", "__mtp_", f.C + ".", f.C + " ", " " + f.C,
		strings.ToUpper(f.C), "system​.js", "ｓystem.js", f.DB + "." + f.C, "$cmd", "$cmd.sys.inprog", "", "a/b", "a\\b",
		"x$y", "ıtems"}
}

func catalogue() []attack {
	var as []attack
	add := func(class, name string, mut bool, cmd func(f *fixture) bson.D) {
		as = append(as, attack{class: class, name: name, mutates: mut, cmd: cmd})
	}
	addDB := func(class, db, name string, mut bool, cmd func(f *fixture) bson.D) {
		as = append(as, attack{class: class, name: name, db: db, mutates: mut, cmd: cmd})
	}

	// ---- 1. filter operator injection / widening --------------------------
	filters := []struct {
		name string
		f    any
	}{
		{"tenant override", d("tenantId", tB)},
		{"tenant override in $or", d("$or", arr(d("tenantId", tB), d("k", 1)))},
		{"tenant $ne self", d("tenantId", d("$ne", tA))},
		{"tenant $in victims", d("tenantId", d("$in", arr(tB, tC, tU)))},
		{"tenant $regex any", d("tenantId", d("$regex", ".*"))},
		{"tenant $regex case-insens", d("tenantId", d("$regex", "^TENANT-", "$options", "i"))},
		{"tenant $gt empty", d("tenantId", d("$gt", ""))},
		{"tenant $exists", d("tenantId", d("$exists", true))},
		{"tenant $type string", d("tenantId", d("$type", "string"))},
		{"tenant $not $eq self", d("tenantId", d("$not", d("$eq", tA)))},
		{"$nor self", d("$nor", arr(d("tenantId", tA)))},
		{"$expr eq victim", d("$expr", d("$eq", arr("$tenantId", tB)))},
		{"$expr ne self", d("$expr", d("$ne", arr("$tenantId", tA)))},
		{"$expr true", d("$expr", true)},
		{"$expr with $$ROOT", d("$expr", d("$ne", arr("$$ROOT.tenantId", tA)))},
		{"$expr regexMatch", d("$expr", d("$regexMatch", d("input", "$tenantId", "regex", "bravo")))},
		{"$expr dynamic field", d("$expr", d("$eq", arr(d("$getField", "tenantId"), tB)))},
		{"$expr $or widening", d("$expr", d("$or", arr(true, d("$eq", arr("$tenantId", tA)))))},
		{"dup key victim first", d("tenantId", tB, "tenantId", tA)},
		{"dup key self first", d("tenantId", tA, "tenantId", tB)},
		{"dup $or", d("$or", arr(d("k", 1)), "$or", arr(d("tenantId", tB)))},
		{"tenant exists false", d("tenantId", d("$exists", false))},
		{"tenant null", d("tenantId", nil)},
		{"tenant array", d("tenantId", arr(tB))},
		{"tenant array both", d("tenantId", arr(tA, tB))},
		{"tenant object", d("tenantId", d("x", tB))},
		{"tenant int", d("tenantId", 1)},
		{"tenant elemMatch", d("tenantId", d("$elemMatch", d("$eq", tB)))},
		{"tenant $all", d("tenantId", d("$all", arr(tB)))},
		{"tenant $size", d("tenantId", d("$size", 1))},
		{"tenant dotted", d("tenantId.x", tB)},
		{"tenant positional", d("tenantId.$", tB)},
		{"empty key", d("", tB)},
		{"tenant trailing NUL value", d("tenantId", tB+"\x00")},
		{"self with NUL value", d("tenantId", tA+"\x00"+tB)},
		{"case variant of self", d("tenantId", tU)},
		{"case variant field name", d("TenantId", tB)},
		{"unicode field name", d("tenant​Id", tB)},
		{"$and override", d("$and", arr(d("tenantId", tB)))},
		{"nested $or/$and/$nor", d("$or", arr(d("$and", arr(d("$nor", arr(d("tenantId", tA)))))))},
		{"$jsonSchema enum victim", d("$jsonSchema", d("properties", d("tenantId", d("enum", arr(tB)))))},
		{"$jsonSchema any", d("$jsonSchema", d("required", arr("k")))},
		{"$comment", d("$comment", tB, "k", 1)},
		{"$where string victim", d("$where", "this.tenantId == 'tenant-bravo'")},
		{"$where return true", d("$where", "return true")},
		{"$where function body", d("$where", "function() { return this.secret.indexOf('CNRY') >= 0 }")},
		{"$expr $function", d("$expr", jsFn("function(){ return true }"))},
		{"$expr $function reading arg", d("$expr", d("$function", d("body", "function(t){ return t != 'x' }", "args", arr("$tenantId"), "lang", "js")))},
		{"$where code type", d("$where", bson.JavaScript("return true"))},
		{"deep $and 150", deepNot(150)},
		{"deep $and 5000", deepNot(5000)},
		{"deep $expr 150", d("$expr", d("$eq", arr(deepExpr(150), 1)))},
		{"regex catastrophic", d("name", d("$regex", "^(a+)+$"))},
		{"regex catastrophic on tenant", d("tenantId", d("$regex", "(.*)*(.*)*(.*)*x"))},
		{"$text without index", d("$text", d("$search", "bravo"))},
		{"geoWithin", d("loc", d("$geoWithin", d("$box", arr(arr(0, 0), arr(1, 1)))))},
		{"$near", d("loc", d("$near", arr(0, 0)))},
		{"$mod/$bitsAllSet", d("k", d("$bitsAllSet", 0))},
		{"$ref sneaky", d("$db", "admin")},
		{"$natural filter", d("$natural", 1)},
		{"$_internalSchemaMinItems", d("tags", d("$_internalSchemaMinItems", 1))},
		{"$sampleRate", d("$sampleRate", 1.0)},
		{"$alwaysTrue", d("$alwaysTrue", 1)},
		{"$_internalExprEq", d("tenantId", d("$_internalExprEq", tB))},
	}
	for _, fl := range filters {
		fl := fl
		add("operator-injection", "find/"+fl.name, false, find(fl.f))
		add("operator-injection", "count/"+fl.name, false, func(f *fixture) bson.D { return d("count", f.C, "query", fl.f) })
		add("operator-injection", "distinct/"+fl.name, false, func(f *fixture) bson.D {
			return d("distinct", f.C, "key", "tenantId", "query", fl.f)
		})
		add("operator-injection", "agg-match/"+fl.name, false, agg(stages(d("$match", fl.f))))
		add("operator-injection", "update-q/"+fl.name, true, upd(fl.f, d("$set", d("touched", 1)), "multi", true))
		add("operator-injection", "delete-q/"+fl.name, true, del(fl.f, 0))
		add("operator-injection", "fam-query/"+fl.name, true, fam("query", fl.f, "update", d("$set", d("touched", 1))))
		add("operator-injection", "fam-remove/"+fl.name, true, fam("query", fl.f, "remove", true))
	}

	// ---- 2. find / command option smuggling -------------------------------
	add("option-smuggling", "projection $$ROOT", false, find(d(), "projection", d("all", "$$ROOT")))
	add("option-smuggling", "projection exclude tenant", false, find(d(), "projection", d("tenantId", 0)))
	add("option-smuggling", "projection expr lookup", false, find(d(), "projection", d("x", d("$function", d("body", "function(){return 1}", "args", bson.A{}, "lang", "js")))))
	add("option-smuggling", "sort meta", false, find(d(), "sort", d("score", d("$meta", "textScore"))))
	add("option-smuggling", "hint natural", false, find(d(), "hint", d("$natural", 1)))
	add("option-smuggling", "hint victim index name", false, func(f *fixture) bson.D {
		return d("find", f.C, "filter", d(), "hint", f.BIdxPhys)
	})
	add("option-smuggling", "hint victim index (unsuffixed)", false, func(f *fixture) bson.D {
		return d("find", f.C, "filter", d(), "hint", "b_k_idx")
	})
	add("option-smuggling", "min/max", false, find(d(), "min", d("k", 0), "max", d("k", 99), "hint", d("k", 1)))
	add("option-smuggling", "let vars", false, find(d("$expr", d("$eq", arr("$tenantId", "$$t"))), "let", d("t", tB)))
	add("option-smuggling", "singleBatch large", false, find(d(), "singleBatch", true, "limit", -5))
	add("option-smuggling", "readConcern snapshot", false, find(d(), "readConcern", d("level", "snapshot")))
	add("option-smuggling", "readConcern afterClusterTime", false, find(d(), "readConcern", d("afterClusterTime", bson.Timestamp{T: 1, I: 1})))
	add("option-smuggling", "$readPreference primaryPreferred", false, find(d(), "$readPreference", d("mode", "primaryPreferred")))
	add("option-smuggling", "extra $db admin", false, func(f *fixture) bson.D { return d("$db", "admin", "find", f.C, "filter", d()) })
	add("option-smuggling", "dup find collection", false, func(f *fixture) bson.D { return d("find", f.C, "find", f.Other, "filter", d()) })
	add("option-smuggling", "dup filter", false, func(f *fixture) bson.D { return d("find", f.C, "filter", d("k", 1), "filter", d("tenantId", tB)) })
	add("option-smuggling", "dup filter reversed", false, func(f *fixture) bson.D { return d("find", f.C, "filter", d("tenantId", tB), "filter", d("k", 1)) })
	add("option-smuggling", "filter as array", false, func(f *fixture) bson.D { return d("find", f.C, "filter", arr(d("tenantId", tB))) })
	add("option-smuggling", "filter as string", false, func(f *fixture) bson.D { return d("find", f.C, "filter", tB) })
	add("option-smuggling", "collection as doc", false, func(f *fixture) bson.D { return d("find", d("x", f.C), "filter", d()) })
	add("option-smuggling", "collection as array", false, func(f *fixture) bson.D { return d("find", arr(f.C), "filter", d()) })
	add("option-smuggling", "find collection 1", false, func(f *fixture) bson.D { return d("find", 1, "filter", d()) })
	add("option-smuggling", "limit negative huge", false, find(d(), "limit", int64(-1<<62)))
	add("option-smuggling", "comment doc", false, find(d(), "comment", d("tenantId", tB)))
	add("option-smuggling", "allowDiskUse/noCursorTimeout/tailable", false, find(d(), "noCursorTimeout", true, "tailable", true, "awaitData", true))
	add("option-smuggling", "showRecordId/returnKey", false, find(d(), "showRecordId", true, "returnKey", true))
	add("option-smuggling", "collation victim case", false, find(d("tenantId", tU), "collation", d("locale", "en", "strength", 2)))
	add("option-smuggling", "collation strength 1", false, find(d(), "collation", d("locale", "en", "strength", 1)))
	add("option-smuggling", "collation alternate shifted", false, find(d("tenantId", "tenant alpha"), "collation", d("locale", "en", "strength", 3, "alternate", "shifted")))
	add("option-smuggling", "collation normalization", false, find(d(), "collation", d("locale", "en", "normalization", true)))
	add("option-smuggling", "collation numericOrdering", false, find(d(), "collation", d("locale", "en", "numericOrdering", true)))
	add("option-smuggling", "collation simple", false, find(d(), "collation", d("locale", "simple")))
	add("option-smuggling", "collation maxVariable", false, find(d(), "collation", d("locale", "en", "strength", 2, "caseLevel", false)))
	add("option-smuggling", "agg collation", false, agg(stages(d("$match", d("tenantId", tU))), "collation", d("locale", "en", "strength", 2)))
	add("option-smuggling", "count collation", false, func(f *fixture) bson.D {
		return d("count", f.C, "query", d("tenantId", tU), "collation", d("locale", "en", "strength", 2))
	})
	add("option-smuggling", "distinct collation", false, func(f *fixture) bson.D {
		return d("distinct", f.C, "key", "tenantId", "collation", d("locale", "en", "strength", 1))
	})
	add("option-smuggling", "update collation", true, upd(d("tenantId", tU), d("$set", d("x", 1)), "multi", true, "collation", d("locale", "en", "strength", 2)))
	add("option-smuggling", "delete collation", true, func(f *fixture) bson.D {
		return d("delete", f.C, "deletes", arr(d("q", d("tenantId", tU), "limit", 0, "collation", d("locale", "en", "strength", 2))))
	})
	add("option-smuggling", "fam collation", true, fam("query", d("tenantId", tU), "remove", true, "collation", d("locale", "en", "strength", 2)))
	add("option-smuggling", "index collation", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("tenantId", 1), "name", "ci", "collation", d("locale", "en", "strength", 2))))
	})
	add("option-smuggling", "explain collation", false, func(f *fixture) bson.D {
		return d("explain", d("find", f.C, "filter", d("tenantId", tU), "collation", d("locale", "en", "strength", 2)), "verbosity", "allPlansExecution")
	})

	// ---- 3. aggregation pipeline injection --------------------------------
	lookupVictim := func(from any) func(f *fixture) bson.D {
		return agg(func(f *fixture) bson.A {
			fr := from
			if s, ok := from.(func(*fixture) any); ok {
				fr = s(f)
			}
			return arr(d("$lookup", d("from", fr, "localField", "k", "foreignField", "k", "as", "j")))
		})
	}
	selfColl := func(f *fixture) any { return f.C }
	otherColl := func(f *fixture) any { return f.Other }
	add("pipeline-injection", "lookup self collection", false, lookupVictim(selfColl))
	add("pipeline-injection", "lookup other collection", false, lookupVictim(otherColl))
	add("pipeline-injection", "lookup victim view", false, lookupVictim(func(f *fixture) any { return f.BView }))
	add("pipeline-injection", "lookup physical view", false, lookupVictim(func(f *fixture) any { return f.BViewPhys }))
	for _, n := range []string{"system.views", "__mtp_views", "__mtp_validators", "system.js", "system.profile"} {
		n := n
		add("pipeline-injection", "lookup "+n, false, lookupVictim(func(*fixture) any { return n }))
		add("pipeline-injection", "unionWith "+n, false, agg(stages(d("$unionWith", n))))
		add("pipeline-injection", "graphLookup "+n, false, agg(stages(d("$graphLookup", d("from", n, "startWith", "$k", "connectFromField", "k", "connectToField", "k", "as", "g")))))
	}
	add("pipeline-injection", "lookup db-qualified admin.system.users", false, lookupVictim(func(*fixture) any { return d("db", "admin", "coll", "system.users") }))
	add("pipeline-injection", "lookup db-qualified admin.system.version", false, lookupVictim(func(*fixture) any { return d("db", "admin", "coll", "system.version") }))
	add("pipeline-injection", "lookup db-qualified local.oplog.rs", false, lookupVictim(func(*fixture) any { return d("db", "local", "coll", "oplog.rs") }))
	add("pipeline-injection", "lookup db-qualified config", false, lookupVictim(func(*fixture) any { return d("db", "config", "coll", "system.sessions") }))
	add("pipeline-injection", "lookup db-qualified same db", false, lookupVictim(func(f *fixture) any { return d("db", f.DB, "coll", f.C) }))
	add("pipeline-injection", "lookup db-qualified other db", false, lookupVictim(func(f *fixture) any { return d("db", "other", "coll", f.C) }))
	add("pipeline-injection", "lookup from dotted", false, lookupVictim(func(f *fixture) any { return f.DB + "." + f.C }))
	add("pipeline-injection", "lookup from empty", false, lookupVictim(func(*fixture) any { return "" }))
	add("pipeline-injection", "lookup from int", false, lookupVictim(func(*fixture) any { return 1 }))
	add("pipeline-injection", "unionWith db-qualified admin", false, agg(stages(d("$unionWith", d("coll", "system.users", "db", "admin")))))
	add("pipeline-injection", "lookup pipeline victim match", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("from", f.C, "pipeline", arr(d("$match", d("tenantId", tB))), "as", "j")))
	}))
	add("pipeline-injection", "lookup pipeline let/expr", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("from", f.C, "let", d("t", tB), "pipeline", arr(d("$match", d("$expr", d("$eq", arr("$tenantId", "$$t"))))), "as", "j")))
	}))
	add("pipeline-injection", "lookup nested lookup", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("from", f.C, "pipeline", arr(d("$lookup", d("from", f.Other, "pipeline", arr(d("$unionWith", f.C)), "as", "q"))), "as", "j")))
	}))
	add("pipeline-injection", "lookup pipeline unionWith graphLookup", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("from", f.C, "pipeline", arr(
			d("$unionWith", d("coll", f.Other, "pipeline", arr(d("$graphLookup", d("from", f.C, "startWith", "$parent", "connectFromField", "parent", "connectToField", "k", "as", "g"))))),
		), "as", "j")))
	}))
	add("pipeline-injection", "lookup pipeline with $documents", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("pipeline", arr(d("$documents", arr(d("x", 1)))), "as", "j")))
	}))
	add("pipeline-injection", "lookup pipeline no from", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("pipeline", arr(d("$collStats", d("storageStats", d()))), "as", "j")))
	}))
	add("pipeline-injection", "unionWith victim match", false, agg(func(f *fixture) bson.A {
		return arr(d("$unionWith", d("coll", f.C, "pipeline", arr(d("$match", d("tenantId", tB))))))
	}))
	add("pipeline-injection", "unionWith victim view", false, agg(func(f *fixture) bson.A { return arr(d("$unionWith", f.BView)) }))
	add("pipeline-injection", "unionWith physical view", false, agg(func(f *fixture) bson.A { return arr(d("$unionWith", f.BViewPhys)) }))
	add("pipeline-injection", "unionWith no coll (documents)", false, agg(stages(d("$unionWith", d("pipeline", arr(d("$documents", arr(d("x", 1)))))))))
	add("pipeline-injection", "unionWith nested", false, agg(func(f *fixture) bson.A {
		return arr(d("$unionWith", d("coll", f.Other, "pipeline", arr(d("$unionWith", d("coll", f.C, "pipeline", arr(d("$unionWith", f.Other))))))))
	}))
	add("pipeline-injection", "graphLookup restrict victim", false, agg(func(f *fixture) bson.A {
		return arr(d("$graphLookup", d("from", f.C, "startWith", "$parent", "connectFromField", "parent", "connectToField", "k", "as", "g",
			"restrictSearchWithMatch", d("tenantId", tB))))
	}))
	add("pipeline-injection", "graphLookup other coll", false, agg(func(f *fixture) bson.A {
		return arr(d("$graphLookup", d("from", f.Other, "startWith", "$parent", "connectFromField", "parent", "connectToField", "k", "as", "g", "maxDepth", 9)))
	}))
	add("pipeline-injection", "graphLookup in facet", false, agg(func(f *fixture) bson.A {
		return arr(d("$facet", d("a", arr(d("$graphLookup", d("from", f.C, "startWith", "$parent", "connectFromField", "parent", "connectToField", "k", "as", "g"))))))
	}))
	add("pipeline-injection", "facet victim match", false, agg(stages(d("$facet", d("a", arr(d("$match", d("tenantId", tB))), "b", arr(d("$match", d("tenantId", tC))))))))
	add("pipeline-injection", "facet lookup unionWith nest", false, agg(func(f *fixture) bson.A {
		return arr(d("$facet", d("a", arr(d("$lookup", d("from", f.C, "pipeline", arr(d("$facet", d("z", arr(d("$unionWith", f.Other))))), "as", "j"))))))
	}))
	add("pipeline-injection", "geoNear", false, agg(stages(d("$geoNear", d("near", arr(0, 0), "distanceField", "d", "query", d("tenantId", tB))))))
	add("pipeline-injection", "geoNear key", false, agg(stages(d("$geoNear", d("near", arr(0, 0), "distanceField", "d", "key", "loc")))))
	add("pipeline-injection", "match after replaceRoot", false, agg(stages(d("$replaceRoot", d("newRoot", d("x", 1))), d("$match", d("tenantId", tB)))))
	add("pipeline-injection", "project away tenant then lookup", false, agg(func(f *fixture) bson.A {
		return arr(d("$project", d("tenantId", 0)), d("$lookup", d("from", f.C, "localField", "k", "foreignField", "k", "as", "j")))
	}))
	add("pipeline-injection", "redact", false, agg(stages(d("$redact", "$$KEEP"))))
	add("pipeline-injection", "group by tenant", false, agg(stages(d("$group", d("_id", "$tenantId", "n", d("$sum", 1), "s", d("$push", "$secret"))))))
	add("pipeline-injection", "setWindowFields", false, agg(stages(d("$setWindowFields", d("partitionBy", "$tenantId", "output", d("n", d("$count", d())))))))
	add("pipeline-injection", "$function in addFields", false, agg(stages(d("$addFields", d("x", jsFn("function(){ return 1 }"))))))
	add("pipeline-injection", "$accumulator", false, agg(stages(d("$group", d("_id", nil, "x", d("$accumulator", d("init", "function(){return 0}", "accumulate", "function(s,v){return s+1}",
		"accumulateArgs", arr("$k"), "merge", "function(a,b){return a+b}", "lang", "js")))))))
	add("pipeline-injection", "stage with two keys", false, agg(stages(d("$match", d("k", 1), "$unionWith", "o1"))))
	add("pipeline-injection", "stage with two keys reversed", false, agg(func(f *fixture) bson.A {
		return arr(d("$project", d("k", 1), "$unionWith", f.Other))
	}))
	add("pipeline-injection", "stage dup key", false, agg(stages(d("$match", d("k", 1), "$match", d("tenantId", tB)))))
	add("pipeline-injection", "empty stage", false, agg(stages(d())))
	add("pipeline-injection", "non-document stage", false, agg(stages("$match")))
	add("pipeline-injection", "dollar-less stage", false, agg(stages(d("match", d("tenantId", tB)))))
	add("pipeline-injection", "pipeline not array", false, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", d("$match", d("tenantId", tB)), "cursor", d())
	})
	add("pipeline-injection", "dup pipeline", false, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(), "pipeline", arr(d("$match", d("tenantId", tB))), "cursor", d())
	})
	add("pipeline-injection", "unicode stage name", false, agg(stages(d("$ma​tch", d("tenantId", tB)))))
	add("pipeline-injection", "deep facet nesting", false, agg(func(f *fixture) bson.A {
		var cur any = arr(d("$match", d()))
		for i := 0; i < 120; i++ {
			cur = arr(d("$facet", d("a", cur)))
		}
		return cur.(bson.A)
	}))
	add("pipeline-injection", "huge pipeline", false, agg(func(f *fixture) bson.A {
		var p bson.A
		for i := 0; i < 1500; i++ {
			p = append(p, d("$addFields", d("z", i)))
		}
		return p
	}))
	add("pipeline-injection", "explain agg", false, func(f *fixture) bson.D {
		return d("explain", d("aggregate", f.C, "pipeline", arr(d("$lookup", d("from", f.Other, "localField", "k", "foreignField", "k", "as", "j"))), "cursor", d()), "verbosity", "executionStats")
	})
	add("pipeline-injection", "agg explain flag", false, agg(stages(d("$match", d("tenantId", tB))), "explain", true))
	add("pipeline-injection", "agg let victim", false, agg(stages(d("$match", d("$expr", d("$eq", arr("$tenantId", "$$t"))))), "let", d("t", tB)))
	add("pipeline-injection", "agg collection 1 documents", false, func(f *fixture) bson.D {
		return d("aggregate", 1, "pipeline", arr(d("$documents", arr(d("x", 1)))), "cursor", d())
	})
	add("pipeline-injection", "agg collection 1 lookup", false, func(f *fixture) bson.D {
		return d("aggregate", 1, "pipeline", arr(d("$documents", arr(d("k", 1))), d("$lookup", d("from", f.C, "localField", "k", "foreignField", "k", "as", "j"))), "cursor", d())
	})
	add("pipeline-injection", "agg collection 1 unionWith", false, func(f *fixture) bson.D {
		return d("aggregate", 1, "pipeline", arr(d("$documents", arr(d("k", 1))), d("$unionWith", f.C)), "cursor", d())
	})
	add("pipeline-injection", "$match with $text first", false, agg(stages(d("$match", d("$text", d("$search", "x"))))))
	add("pipeline-injection", "pipeline on victim view", false, func(f *fixture) bson.D {
		return d("aggregate", f.BView, "pipeline", arr(), "cursor", d())
	})
	add("pipeline-injection", "find on victim view", false, func(f *fixture) bson.D { return d("find", f.BView, "filter", d()) })
	add("pipeline-injection", "find on physical view", false, func(f *fixture) bson.D { return d("find", f.BViewPhys, "filter", d()) })

	// internal / administrative stages
	for _, st := range []bson.D{
		d("$collStats", d("latencyStats", d("histograms", true), "storageStats", d(), "count", d())),
		d("$indexStats", d()),
		d("$planCacheStats", d()),
		d("$currentOp", d("allUsers", true, "idleConnections", true, "idleSessions", true, "localOps", true)),
		d("$listLocalSessions", d("allUsers", true)),
		d("$listSessions", d("allUsers", true)),
		d("$listSampledQueries", d()),
		d("$listSearchIndexes", d()),
		d("$listCatalog", d()),
		d("$listClusterCatalog", d()),
		d("$shardedDataDistribution", d()),
		d("$querySettings", d()),
		d("$queryStats", d()),
		d("$mergeCursors", d("cursors", arr(), "sort", d(), "compareWholeSortKey", false)),
		d("$_internalInhibitOptimization", d()),
		d("$_internalSplitPipeline", d("mergeType", "mongos")),
		d("$_internalAllCollectionStats", d("stats", d())),
		d("$_internalUnpackBucket", d("timeField", "t")),
		d("$_internalConvertBucketIndexStats", d()),
		d("$_internalListCollections", d()),
		d("$_internalShredDocuments", d()),
		d("$changeStreamSplitLargeEvent", d()),
		d("$_internalApplyOplogUpdate", d("oplogUpdate", d())),
		d("$search", d("text", d("query", "x", "path", "name"))),
		d("$searchMeta", d("facet", d())),
		d("$vectorSearch", d("queryVector", arr(1, 2), "path", "v", "numCandidates", 5, "limit", 1, "index", "i")),
		d("$sample", d("size", 100)),
		d("$bucketAuto", d("groupBy", "$tenantId", "buckets", 3)),
		d("$bucket", d("groupBy", "$tenantId", "boundaries", arr("a", "z"), "default", "other")),
		d("$densify", d("field", "k", "range", d("step", 1, "bounds", "full"))),
		d("$fill", d("output", d("k", d("method", "linear")))),
		d("$sortByCount", "$tenantId"),
		d("$count", "n"),
		d("$unwind", "$tags"),
		d("$set", d("tenantId", tB)),
		d("$unset", "tenantId"),
		d("$replaceWith", "$$ROOT"),
	} {
		st := st
		add("pipeline-injection", "stage "+st[0].Key, false, agg(stages(st)))
		addDB("pipeline-injection", "admin", "admin stage "+st[0].Key, false, func(f *fixture) bson.D {
			return d("aggregate", 1, "pipeline", arr(st), "cursor", d())
		})
		add("pipeline-injection", "coll1 stage "+st[0].Key, false, func(f *fixture) bson.D {
			return d("aggregate", 1, "pipeline", arr(st), "cursor", d())
		})
		add("pipeline-injection", "after-match stage "+st[0].Key, false, agg(stages(d("$match", d("k", 1)), st)))
		add("pipeline-injection", "in-facet stage "+st[0].Key, false, agg(stages(d("$facet", d("a", arr(st))))))
		add("pipeline-injection", "in-lookup stage "+st[0].Key, false, func(f *fixture) bson.D {
			return d("aggregate", f.C, "pipeline", arr(d("$lookup", d("from", f.Other, "pipeline", arr(st), "as", "j"))), "cursor", d())
		})
		add("pipeline-injection", "in-unionWith stage "+st[0].Key, false, func(f *fixture) bson.D {
			return d("aggregate", f.C, "pipeline", arr(d("$unionWith", d("coll", f.Other, "pipeline", arr(st)))), "cursor", d())
		})
	}

	// $merge / $out
	mergeInto := func(into any, extra ...any) func(f *fixture) bson.D {
		return agg(func(f *fixture) bson.A { return arr(d("$merge", append(d("into", into), d(extra...)...))) })
	}
	add("merge-out", "merge into self collection on _id", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$merge", d("into", f.Other, "on", "_id", "whenMatched", "replace"))), "cursor", d())
	})
	add("merge-out", "merge replace stamping victim", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$set", d("tenantId", tB)), d("$merge", d("into", f.Other, "on", "_id", "whenMatched", "replace"))), "cursor", d())
	})
	add("merge-out", "merge whenMatched pipeline sets tenant", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$merge", d("into", f.Other, "on", "k", "whenMatched", arr(d("$set", d("tenantId", tB))), "whenNotMatched", "insert"))), "cursor", d())
	})
	add("merge-out", "merge on k (cross-tenant match)", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$set", d("secret", "OVERWRITE")), d("$merge", d("into", f.Other, "on", "k", "whenMatched", "merge"))), "cursor", d())
	})
	add("merge-out", "merge on tenantId", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$merge", d("into", f.Other, "on", arr("tenantId", "k"), "whenMatched", "replace"))), "cursor", d())
	})
	add("merge-out", "merge from victim view", true, func(f *fixture) bson.D {
		return d("aggregate", f.BView, "pipeline", arr(d("$merge", d("into", f.Other))), "cursor", d())
	})
	add("merge-out", "merge into victim view", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$merge", d("into", f.BView))), "cursor", d())
	})
	add("merge-out", "merge into physical view", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$merge", d("into", f.BViewPhys))), "cursor", d())
	})
	add("merge-out", "merge into other db", true, mergeInto(d("db", "other", "coll", "x")))
	add("merge-out", "merge into admin", true, mergeInto(d("db", "admin", "coll", "system.users")))
	add("merge-out", "merge into local", true, mergeInto(d("db", "local", "coll", "x")))
	add("merge-out", "merge into dotted", true, mergeInto("app.o1"))
	add("merge-out", "merge into different casing db", true, mergeInto(d("db", "APP", "coll", "o1")))
	for _, n := range []string{"system.views", "system.js", "__mtp_views", "__mtp_validators", "system.buckets.x"} {
		n := n
		add("merge-out", "merge into "+n, true, mergeInto(n))
		add("merge-out", "out "+n, true, agg(stages(d("$out", n))))
		add("merge-out", "out db-qualified "+n, true, agg(stages(d("$out", d("db", isoDB, "coll", n)))))
	}
	add("merge-out", "out other collection", true, agg(func(f *fixture) bson.A { return arr(d("$out", f.Other)) }))
	add("merge-out", "out self collection", true, agg(func(f *fixture) bson.A { return arr(d("$out", f.C)) }))
	add("merge-out", "out victim view", true, agg(func(f *fixture) bson.A { return arr(d("$out", f.BView)) }))
	add("merge-out", "out other db", true, agg(stages(d("$out", d("db", "other", "coll", "x")))))
	add("merge-out", "out admin", true, agg(stages(d("$out", d("db", "admin", "coll", "system.users")))))
	add("merge-out", "out with set tenant", true, agg(func(f *fixture) bson.A { return arr(d("$set", d("tenantId", tB)), d("$out", f.Other)) }))
	add("merge-out", "out in lookup", true, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("from", f.Other, "pipeline", arr(d("$out", "x")), "as", "j")))
	}))
	add("merge-out", "out in facet", true, agg(func(f *fixture) bson.A { return arr(d("$facet", d("a", arr(d("$out", f.Other))))) }))
	add("merge-out", "merge in unionWith", true, agg(func(f *fixture) bson.A {
		return arr(d("$unionWith", d("coll", f.C, "pipeline", arr(d("$merge", d("into", f.Other))))))
	}))
	add("merge-out", "out not last", true, agg(func(f *fixture) bson.A { return arr(d("$out", f.Other), d("$match", d("tenantId", tB))) }))
	add("merge-out", "merge on _id with dup _id", true, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$match", d("k", 0)), d("$replaceRoot", d("newRoot", d("_id", f.BID, "k", 0, "secret", "pwn"))),
			d("$merge", d("into", f.C, "on", "_id", "whenMatched", "replace", "whenNotMatched", "insert"))), "cursor", d())
	})
	add("merge-out", "merge replace _id of victim", true, func(f *fixture) bson.D {
		return d("aggregate", f.Other, "pipeline", arr(d("$limit", 1), d("$replaceRoot", d("newRoot", d("_id", f.BID, "secret", "pwn"))),
			d("$merge", d("into", f.C, "on", "_id", "whenMatched", "replace", "whenNotMatched", "insert"))), "cursor", d())
	})

	// ---- 4. update operator tampering -------------------------------------
	tamper := []struct {
		name string
		u    any
		af   bson.A
	}{
		{"$set tenant", d("$set", d("tenantId", tB)), nil},
		{"$set tenant to self (noop)", d("$set", d("tenantId", tA)), nil},
		{"$set dotted tenant", d("$set", d("tenantId.x", 1)), nil},
		{"$set nested tenant via parent", d("$set", d("tenantId", d("$x", 1))), nil},
		{"$unset tenant", d("$unset", d("tenantId", "")), nil},
		{"$rename to tenant", d("$rename", d("secret", "tenantId")), nil},
		{"$rename from tenant", d("$rename", d("tenantId", "oops")), nil},
		{"$rename swap", d("$rename", d("tenantId", "a", "secret", "tenantId")), nil},
		{"$setOnInsert tenant", d("$setOnInsert", d("tenantId", tB)), nil},
		{"$currentDate tenant", d("$currentDate", d("tenantId", true)), nil},
		{"$inc tenant", d("$inc", d("tenantId", 1)), nil},
		{"$push tenant", d("$push", d("tenantId", tB)), nil},
		{"$addToSet tenant", d("$addToSet", d("tenantId", tB)), nil},
		{"$min/$max tenant", d("$max", d("tenantId", "zzzz")), nil},
		{"$bit tenant", d("$bit", d("tenantId", d("or", 1))), nil},
		{"$mul tenant", d("$mul", d("tenantId", 2)), nil},
		{"$pull tenant", d("$pull", d("tenantId", tA)), nil},
		{"$set positional tenant", d("$set", d("tenantId.$", tB)), nil},
		{"$set all-positional tenant", d("$set", d("tenantId.$[]", tB)), nil},
		{"$set filtered tenant", d("$set", d("tenantId.$[e]", tB)), arr(d("e", d("$exists", true)))},
		{"arrayFilters tenant", d("$set", d("tags.$[e]", "z")), arr(d("e", d("$exists", true)))},
		{"arrayFilters victim tenant", d("$set", d("tags.$[e]", "z")), arr(d("e.tenantId", tB))},
		{"empty key set", d("$set", d("", 1)), nil},
		{"dup $set keys", d("$set", d("tenantId", tB, "tenantId", tA)), nil},
		{"dup operators", d("$set", d("x", 1), "$set", d("tenantId", tB)), nil},
		{"mixed operator and field", d("$set", d("x", 1), "tenantId", tB), nil},
		{"replacement with victim tenant", d("tenantId", tB, "k", 99), nil},
		{"replacement without tenant", d("k", 99), nil},
		{"replacement with _id of victim", d("_id", "BID", "k", 99), nil},
		{"replacement tenant array", d("tenantId", arr(tA, tB)), nil},
		{"pipeline set tenant", arr(d("$set", d("tenantId", tB))), nil},
		{"pipeline unset tenant", arr(d("$unset", "tenantId")), nil},
		{"pipeline replaceRoot", arr(d("$replaceRoot", d("newRoot", d("tenantId", tB)))), nil},
		{"pipeline replaceWith", arr(d("$replaceWith", d("k", 1))), nil},
		{"pipeline project tenant out", arr(d("$project", d("tenantId", 0))), nil},
		{"pipeline addFields dynamic", arr(d("$addFields", d("tenantId", d("$concat", arr("tenant-", "bravo"))))), nil},
		{"pipeline setField", arr(d("$replaceWith", d("$setField", d("field", "tenantId", "input", "$$ROOT", "value", tB)))), nil},
		{"pipeline lookup then set", arr(d("$set", d("j", "x")), d("$replaceWith", d("$unsetField", d("field", "tenantId", "input", "$$ROOT")))), nil},
		{"pipeline merge", arr(d("$merge", d("into", "x"))), nil},
		{"pipeline lookup victim", arr(d("$lookup", d("from", "o1", "pipeline", arr(d("$match", d("tenantId", tB))), "as", "j"))), nil},
		{"pipeline function", arr(d("$set", d("x", jsFn("function(){return 1}")))), nil},
		{"$set via let var", d("$set", d("tenantId", "$$t")), nil},
		{"$set x only (benign)", d("$set", d("x", 1)), nil},
	}
	for _, tp := range tamper {
		tp := tp
		for _, up := range []struct {
			n   string
			q   any
			opt []any
		}{
			{"self", d("k", 1), nil},
			{"all", d(), []any{"multi", true}},
			{"upsert-nomatch", d("k", 4242), []any{"upsert", true}},
			{"upsert-victim-eq", d("tenantId", tB, "k", 4243), []any{"upsert", true}},
			{"upsert-_id-victim", d("_id", "BID"), []any{"upsert", true}},
		} {
			up := up
			opts := append([]any{}, up.opt...)
			if tp.af != nil {
				opts = append(opts, "arrayFilters", tp.af)
			}
			add("update-tampering", "update "+tp.name+"/"+up.n, true, func(f *fixture) bson.D {
				fix := func(v any) any { return replaceBID(v, f) }
				return upd(fix(up.q), fix(tp.u), opts...)(f)
			})
		}
		add("update-tampering", "fam "+tp.name, true, func(f *fixture) bson.D {
			return fam("query", d("k", 1), "update", replaceBID(tp.u, f), "new", true)(f)
		})
		add("update-tampering", "fam upsert "+tp.name, true, func(f *fixture) bson.D {
			return fam("query", d("k", 4244), "update", replaceBID(tp.u, f), "upsert", true, "new", true)(f)
		})
	}
	add("update-tampering", "update let tenant", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("k", 1), "u", arr(d("$set", d("tenantId", "$$t"))), "c", d("t", tB))), "let", d("t", tB))
	})
	add("update-tampering", "update dup q", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("k", 1), "q", d("tenantId", tB), "u", d("$set", d("x", 1)), "multi", true)))
	})
	add("update-tampering", "update dup u", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("k", 1), "u", d("$set", d("x", 1)), "u", d("$set", d("tenantId", tB)))))
	})
	add("update-tampering", "update many statements one bad", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("k", 1), "u", d("$set", d("x", 1))), d("q", d("tenantId", tB), "u", d("$set", d("x", 1)), "multi", true)), "ordered", false)
	})
	add("update-tampering", "update updates as doc", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", d("q", d("tenantId", tB), "u", d("$set", d("x", 1))))
	})
	add("update-tampering", "update hint victim index", true, upd(d("k", 1), d("$set", d("x", 1)), "hint", "b_k_idx"))
	add("update-tampering", "update bypassDocumentValidation", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("k", 1), "u", d("$set", d("tenantId", tB)))), "bypassDocumentValidation", true)
	})
	add("update-tampering", "findAndModify sort/fields tenant", true, fam("query", d("k", 1), "update", d("$set", d("x", 1)), "fields", d("tenantId", 0, "secret", 1), "new", true))
	add("update-tampering", "findAndModify remove+update", true, fam("query", d("k", 1), "remove", true, "update", d("$set", d("x", 1))))
	add("update-tampering", "findAndModify missing action", true, fam("query", d("tenantId", tB)))
	add("update-tampering", "findAndModify sort tenant", true, fam("query", d(), "sort", d("tenantId", -1, "k", 1), "remove", true))

	// ---- 5. insert tampering / dup key oracles ----------------------------
	add("insert-tampering", "insert tenant victim", true, ins(d("tenantId", tB, "k", 100)))
	add("insert-tampering", "insert tenant array", true, ins(d("tenantId", arr(tA, tB), "k", 101)))
	add("insert-tampering", "insert tenant object", true, ins(d("tenantId", d("$ne", tA), "k", 102)))
	add("insert-tampering", "insert dup tenant keys", true, ins(d("tenantId", tB, "tenantId", tA, "k", 103)))
	add("insert-tampering", "insert dup tenant keys rev", true, ins(d("tenantId", tA, "tenantId", tB, "k", 104)))
	add("insert-tampering", "insert case-variant tenant", true, ins(d("tenantId", tU, "k", 105)))
	add("insert-tampering", "insert dotted key", true, ins(d("a.b", 1, "$x", 2, "k", 106)))
	add("insert-tampering", "insert $-prefixed top-level", true, ins(d("$set", d("tenantId", tB))))
	add("insert-tampering", "insert _id victim", true, func(f *fixture) bson.D { return d("insert", f.C, "documents", arr(d("_id", f.BID, "k", 107))) })
	add("insert-tampering", "insert _id victim unordered", true, func(f *fixture) bson.D {
		return d("insert", f.C, "documents", arr(d("_id", f.BID, "k", 108), d("k", 109)), "ordered", false)
	})
	add("insert-tampering", "insert _id victim with bypass", true, func(f *fixture) bson.D {
		return d("insert", f.C, "documents", arr(d("_id", f.BID, "k", 110)), "bypassDocumentValidation", true)
	})
	add("insert-tampering", "insert _id victim + upsert-ish via update", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("_id", f.BID), "u", d("$set", d("k", 111)), "upsert", true)))
	})
	add("insert-tampering", "insert _id victim into other coll", true, func(f *fixture) bson.D {
		return d("insert", f.Other, "documents", arr(d("_id", f.BID, "k", 112)))
	})
	add("insert-tampering", "insert unique-index victim value", true, func(f *fixture) bson.D { return d("insert", f.C, "documents", arr(d("k", 0, "x", 1))) })
	add("insert-tampering", "insert documents not array", true, func(f *fixture) bson.D { return d("insert", f.C, "documents", d("tenantId", tB)) })
	add("insert-tampering", "insert 0 docs", true, ins())
	add("insert-tampering", "insert huge string", true, ins(d("k", 113, "big", strings.Repeat("x", 1<<20))))
	add("insert-tampering", "insert deep doc", true, ins(deepNot(90)))
	add("insert-tampering", "insert json-injection string", true, ins(d("k", 114, "name", `x","tenantId":"tenant-bravo`)))
	add("insert-tampering", "insert NUL in values", true, ins(d("k", 115, "name", "a\x00b", "tenantId", tB+"\x00")))
	add("insert-tampering", "insert collation victim", true, func(f *fixture) bson.D {
		return d("insert", f.C, "documents", arr(d("k", 116)), "collation", d("locale", "en"))
	})
	add("insert-tampering", "insert let/comment", true, func(f *fixture) bson.D {
		return d("insert", f.C, "documents", arr(d("k", 117)), "comment", d("tenantId", tB), "writeConcern", d("w", "majority"))
	})
	add("insert-tampering", "delete one by victim _id", true, func(f *fixture) bson.D {
		return d("delete", f.C, "deletes", arr(d("q", d("_id", f.BID), "limit", 1)))
	})
	add("insert-tampering", "delete by victim _id $in", true, func(f *fixture) bson.D {
		return d("delete", f.C, "deletes", arr(d("q", d("_id", d("$in", arr(f.BID, f.CID))), "limit", 0)))
	})
	add("insert-tampering", "update by victim _id", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("_id", f.BID), "u", d("$set", d("pwn", 1)))))
	})
	add("insert-tampering", "replace by victim _id", true, func(f *fixture) bson.D {
		return d("update", f.C, "updates", arr(d("q", d("_id", f.BID), "u", d("pwn", 1))))
	})
	add("insert-tampering", "find by victim _id", false, func(f *fixture) bson.D { return d("find", f.C, "filter", d("_id", f.BID)) })
	add("insert-tampering", "find _id $in both", false, func(f *fixture) bson.D {
		return d("find", f.C, "filter", d("_id", d("$in", arr(f.BID, f.CID))))
	})
	add("insert-tampering", "count by victim _id", false, func(f *fixture) bson.D { return d("count", f.C, "query", d("_id", f.BID)) })
	add("insert-tampering", "distinct _id", false, func(f *fixture) bson.D { return d("distinct", f.C, "key", "_id") })
	add("insert-tampering", "fam by victim _id", true, func(f *fixture) bson.D {
		return d("findAndModify", f.C, "query", d("_id", f.BID), "remove", true)
	})
	add("insert-tampering", "agg match victim _id", false, func(f *fixture) bson.D {
		return d("aggregate", f.C, "pipeline", arr(d("$match", d("_id", f.BID))), "cursor", d())
	})
	add("insert-tampering", "agg group _id first", false, agg(stages(d("$group", d("_id", nil, "first", d("$first", "$_id"))))))
	add("insert-tampering", "agg lookup on _id", false, agg(func(f *fixture) bson.A {
		return arr(d("$lookup", d("from", f.Other, "localField", "_id", "foreignField", "_id", "as", "j")))
	}))

	// ---- 6. namespace / registry smuggling --------------------------------
	for _, opName := range []string{"find", "insert", "update", "delete", "aggregate", "count", "distinct", "drop", "createIndexes",
		"dropIndexes", "listIndexes", "collMod", "create", "validate", "collStats", "dataSize", "findAndModify", "renameTo", "renameFrom", "createView", "mapReduce", "explainFind", "geoNear", "reIndex", "compact"} {
		opName := opName
		for i := range reservedNames(&fixture{DB: isoDB, C: "c"}) {
			i := i
			add("namespace-smuggling", fmt.Sprintf("%s reserved#%d", opName, i), true, func(f *fixture) bson.D {
				n := reservedNames(f)[i]
				switch opName {
				case "find":
					return d("find", n, "filter", d())
				case "insert":
					return d("insert", n, "documents", arr(d("k", 1, "tenantId", tB)))
				case "update":
					return d("update", n, "updates", arr(d("q", d(), "u", d("$set", d("x", 1)), "multi", true, "upsert", true)))
				case "delete":
					return d("delete", n, "deletes", arr(d("q", d(), "limit", 0)))
				case "aggregate":
					return d("aggregate", n, "pipeline", arr(), "cursor", d())
				case "count":
					return d("count", n)
				case "distinct":
					return d("distinct", n, "key", "_id")
				case "drop":
					return d("drop", n)
				case "createIndexes":
					return d("createIndexes", n, "indexes", arr(d("key", d("x", 1), "name", "x_1")))
				case "dropIndexes":
					return d("dropIndexes", n, "index", "*")
				case "listIndexes":
					return d("listIndexes", n)
				case "collMod":
					return d("collMod", n, "validator", d("x", d("$exists", true)))
				case "create":
					return d("create", n)
				case "validate":
					return d("validate", n, "full", true)
				case "collStats":
					return d("collStats", n)
				case "dataSize":
					return d("dataSize", f.DB+"."+n)
				case "findAndModify":
					return d("findAndModify", n, "query", d(), "remove", true)
				case "renameTo":
					return d("renameCollection", f.DB+"."+f.C, "to", f.DB+"."+n, "dropTarget", true)
				case "renameFrom":
					return d("renameCollection", f.DB+"."+n, "to", f.DB+"."+f.C+"x", "dropTarget", false)
				case "createView":
					return d("create", n, "viewOn", f.C, "pipeline", arr())
				case "mapReduce":
					return d("mapReduce", n, "map", "function(){emit(1,1)}", "reduce", "function(k,v){return 1}", "out", d("inline", 1))
				case "explainFind":
					return d("explain", d("find", n, "filter", d()))
				case "geoNear":
					return d("geoNear", n, "near", arr(0, 0))
				case "reIndex":
					return d("reIndex", n)
				case "compact":
					return d("compact", n)
				}
				return nil
			})
		}
	}
	for _, db := range []string{"admin", "local", "config", "ADMIN", "Admin", "admin ", " admin", "admin\x00", "admin.", "app.x", "APP", "App", "app ", "aPP", "ｌocal", "a/b", "$external", "", "x", "other", "..", "*", "system", "ap​p", "test", "app\x00admin"} {
		db := db
		for _, op := range []func(f *fixture) bson.D{
			func(f *fixture) bson.D { return d("find", "system.users", "filter", d()) },
			func(f *fixture) bson.D { return d("find", f.C, "filter", d()) },
			func(f *fixture) bson.D { return d("find", "system.version", "filter", d()) },
			func(f *fixture) bson.D { return d("find", "oplog.rs", "filter", d()) },
			func(f *fixture) bson.D { return d("find", "system.sessions", "filter", d()) },
			func(f *fixture) bson.D { return d("aggregate", "system.users", "pipeline", arr(), "cursor", d()) },
			func(f *fixture) bson.D { return d("insert", "x", "documents", arr(d("a", 1))) },
			func(f *fixture) bson.D { return d("drop", "system.users") },
			func(f *fixture) bson.D { return d("dropDatabase", 1) },
			func(f *fixture) bson.D { return d("listCollections", 1) },
			func(f *fixture) bson.D { return d("dbStats", 1) },
			func(f *fixture) bson.D { return d("usersInfo", 1) },
			func(f *fixture) bson.D {
				return d("createIndexes", f.C, "indexes", arr(d("key", d("zz", 1), "name", "zz")))
			},
			func(f *fixture) bson.D {
				return d("aggregate", f.C, "pipeline", arr(d("$lookup", d("from", f.Other, "localField", "k", "foreignField", "k", "as", "j"))), "cursor", d())
			},
		} {
			op := op
			addDB("db-smuggling", db, fmt.Sprintf("db %q", db), true, op)
		}
	}
	// qualified collection names inside other namespaces
	add("namespace-smuggling", "find collection with db prefix", false, func(f *fixture) bson.D { return d("find", "admin.system.users", "filter", d()) })
	add("namespace-smuggling", "find collection with dots", false, func(f *fixture) bson.D { return d("find", "a.b.c", "filter", d()) })
	add("namespace-smuggling", "rename into victim coll", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+"."+f.Other, "dropTarget", true)
	})
	add("namespace-smuggling", "rename into victim coll (no dropTarget)", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+"."+f.Other)
	})
	add("namespace-smuggling", "rename from other", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.Other, "to", f.DB+".stolen", "dropTarget", true)
	})
	add("namespace-smuggling", "rename into victim view", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+"."+f.BView, "dropTarget", true)
	})
	add("namespace-smuggling", "rename to other db", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", "other."+f.C, "dropTarget", true)
	})
	add("namespace-smuggling", "rename to admin", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", "admin.system.users", "dropTarget", true)
	})
	add("namespace-smuggling", "rename from admin", true, func(f *fixture) bson.D {
		return d("renameCollection", "admin.system.users", "to", f.DB+".users", "dropTarget", true)
	})
	add("namespace-smuggling", "rename via admin db", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+".r"+f.C, "dropTarget", true, "$db", "admin")
	})
	add("namespace-smuggling", "rename dup to", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+".safe", "to", f.DB+"."+f.Other, "dropTarget", true)
	})
	add("namespace-smuggling", "rename to self", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+"."+f.C, "dropTarget", true)
	})
	add("namespace-smuggling", "rename numeric", true, func(f *fixture) bson.D { return d("renameCollection", 1, "to", 2) })
	add("namespace-smuggling", "rename with trailing/uppercase", true, func(f *fixture) bson.D {
		return d("renameCollection", f.DB+"."+f.C, "to", f.DB+"."+strings.ToUpper(f.Other), "dropTarget", true)
	})
	add("namespace-smuggling", "bulkWrite foreign ns", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("insert", 0, "document", d("tenantId", tB, "k", 1)), d("insert", 1, "document", d("pwn", 1)), d("delete", 2, "filter", d(), "multi", true)),
			"nsInfo", arr(d("ns", f.DB+"."+f.C), d("ns", "admin.system.users"), d("ns", f.DB+"."+f.Other)))
	})
	add("namespace-smuggling", "bulkWrite victim filters", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("update", 0, "filter", d("tenantId", tB), "updateMods", d("$set", d("pwn", 1)), "multi", true),
			d("delete", 0, "filter", d("tenantId", tC), "multi", true)), "nsInfo", arr(d("ns", f.DB+"."+f.C)))
	})
	add("namespace-smuggling", "bulkWrite ns index out of range", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("insert", 5, "document", d("k", 1)), d("insert", -1, "document", d("k", 2))), "nsInfo", arr(d("ns", f.DB+"."+f.C)))
	})
	add("namespace-smuggling", "bulkWrite ns reserved", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("delete", 0, "filter", d(), "multi", true), d("insert", 1, "document", d("v", 1))),
			"nsInfo", arr(d("ns", f.DB+".system.js"), d("ns", f.DB+".__mtp_views")))
	})
	add("namespace-smuggling", "bulkWrite ns dup entry", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("delete", 0, "filter", d(), "multi", true)),
			"nsInfo", arr(d("ns", f.DB+"."+f.C, "ns", "admin.system.users")))
	})
	add("namespace-smuggling", "bulkWrite upsert tamper", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("update", 0, "filter", d("k", 4300), "updateMods", d("$set", d("tenantId", tB)), "upsert", true)),
			"nsInfo", arr(d("ns", f.DB+"."+f.C)))
	})
	add("namespace-smuggling", "bulkWrite ops dup ns key", true, func(f *fixture) bson.D {
		return d("bulkWrite", 1, "ops", arr(d("insert", 0, "insert", 1, "document", d("pwn", 1))),
			"nsInfo", arr(d("ns", f.DB+"."+f.C), d("ns", "admin.x")))
	})

	// ---- 7. index tampering ----------------------------------------------
	add("index-tampering", "dropIndexes *", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", "*") })
	add("index-tampering", "dropIndexes victim name", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", "b_k_idx") })
	add("index-tampering", "dropIndexes victim physical name", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", f.BIdxPhys) })
	add("index-tampering", "dropIndexes victim physical name array", true, func(f *fixture) bson.D {
		return d("dropIndexes", f.C, "index", arr(f.BIdxPhys, f.CIdxPhys))
	})
	add("index-tampering", "dropIndexes by key", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", d("k", 1)) })
	add("index-tampering", "dropIndexes by key name+", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", d("name", 1)) })
	add("index-tampering", "dropIndexes _id_", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", "_id_") })
	add("index-tampering", "dropIndexes tenantId_1", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", "tenantId_1") })
	add("index-tampering", "dropIndexes int", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", 1) })
	add("index-tampering", "dropIndexes on other db", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", "*", "$db", "other") })
	add("index-tampering", "dropIndexes dup index", true, func(f *fixture) bson.D {
		return d("dropIndexes", f.C, "index", "nope", "index", f.BIdxPhys)
	})
	add("index-tampering", "dropIndexes glob", true, func(f *fixture) bson.D { return d("dropIndexes", f.C, "index", "b_*") })
	add("index-tampering", "dropIndexes suffix trick", true, func(f *fixture) bson.D {
		// a name that carries a tenant tag the proxy would treat as foreign/own
		return d("dropIndexes", f.C, "index", "b_k_idx__mtp_t000000000000")
	})
	add("index-tampering", "collMod victim index hidden", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "index", d("name", f.BIdxPhys, "hidden", true))
	})
	add("index-tampering", "collMod victim index ttl", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "index", d("name", f.BIdxPhys, "expireAfterSeconds", 1))
	})
	add("index-tampering", "collMod victim index by name", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "index", d("name", "b_k_idx", "hidden", true))
	})
	add("index-tampering", "collMod index by keyPattern", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "index", d("keyPattern", d("k", 1), "hidden", true))
	})
	add("index-tampering", "collMod validator", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "validator", d("$jsonSchema", d("required", arr("nonexistent"))), "validationAction", "error", "validationLevel", "strict")
	})
	add("index-tampering", "collMod validator expr", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "validator", d("$expr", d("$eq", arr("$tenantId", tB))))
	})
	add("index-tampering", "collMod viewOn", true, func(f *fixture) bson.D { return d("collMod", f.BView, "viewOn", f.Other, "pipeline", arr()) })
	add("index-tampering", "collMod physical view", true, func(f *fixture) bson.D { return d("collMod", f.BViewPhys, "viewOn", f.Other, "pipeline", arr()) })
	add("index-tampering", "collMod changeStreamPreAndPostImages", true, func(f *fixture) bson.D {
		return d("collMod", f.C, "changeStreamPreAndPostImages", d("enabled", false))
	})
	add("index-tampering", "collMod recordPreImages/capped", true, func(f *fixture) bson.D { return d("collMod", f.C, "cappedSize", 4096) })
	add("index-tampering", "collMod timeseries", true, func(f *fixture) bson.D { return d("collMod", f.C, "timeseries", d("granularity", "hours")) })
	add("index-tampering", "createIndexes unique across tenants", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("k", 1), "name", "uniq_k", "unique", true)))
	})
	add("index-tampering", "createIndexes unique on _id-less field", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("secret", 1), "name", "uniq_secret", "unique", true)))
	})
	add("index-tampering", "createIndexes name collides with victim", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("x", 1), "name", "b_k_idx")))
	})
	add("index-tampering", "createIndexes name collides physical", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("x", 1), "name", f.BIdxPhys)))
	})
	add("index-tampering", "createIndexes same key as victim different options", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("k", 1), "name", "k_other", "unique", true, "sparse", true)))
	})
	add("index-tampering", "createIndexes ttl", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("ts", 1), "name", "ttl_a", "expireAfterSeconds", 1)))
	})
	add("index-tampering", "createIndexes ttl on _id", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("_id", 1), "name", "ttl_id", "expireAfterSeconds", 1)))
	})
	add("index-tampering", "createIndexes ttl on tenantId", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("tenantId", 1), "name", "ttl_t", "expireAfterSeconds", 0)))
	})
	add("index-tampering", "createIndexes ttl with pfe victim", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("ts", 1), "name", "ttl_b", "expireAfterSeconds", 1, "partialFilterExpression", d("tenantId", tB))))
	})
	add("index-tampering", "createIndexes ttl with pfe or", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("ts", 1), "name", "ttl_or", "expireAfterSeconds", 1,
			"partialFilterExpression", d("$or", arr(d("tenantId", tB), d("tenantId", tA))))))
	})
	add("index-tampering", "createIndexes ttl with pfe exists", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("ts", 1), "name", "ttl_ex", "expireAfterSeconds", 1, "partialFilterExpression", d("tenantId", d("$exists", true)))))
	})
	add("index-tampering", "createIndexes pfe dup tenant key", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("ts", 1), "name", "ttl_dup", "expireAfterSeconds", 1, "partialFilterExpression", d("tenantId", tB, "tenantId", tA))))
	})
	add("index-tampering", "createIndexes wildcard", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("$**", 1), "name", "wild")))
	})
	add("index-tampering", "createIndexes text", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("name", "text"), "name", "txt")))
	})
	add("index-tampering", "createIndexes hashed tenant", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("tenantId", "hashed"), "name", "ht")))
	})
	add("index-tampering", "createIndexes many", true, func(f *fixture) bson.D {
		var ix bson.A
		for i := 0; i < 70; i++ {
			ix = append(ix, d("key", d(fmt.Sprintf("f%d", i), 1), "name", fmt.Sprintf("many%d", i)))
		}
		return d("createIndexes", f.C, "indexes", ix)
	})
	add("index-tampering", "createIndexes key not doc", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", "tenantId", "name", "bad")))
	})
	add("index-tampering", "createIndexes dup keys", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("a", 1), "key", d("tenantId", 1), "name", "dupkey")))
	})
	add("index-tampering", "createIndexes clustered/expire dup name", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("a", 1), "name", "n1", "name", "b_k_idx")))
	})
	add("index-tampering", "createIndexes commitQuorum", true, func(f *fixture) bson.D {
		return d("createIndexes", f.C, "indexes", arr(d("key", d("a", 1), "name", "cq")), "commitQuorum", "majority")
	})
	add("index-tampering", "listIndexes", false, func(f *fixture) bson.D { return d("listIndexes", f.C, "cursor", d("batchSize", 1)) })
	add("index-tampering", "listIndexes victim view", false, func(f *fixture) bson.D { return d("listIndexes", f.BView) })
	add("index-tampering", "agg $indexStats", false, agg(stages(d("$indexStats", d()))))

	// ---- 8. collection / database level ----------------------------------
	add("admin-leak", "drop collection", true, func(f *fixture) bson.D { return d("drop", f.C) })
	add("admin-leak", "drop other", true, func(f *fixture) bson.D { return d("drop", f.Other) })
	add("admin-leak", "drop victim view", true, func(f *fixture) bson.D { return d("drop", f.BView) })
	add("admin-leak", "drop physical view", true, func(f *fixture) bson.D { return d("drop", f.BViewPhys) })
	add("admin-leak", "drop dup", true, func(f *fixture) bson.D { return d("drop", f.C, "drop", f.Other) })
	add("admin-leak", "dropDatabase", true, func(f *fixture) bson.D { return d("dropDatabase", 1) })
	add("admin-leak", "dropDatabase writeConcern", true, func(f *fixture) bson.D { return d("dropDatabase", 1, "writeConcern", d("w", "majority")) })
	add("admin-leak", "create collection options", true, func(f *fixture) bson.D {
		return d("create", "newc", "capped", true, "size", 4096, "validator", d("tenantId", tB), "collation", d("locale", "en", "strength", 2))
	})
	add("admin-leak", "create timeseries", true, func(f *fixture) bson.D { return d("create", "ts1", "timeseries", d("timeField", "t")) })
	add("admin-leak", "create clustered", true, func(f *fixture) bson.D {
		return d("create", "cl1", "clusteredIndex", d("key", d("_id", 1), "unique", true))
	})
	add("admin-leak", "create view of victim view", true, func(f *fixture) bson.D { return d("create", "va", "viewOn", f.BView, "pipeline", arr()) })
	add("admin-leak", "create view of physical view", true, func(f *fixture) bson.D { return d("create", "vb", "viewOn", f.BViewPhys, "pipeline", arr()) })
	add("admin-leak", "create view of system.views", true, func(f *fixture) bson.D { return d("create", "vc", "viewOn", "system.views", "pipeline", arr()) })
	add("admin-leak", "create view of registry", true, func(f *fixture) bson.D { return d("create", "vd", "viewOn", "__mtp_views", "pipeline", arr()) })
	add("admin-leak", "create view with victim lookup", true, func(f *fixture) bson.D {
		return d("create", "ve", "viewOn", f.C, "pipeline", arr(d("$lookup", d("from", f.BViewPhys, "localField", "k", "foreignField", "k", "as", "j"))))
	})
	add("admin-leak", "create view pipeline match victim", true, func(f *fixture) bson.D {
		return d("create", "vf", "viewOn", f.C, "pipeline", arr(d("$match", d("tenantId", tB))))
	})
	add("admin-leak", "create view replaceRoot to hide tenant", true, func(f *fixture) bson.D {
		return d("create", "vg", "viewOn", f.C, "pipeline", arr(d("$unionWith", f.Other), d("$project", d("tenantId", 0))))
	})
	add("admin-leak", "create view unionWith", true, func(f *fixture) bson.D {
		return d("create", "vh", "viewOn", f.C, "pipeline", arr(d("$unionWith", d("coll", f.C, "pipeline", arr(d("$match", d("tenantId", tB)))))))
	})
	add("admin-leak", "create view with $out", true, func(f *fixture) bson.D {
		return d("create", "vi", "viewOn", f.C, "pipeline", arr(d("$out", "zz")))
	})
	add("admin-leak", "create view same name as victim view", true, func(f *fixture) bson.D {
		return d("create", f.BView, "viewOn", f.C, "pipeline", arr())
	})
	add("admin-leak", "create view over itself", true, func(f *fixture) bson.D { return d("create", "self", "viewOn", "self", "pipeline", arr()) })
	add("admin-leak", "create view with collation", true, func(f *fixture) bson.D {
		return d("create", "vj", "viewOn", f.C, "pipeline", arr(), "collation", d("locale", "en", "strength", 2))
	})
	add("admin-leak", "create view of other db", true, func(f *fixture) bson.D { return d("create", "vk", "viewOn", "other.x", "pipeline", arr()) })
	add("admin-leak", "create duplicate-name view then read", true, func(f *fixture) bson.D { return d("create", f.BView, "viewOn", f.Other) })
	add("admin-leak", "listCollections default", false, func(f *fixture) bson.D { return d("listCollections", 1) })
	add("admin-leak", "listCollections filter victim", false, func(f *fixture) bson.D { return d("listCollections", 1, "filter", d("name", d("$regex", "CNRY"))) })
	add("admin-leak", "listCollections filter __mtp", false, func(f *fixture) bson.D { return d("listCollections", 1, "filter", d("name", d("$regex", "^__mtp"))) })
	add("admin-leak", "listCollections filter system", false, func(f *fixture) bson.D { return d("listCollections", 1, "filter", d("name", d("$regex", "^system"))) })
	add("admin-leak", "listCollections filter options", false, func(f *fixture) bson.D {
		return d("listCollections", 1, "filter", d("options.viewOn", d("$exists", true)))
	})
	add("admin-leak", "listCollections filter viewOn", false, func(f *fixture) bson.D {
		return d("listCollections", 1, "filter", d("options.pipeline", d("$exists", true)))
	})
	add("admin-leak", "listCollections filter $or", false, func(f *fixture) bson.D {
		return d("listCollections", 1, "filter", d("$or", arr(d("name", "system.views"), d("name", d("$regex", "mtp")))))
	})
	add("admin-leak", "listCollections filter $expr", false, func(f *fixture) bson.D {
		return d("listCollections", 1, "filter", d("$expr", d("$regexMatch", d("input", "$name", "regex", "mtp"))))
	})
	add("admin-leak", "listCollections nameOnly authorized", false, func(f *fixture) bson.D {
		return d("listCollections", 1, "nameOnly", true, "authorizedCollections", true)
	})
	add("admin-leak", "listCollections dup filter", false, func(f *fixture) bson.D {
		return d("listCollections", 1, "filter", d("name", "nope"), "filter", d())
	})
	add("admin-leak", "listCollections coll 'system.views'", false, func(f *fixture) bson.D { return d("listCollections", "system.views") })
	add("admin-leak", "listDatabases", false, func(f *fixture) bson.D { return d("listDatabases", 1) })
	add("admin-leak", "listDatabases admin", false, func(f *fixture) bson.D { return d("listDatabases", 1, "$db", "admin") })
	addDB("admin-leak", "admin", "listDatabases in admin", false, func(f *fixture) bson.D { return d("listDatabases", 1, "nameOnly", true, "filter", d()) })
	addDB("admin-leak", "admin", "listDatabases filter", false, func(f *fixture) bson.D { return d("listDatabases", 1, "filter", d("name", d("$regex", ".*"))) })
	add("admin-leak", "listDatabases nameOnly", false, func(f *fixture) bson.D { return d("listDatabases", 1, "nameOnly", true) })
	add("admin-leak", "listDatabases authorized", false, func(f *fixture) bson.D { return d("listDatabases", 1, "authorizedDatabases", true) })
	add("admin-leak", "collStats", false, func(f *fixture) bson.D { return d("collStats", f.C) })
	add("admin-leak", "collStats scale", false, func(f *fixture) bson.D { return d("collStats", f.C, "scale", 1, "verbose", true) })
	add("admin-leak", "dbStats", false, func(f *fixture) bson.D { return d("dbStats", 1, "freeStorage", 1) })
	add("admin-leak", "dataSize", false, func(f *fixture) bson.D {
		return d("dataSize", f.DB+"."+f.C, "min", d("k", 0), "max", d("k", 9), "keyPattern", d("k", 1))
	})
	add("admin-leak", "validate", false, func(f *fixture) bson.D { return d("validate", f.C, "full", true) })
	add("admin-leak", "dbHash", false, func(f *fixture) bson.D { return d("dbHash", 1) })
	add("admin-leak", "top", false, func(f *fixture) bson.D { return d("top", 1) })
	add("admin-leak", "count no query", false, func(f *fixture) bson.D { return d("count", f.C) })
	add("admin-leak", "count with hint victim", false, func(f *fixture) bson.D { return d("count", f.C, "hint", f.BIdxPhys) })
	add("admin-leak", "distinct secret", false, func(f *fixture) bson.D { return d("distinct", f.C, "key", "secret") })
	add("admin-leak", "distinct tenantId", false, func(f *fixture) bson.D { return d("distinct", f.C, "key", "tenantId") })
	add("admin-leak", "distinct dotted", false, func(f *fixture) bson.D { return d("distinct", f.C, "key", "tenantId.x") })
	add("admin-leak", "distinct empty key", false, func(f *fixture) bson.D { return d("distinct", f.C, "key", "") })
	add("admin-leak", "distinct key array", false, func(f *fixture) bson.D { return d("distinct", f.C, "key", arr("tenantId")) })
	add("admin-leak", "distinct on view", false, func(f *fixture) bson.D { return d("distinct", f.BView, "key", "secret") })
	add("admin-leak", "mapReduce inline", false, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(this.tenantId, this.secret) }", "reduce", "function(k,v){ return v.join(',') }", "out", d("inline", 1))
	})
	add("admin-leak", "mapReduce query victim", false, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(1, this.secret) }", "reduce", "function(k,v){ return v[0] }", "out", d("inline", 1), "query", d("tenantId", tB))
	})
	add("admin-leak", "mapReduce out replace other", true, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(this.k, 1) }", "reduce", "function(k,v){ return 1 }", "out", d("replace", f.Other))
	})
	add("admin-leak", "mapReduce out merge victim view", true, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(this.k, 1) }", "reduce", "function(k,v){ return 1 }", "out", d("merge", f.BView))
	})
	add("admin-leak", "mapReduce out other db", true, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(this.k, 1) }", "reduce", "function(k,v){ return 1 }", "out", d("replace", "x", "db", "admin"))
	})
	add("admin-leak", "mapReduce scope/finalize", false, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(1, db.getSiblingDB('admin').system.users.findOne()) }", "reduce", "function(k,v){ return 1 }", "out", d("inline", 1))
	})
	add("admin-leak", "mapReduce reads other collection", false, func(f *fixture) bson.D {
		return d("mapReduce", f.C, "map", "function(){ emit(1, db.getCollection('"+f.Other+"').find().toArray()) }", "reduce", "function(k,v){ return 1 }", "out", d("inline", 1))
	})
	add("admin-leak", "$where reads other collection", false, find(d("$where", "db.getSiblingDB('admin').system.users.count() > 0")))
	add("admin-leak", "$where reads db", false, find(d("$where", "db.getCollection('c1').count() > 0")))
	add("admin-leak", "$function reads db", false, agg(stages(d("$addFields", d("x", jsFn("function(){ return db.getSiblingDB('admin').system.users.findOne() }"))))))
	add("admin-leak", "$function eval/sleep", false, agg(stages(d("$addFields", d("x", jsFn("function(){ return typeof sleep === 'function' ? 1 : 0 }"))))))
	add("admin-leak", "$function Function ctor", false, agg(stages(d("$addFields", d("x", jsFn("function(){ return (function(){ return this }).call(null) === undefined }"))))))
	add("admin-leak", "$function this global", false, agg(stages(d("$addFields", d("x", jsFn("function(){ return Object.keys((function(){return this})()).join(',') }"))))))
	add("admin-leak", "$function bsonsize/serverStatus", false, agg(stages(d("$addFields", d("x", jsFn("function(){ return typeof db + typeof require + typeof process }"))))))

	// admin / diagnostic / privilege commands
	for _, c := range []bson.D{
		d("hello", 1), d("isMaster", 1), d("ismaster", 1), d("buildInfo", 1), d("buildinfo", 1), d("connectionStatus", 1, "showPrivileges", true),
		d("usersInfo", 1), d("usersInfo", d("forAllDBs", true), "showCredentials", true), d("rolesInfo", 1, "showPrivileges", true),
		d("getParameter", "*"), d("getParameter", 1, "authenticationMechanisms", 1), d("setParameter", 1, "logLevel", 3),
		d("getCmdLineOpts", 1), d("getLog", "*"), d("getLog", "global"), d("hostInfo", 1), d("serverStatus", 1),
		d("serverStatus", 1, "repl", 1, "opcounters", 1, "connections", 1, "metrics", 1, "sharding", 0, "security", 1),
		d("replSetGetStatus", 1), d("replSetGetConfig", 1), d("replSetStepDown", 1), d("replSetFreeze", 1), d("replSetReconfig", d()),
		d("listCommands", 1), d("whatsmyuri", 1), d("ping", 1), d("logout", 1), d("shutdown", 1), d("shutdown", 1, "force", true),
		d("fsync", 1), d("fsyncUnlock", 1), d("compact", "c1"), d("repairDatabase", 1), d("reIndex", "c1"),
		d("planCacheClear", "c1"), d("planCacheListFilters", "c1"), d("planCacheSetFilter", "c1", "query", d(), "indexes", arr(d("k", 1))),
		d("profile", 2), d("profile", -1), d("setProfilingLevel", 2), d("getProfilingLevel", 1),
		d("createUser", "evil", "pwd", "x", "roles", arr("root")), d("dropUser", "CNRY-ROOT-user"), d("updateUser", "CNRY-ROOT-user", "pwd", "zz"),
		d("grantRolesToUser", "CNRY-ROOT-user", "roles", arr("root")), d("createRole", "r", "privileges", arr(), "roles", arr()),
		d("dropAllUsersFromDatabase", 1), d("dropAllRolesFromDatabase", 1),
		d("saslStart", 1, "mechanism", "SCRAM-SHA-256", "payload", bson.Binary{Data: []byte("n,,n=proxy,r=abc")}, "autoAuthorize", 1),
		d("authenticate", 1, "user", "proxy", "mechanism", "MONGODB-X509"), d("getnonce", 1),
		d("setFeatureCompatibilityVersion", "6.0", "confirm", true), d("getFeatureCompatibilityVersion", 1),
		d("setDefaultRWConcern", 1, "defaultWriteConcern", d("w", 0)), d("getDefaultRWConcern", 1),
		d("setClusterParameter", d("changeStreamOptions", d("preAndPostImages", d("expireAfterSeconds", 1)))), d("getClusterParameter", "*"),
		d("setUserWriteBlockMode", 1, "global", true), d("setIndexCommitQuorum", "c1", "indexNames", arr("a"), "commitQuorum", 1),
		d("killAllSessions", arr()), d("killAllSessionsByPattern", arr()), d("killSessions", arr(d("id", bson.Binary{Subtype: 4, Data: make([]byte, 16)}))),
		d("refreshSessions", arr()), d("endSessions", arr()), d("startSession", 1), d("commitTransaction", 1), d("abortTransaction", 1),
		d("currentOp", 1, "$all", true), d("currentOp", 1, "allUsers", true, "idleConnections", true), d("killOp", 1, "op", 1), d("killOp", 1, "op", "shard0:1"),
		d("inprog", 1), d("$eval", "1"), d("eval", "db.getSiblingDB('admin').system.users.find().toArray()"), d("doEval", 1),
		d("applyOps", arr(d("op", "i", "ns", "app.c1", "o", d("tenantId", tB, "x", 1)))), d("appendOplogNote", 1, "data", d("x", 1)),
		d("cloneCollectionAsCapped", "c1", "toCollection", "cc", "size", 4096), d("convertToCapped", "c1", "size", 4096),
		d("copydb", 1), d("clone", "x"), d("cleanupOrphaned", "app.c1"), d("flushRouterConfig", 1), d("sleep", 1, "secs", 1),
		d("configureFailPoint", "x", "mode", "alwaysOn"), d("sysprofile", 1), d("rotateCertificates", 1), d("logRotate", 1),
		d("autoSplitVector", "c1", "keyPattern", d("k", 1), "min", d("k", 0), "max", d("k", 9), "maxChunkSizeBytes", 1),
		d("splitVector", "app.c1", "keyPattern", d("k", 1), "maxChunkSizeBytes", 1), d("checkShardingIndex", "app.c1", "keyPattern", d("k", 1)),
		d("enableSharding", "app"), d("shardCollection", "app.c1", "key", d("k", 1)), d("moveChunk", "app.c1"), d("listShards", 1),
		d("mergeChunks", "app.c1"), d("balancerStatus", 1), d("transitionToDedicatedConfigServer", 1),
		d("explain", d("serverStatus", 1)), d("explain", d("dropDatabase", 1)), d("explain", d("drop", "c1")),
		d("explain", d("find", "c1", "filter", d("tenantId", tB)), "verbosity", "allPlansExecution"),
		d("explain", d("update", "c1", "updates", arr(d("q", d("tenantId", tB), "u", d("$set", d("x", 1)), "multi", true)))),
		d("explain", d("delete", "c1", "deletes", arr(d("q", d("tenantId", tB), "limit", 0)))),
		d("explain", d("count", "c1", "query", d("tenantId", tB))), d("explain", d("distinct", "c1", "key", "tenantId")),
		d("explain", d("findAndModify", "c1", "query", d("tenantId", tB), "remove", true)),
		d("explain", d("aggregate", "c1", "pipeline", arr(d("$match", d("tenantId", tB))), "cursor", d())),
		d("explain", d("mapReduce", "c1", "map", "function(){}", "reduce", "function(){}", "out", d("inline", 1))),
		d("explain", d("explain", d("find", "c1", "filter", d("tenantId", tB)))),
		d("explain", d("find", "c1", "filter", d()), "verbosity", d("x", 1)),
		d("explain", d("find", "c1", "filter", d()), "$db", "admin"),
		d("find", "c1", "filter", d(), "explain", true),
	} {
		c := c
		addDB("admin-leak", isoDB, "app/"+c[0].Key, true, func(f *fixture) bson.D { return rebind(c, f) })
		addDB("admin-leak", "admin", "admin/"+c[0].Key, true, func(f *fixture) bson.D { return rebind(c, f) })
	}
	for i := range as {
		a := &as[i]
		switch a.name {
		case "dropIndexes victim name", "dropIndexes victim physical name", "dropIndexes by key", "dropIndexes by key name+":
			a.known = "shared-indexes: any tenant can drop an index another tenant created"
		case "merge into victim view", "out victim view", "rename into victim view":
			a.known = "shared-namespace: collection names are global, a tenant may create a collection that shares a name with another tenant's view"
		}
	}
	return as
}

// rebind swaps the placeholder collection names c1/o1 in admin command
// templates for the fixture's collections.
func rebind(c bson.D, f *fixture) bson.D {
	b, _ := bson.MarshalExtJSON(c, true, false)
	s := string(b)
	s = strings.NewReplacer(`"c1"`, `"`+f.C+`"`, `"o1"`, `"`+f.Other+`"`, `app.c1`, f.DB+"."+f.C, `'c1'`, `'`+f.C+`'`).Replace(s)
	var out bson.D
	if err := bson.UnmarshalExtJSON([]byte(s), true, &out); err != nil {
		return c
	}
	return out
}

// replaceBID substitutes the sentinel "BID" with the fixture's victim _id.
func replaceBID(v any, f *fixture) any {
	switch x := v.(type) {
	case string:
		if x == "BID" {
			return f.BID
		}
		return x
	case bson.D:
		out := make(bson.D, len(x))
		for i, e := range x {
			out[i] = bson.E{Key: e.Key, Value: replaceBID(e.Value, f)}
		}
		return out
	case bson.A:
		out := make(bson.A, len(x))
		for i, e := range x {
			out[i] = replaceBID(e, f)
		}
		return out
	}
	return v
}

// TestAttackCatalogue runs every attack from tenant-alpha in every world.
func TestAttackCatalogue(t *testing.T) {
	as := catalogue()
	t.Logf("%d attacks × %d worlds", len(as), len(isoModes))
	for _, m := range isoModes {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			w := newIsoWorld(t, m)
			outcomes := map[string][2]int{} // class -> [rejected, accepted]
			var f *fixture
			var before map[string]string
			var bs string
			var obs map[string]string
			dirty := true
			sinceSeed := 0
			filter := os.Getenv("MTP_ATTACK_FILTER")
			for i, a := range as {
				if (testing.Short() || isoRace) && i%7 != 0 {
					continue
				}
				if filter != "" && !regexp.MustCompile(filter).MatchString(a.class+"/"+a.name) {
					continue
				}
				if dirty {
					f = w.seed()
					before, bs, obs = w.baseline(f)
				}
				db := a.db
				if db == "" {
					db = f.DB
				}
				start := time.Now()
				w.cur = a.class + "/" + a.name
				cmd := a.cmd(f)
				cmdText, _ := bson.MarshalExtJSON(cmd, true, false)
				blob, err := w.run(tA, db, cmd)
				if time.Since(start) > 15*time.Second {
					t.Errorf("%s: took %s (DoS?)", a.name, time.Since(start))
				}
				o := outcomes[a.class]
				if err != nil {
					o[0]++
				} else {
					o[1]++
				}
				outcomes[a.class] = o
				nfail := 0
				if t.Failed() {
					nfail = 1
				}
				w.check(f, a.class+"/"+a.name, before, bs, obs, blob, attackOpts{mutates: a.mutates, cmd: string(cmdText), known: a.known})
				// Anything that may have changed structure (collections, views,
				// validators, indexes) gets a fresh database; other writes only
				// need the attacker's own rows restored.
				dirty = t.Failed() && nfail == 0
				sinceSeed++
				if sinceSeed >= 60 {
					dirty = true
				}
				if !dirty && a.mutates {
					low := strings.ToLower(a.name)
					for _, kw := range []string{"drop", "rename", "collmod", "create", "database", "view"} {
						if strings.Contains(low, kw) {
							dirty = true
						}
					}
					if !dirty {
						w.resetAttacker(f)
						obs[tA] = w.observe(tA, f)
						obs[tA+"#idx"] = strings.Join(w.observeIdx(tA, f), "\n")
					}
				}
				if dirty {
					sinceSeed = 0
				}
				if t.Failed() && testing.Short() {
					return
				}
			}
			for c, o := range outcomes {
				t.Logf("%-20s rejected=%d accepted=%d", c, o[0], o[1])
			}
		})
	}
}
