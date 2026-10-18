package rewrite

import (
	"crypto/rand"
	"encoding/hex"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

// Installing a staging collection into a shared target for one tenant.
//
// $out and mapReduce's collection output both produce their result in a
// private staging collection first. install then moves it into the shared
// target collection, confined to the tenant's documents:
//
//   - replace: the tenant's documents in the target are replaced as a unit.
//     With a transaction-capable upstream this is one transaction (delete the
//     tenant's documents, insert the staged ones), so readers see either the
//     old or the new set. Without one, or if the transaction fails (for
//     example it is too large), it falls back to a marker-based merge followed
//     by deleting the stale documents, which is not atomic.
//   - merge: staged documents overwrite documents with the same _id.
//   - reduce: staged and existing values with the same _id are combined with
//     the mapReduce reduce function.

type installMode int

const (
	modeReplace installMode = iota
	modeMerge
	modeReduce
)

func (r *Rewriter) install(u bound, srcDB, src, dstDB, dst string, mode installMode, reduceFn string) error {
	un := r.uniqueIndex(dstDB, dst, []string{r.field, "_id"})
	if _, err := runIgnoring(u, un.DB, un.Body, 68, 85, 86); err != nil {
		return err
	}
	switch mode {
	case modeReplace:
		if u.Txn() {
			if err := r.swapTxn(u, srcDB, src, dstDB, dst); err == nil {
				return nil
			}
		}
		return r.swapMarker(u, srcDB, src, dstDB, dst)
	case modeMerge:
		return r.mergeStaged(u, srcDB, src, dstDB, dst, strVal("replace"))
	default:
		fn := bsoncore.AppendStringElement(nil, "body", reduceFn)
		pair := bsoncore.BuildArray(nil, strVal("$value"), strVal("$$new.value"))
		call := buildDoc(bDoc("$function", buildDoc(fn,
			bArr("args", arrayOf(strVal("$_id"), arrValue(pair))), bStr("lang", "js"))))
		reduced := buildDoc(bArr("$mergeObjects", arrayOf(strVal("$$ROOT"), docValue(buildDoc(valElem("value", docValue(call)))))))
		pipe := arrayOf(docValue(buildDoc(valElem("$replaceWith", docValue(reduced)))))
		return r.mergeStaged(u, srcDB, src, dstDB, dst, arrValue(pipe))
	}
}

func (r *Rewriter) mergeSpec(dstDB, dst string, whenMatched value) doc {
	return buildDoc(
		bDoc("into", buildDoc(bStr("db", dstDB), bStr("coll", dst))),
		bArr("on", arrayOf(strVal(r.field), strVal("_id"))),
		valElem("whenMatched", whenMatched),
		bStr("whenNotMatched", "insert"))
}

func (r *Rewriter) stampStage(u bound) value {
	return docValue(buildDoc(bDoc("$set", r.tenantDoc(u.t))))
}

func (r *Rewriter) mergeStaged(u bound, srcDB, src, dstDB, dst string, whenMatched value) error {
	_, err := run(u, srcDB, buildDoc(bStr("aggregate", src), bArr("pipeline", arrayOf(
		r.stampStage(u), docValue(buildDoc(bDoc("$merge", r.mergeSpec(dstDB, dst, whenMatched)))))),
		bDoc("cursor", buildDoc())))
	return err
}

func (r *Rewriter) swapMarker(u bound, srcDB, src, dstDB, dst string) error {
	var rb [8]byte
	rand.Read(rb[:])
	runID := hex.EncodeToString(rb[:])
	marker := docValue(buildDoc(bDoc("$set", buildDoc(bStr(outMarker, runID)))))
	if _, err := run(u, srcDB, buildDoc(bStr("aggregate", src), bArr("pipeline", arrayOf(
		r.stampStage(u), marker,
		docValue(buildDoc(bDoc("$merge", r.mergeSpec(dstDB, dst, strVal("replace"))))))),
		bDoc("cursor", buildDoc()))); err != nil {
		return err
	}
	stale := buildDoc(valElem(r.field, u.t.Value), bDoc(outMarker, buildDoc(bStr("$ne", runID))))
	if _, err := run(u, dstDB, buildDoc(bStr("delete", dst), bArr("deletes", arrayOf(docValue(buildDoc(
		bDoc("q", stale), bI32("limit", 0))))))); err != nil {
		return err
	}
	_, err := run(u, dstDB, buildDoc(bStr("update", dst), bArr("updates", arrayOf(docValue(buildDoc(
		bDoc("q", r.tenantDoc(u.t)), bDoc("u", buildDoc(bDoc("$unset", buildDoc(bStr(outMarker, ""))))),
		bBool("multi", true)))))))
	return err
}

const (
	swapBatchDocs  = 500
	swapBatchBytes = 8 << 20
)

// swapTxn replaces the tenant's documents in dst with the staged ones in a
// single transaction.
func (r *Rewriter) swapTxn(u bound, srcDB, src, dstDB, dst string) error {
	var id [16]byte
	rand.Read(id[:])
	lsid := buildDoc(bsoncore.AppendBinaryElement(nil, "id", 4, id[:]))
	started := false
	tx := func(cmd doc) doc {
		cmd = appendRaw(cmd, bDoc("lsid", lsid))
		cmd = appendRaw(cmd, bI64("txnNumber", 1))
		cmd = appendRaw(cmd, bBool("autocommit", false))
		if !started {
			started = true
			cmd = appendRaw(cmd, bBool("startTransaction", true))
		}
		return cmd
	}
	// The abort is best-effort.
	abort := func() {
		cmd := buildDoc(bI32("abortTransaction", 1), bDoc("lsid", lsid), bI64("txnNumber", 1), bBool("autocommit", false))
		u.Run("admin", cmd)
	}
	fail := func(e error) error {
		if started {
			abort()
		}
		return e
	}

	if _, e := run(u, dstDB, tx(buildDoc(bStr("delete", dst), bArr("deletes", arrayOf(docValue(buildDoc(
		bDoc("q", r.tenantDoc(u.t)), bI32("limit", 0)))))))); e != nil {
		return fail(e)
	}
	insert := func(batch []value) error {
		_, e := run(u, dstDB, tx(buildDoc(bStr("insert", dst), bArr("documents", arrayOf(batch...)))))
		return e
	}
	resp, e := run(u, srcDB, buildDoc(bStr("find", src), bI32("batchSize", swapBatchDocs)))
	if e != nil {
		return fail(e)
	}
	var batch []value
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		e := insert(batch)
		batch, size = nil, 0
		return e
	}
	for {
		for _, d := range firstBatch(resp) {
			nd, e := r.ensureTenant(u.t, d)
			if e != nil {
				return fail(e)
			}
			batch = append(batch, docValue(nd))
			size += len(nd)
			if len(batch) >= swapBatchDocs || size >= swapBatchBytes {
				if e := flush(); e != nil {
					return fail(e)
				}
			}
		}
		cid, _ := resp.Lookup("cursor", "id").AsInt64OK()
		if cid == 0 {
			break
		}
		if resp, e = run(u, srcDB, buildDoc(bI64("getMore", cid), bStr("collection", src), bI32("batchSize", swapBatchDocs))); e != nil {
			return fail(e)
		}
	}
	if e := flush(); e != nil {
		return fail(e)
	}
	if !started {
		// Nothing staged and nothing deleted would have started it; the delete
		// always runs first, so this is unreachable, but keep the invariant.
		return nil
	}
	_, e = run(u, "admin", buildDoc(bI32("commitTransaction", 1), bDoc("lsid", lsid), bI64("txnNumber", 1), bBool("autocommit", false)))
	if e != nil {
		return fail(e)
	}
	return nil
}
