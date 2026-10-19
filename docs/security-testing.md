# Adversarial isolation testing

The proxy's promise is that a connection bound to tenant **A** can neither read,
change, delete nor *learn about* data that belongs to tenant **B**. This document
maps the vulnerability classes that matter for a multi-tenant MongoDB gateway to
the tests that exercise them against a real `mongod` and to what the proxy does.

The suite lives in `test/security_iso_*_test.go`:

| File | What it holds |
|---|---|
| `security_iso_world_test.go` | fixtures (four tenants with overlapping data, canaries), the universal invariants |
| `security_iso_attacks_test.go` | `TestAttackCatalogue`: ~2,800 single-command attacks, run in four "worlds" |
| `security_iso_stateful_test.go` | cursors, sessions/transactions, change streams, index privacy, `_id` oracle, known gaps |
| `security_iso_diff_test.go` | `TestDifferentialProxyVsPrivateDB`: random benign workloads, proxy vs private database |

```
go test ./test -run 'TestAttackCatalogue|TestSecurity|TestDifferential'   # full (~10 min; the four worlds run in parallel)
go test ./test -short -run ...                                            # every 7th attack, 1 differential seed
MTP_ATTACK_FILTER='index-tampering' go test ./test -run TestAttackCatalogue   # one class / attack by substring
```

Under `-race` the catalogue is thinned to every 7th attack automatically.
`MTP_MONGOD_BIN` points the suite at a specific `mongod` (the CI compatibility
matrix runs it against several server versions; `bulkWrite` namespace
smuggling attacks only reach the server on 8.0+).

## How the attack tests decide pass/fail

Every world seeds, per attack, a fresh pair of collections with five documents for
each of four tenants: the attacker `tenant-alpha`, the victims `tenant-bravo` and
`tenant-charlie`, and `TENANT-ALPHA`, a tenant whose id differs from the attacker's
only by case (collation collisions). Business fields (`k`, `name`, `grp`, …) are
identical across tenants; only the tenant id and a canary in `secret`
(`CNRY-BRAVO-3`, …) differ. The victims also own indexes and views, and the upstream
holds its own canaries (`system.js`, an admin user).

The attacker runs one command (and follows every cursor it opens), then these
invariants must hold regardless of whether the command was accepted:

1. **No leak.** No reply, error message or cursor batch contains a victim canary,
   victim tenant id, victim `_id` (non-`native` policies) or upstream secret. Strings the
   attacker itself put in the command may be echoed.
2. **No tampering.** Every stored victim document is byte-identical; no document with a
   forged or malformed tenant id exists anywhere; no upstream index or collection
   disappeared; the upstream user list is unchanged.
3. **No side effects visible to victims.** What each victim observes through the proxy
   (its documents, in both collections, and its views) is unchanged; victim indexes can
   only grow.
4. **Attacker integrity.** For read-only attacks the attacker's own view is unchanged.

The four worlds are `appname`+`native`, `appname`+`require-generated`,
`appname`+`namespace` (experimental) `_id` policies, and `scram` with an auth-enabled
upstream and `disableJS`.

## Vulnerability classes

| # | Class | Tests | What the proxy does |
|---|---|---|---|
| 1 | **Operator injection** into filters: `$or`/`$nor`/`$not`/`$ne`/`$in`/`$regex` on the tenant field, `$expr` tricks (`$getField`, `$regexMatch`, `$$ROOT`), `$where`, `$function`, `$jsonSchema`, deep nesting (5,000 levels), catastrophic regexes. Each filter is injected into find, count, distinct, `$match`, update/delete `q`, findAndModify query/remove. | catalogue `operator-injection` (~65 filters × 8 commands) | The tenant predicate is AND-ed at the top level of every filter, so no widening operator can escape it. JS runs inside `mongod` wrapped by the tenant filter (or is refused with `disableJS`). Bodies are validated to depth 100 first. When configured, `maxTimeMSCap`/`defaultMaxTimeMS` bound ReDoS (`mongod` also limits PCRE). |
| 2 | **Type confusion / smuggling**: arrays, objects, null, ints where strings are expected; dotted, empty and Unicode lookalike keys; NUL bytes in values; **duplicate keys** (`tenantId` twice, `filter` twice, `$db` twice, `pipeline` twice, `renameCollection.to` twice, `$changeStream` twice); wrong-type `collection`/`filter`/`pipeline`/`updates`/`documents`; `$db` override. | catalogue `operator-injection`, `option-smuggling`, `insert-tampering`, `namespace-smuggling` | Duplicate command keys are rejected outright. Wrong-typed fields are rejected before rewriting. The rewriter works on a validated BSON tree, never on re-serialised JSON, so there is no string-level injection. |
| 3 | **Aggregation pipeline injection**: `$lookup`/`$graphLookup`/`$unionWith` (collection, `{db,coll}` form, nested in `$facet`/`$lookup` pipelines, from `system.*`, `__mtp_*`, other databases, the victim's view and its physical view), `$facet`, `$geoNear`, `$documents`, `$redact`, `$setWindowFields`, multi-key stages, non-document stages, 1,500-stage and 120-deep pipelines, `$function`/`$accumulator`. Every administrative/internal stage (`$mergeCursors`, `$currentOp`, `$listSessions`, `$collStats`, `$indexStats`, `$planCacheStats`, `$queryStats`, `$_internal*`, `$changeStreamSplitLargeEvent`, `$listCatalog`, `$search`…) is tried at top level, in `$facet`, in `$lookup`, in `$unionWith`, after `$match`, in `admin` and with `aggregate: 1`. | catalogue `pipeline-injection` | Only an allow-list of stages is accepted; nested pipelines (`$lookup`, `$unionWith`, `$facet`, `$graphLookup`) are rewritten recursively so each source collection gets its own tenant `$match`. `from` is checked against the same namespace rules as top-level collections. Internal and administrative stages are not on the allow-list. |
| 4 | **`$merge` / `$out`** with other tenants' keys, `whenMatched` pipelines that restamp the tenant, other databases, `system.*`/`__mtp_*`, victim view names, mid-pipeline placement, victim `_id` replacement. | catalogue `merge-out` | Matched on `(tenantId, on…)` with a proxy-managed unique index, tenant re-stamped on every document, only legal as the last stage of a top-level aggregate; `$out` replaces only the tenant's rows. |
| 5 | **Update-operator tenant tampering**: 45 update documents (`$set`/`$unset`/`$rename`/`$setOnInsert`/`$currentDate`/`$inc`/`$push`/`$min`/…, dotted and positional paths, `arrayFilters`, duplicate operators, replacement documents, pipeline updates with `$set`/`$unset`/`$replaceRoot`/`$setField`/`$lookup`/`$merge`/`$function`) × 5 query shapes (self, all, upsert, upsert with victim equality, upsert by victim `_id`) + findAndModify (plain and upsert). | catalogue `update-tampering` | The tenant field is immutable: operators that touch it (including through `$rename`, pipelines and dynamic field operators) are rejected; upserts and replacements are re-stamped. |
| 6 | **Insert tampering and duplicate-key / `_id` oracles**: tenant field overrides, duplicate tenant keys, `_id` of a victim's document (insert, upsert, update, replace, delete, `$merge`), dot/`$` keys. | catalogue `insert-tampering`; `TestSecurityIDExistenceOracle`; `TestIDPolicy*` | `idPolicy: native` shares the `_id` space (a collision reveals that a victim owns that `_id` — **documented**); `require-generated` and `namespace` close the oracle and the error text is generic. The suite checks that victim canaries never appear in any E11000 message and that, outside `native`, the victim's `_id` never appears either. |
| 7 | **Cursor / `getMore` / `killCursors` hijacking and enumeration**; session, `lsid` and transaction abuse (foreign lsid for find/insert/commit/abort/start-transaction/`endSessions`/`killSessions`/`killAllSessions`, forged `uid`, duplicate `lsid`, wrong-typed `lsid`). | `TestSecurityCursorAttacks` (victim's cursor id probed with every collection/db combination and ±300 neighbouring ids; the victim's cursor must still deliver all its rows), `TestSecuritySessionAbuse`; existing `TestSessionsAreBoundToTenants` | Cursors and sessions are bound to the tenant that created them; foreign ids are refused with the same error as unknown ones. |
| 8 | **Change streams**: `resumeAfter`/`startAfter` with a victim's token, `startAtOperationTime` in the past, `fullDocument: required`, `fullDocumentBeforeChange`, `showExpandedEvents`, user pipelines (`$match` on the victim's tenant, `$replaceRoot`, `$project` tenant away, `$lookup`, `$unionWith`), database- and cluster-level streams, `allChangesForCluster`, duplicate `$changeStream` stages; victim insert/update/replace/delete/index/rename/drop activity runs meanwhile. | `TestSecurityChangeStreamAttacks` | Events are filtered per tenant using pre/post images; cluster-level streams are refused; the `__mtp_*` collections are filtered out; user stages after `$changeStream` run only on the tenant's events. |
| 9 | **Namespace, view and registry bypass**: `system.*`, `__mtp_*` (views, validators, `out`/`mr` temp collections, a victim's physical `__mtp_v.<hash>.<view>`), case and Unicode variants (`SYSTEM.JS`, full-width `ｓystem.js`, zero-width space), trailing dot/space, `db.coll` strings, `$cmd`, empty/slash/`$` names — in 25 operations (find, insert, update, delete, aggregate, drop, createIndexes, dropIndexes, listIndexes, collMod, create, validate, collStats, dataSize, rename from/to, createView, mapReduce, explain, geoNear, reIndex, compact…); 26 database-name tricks (`admin`, `ADMIN`, `admin\0`, `admin.`, full-width, `$external`, other databases) × 14 operations. | catalogue `namespace-smuggling`, `db-smuggling`, `admin-leak/create…view` | Collection and database names are validated against reserved prefixes (case-sensitively, which is how the server compares them) and illegal characters; databases outside the allow-list (and `admin`/`local`/`config`) are inaccessible; views are per-tenant hidden physical views. |
| 10 | **Collation-based tenant-id collisions**: strength 1/2, `alternate: shifted`, `normalization`, `numericOrdering` on find/count/distinct/aggregate/update/delete/findAndModify/explain/`createIndexes`, against a tenant whose id differs only by case. | catalogue `option-smuggling` | Collations weaker than strength 3 (and `alternate`/`numericOrdering`) are rejected on every command. |
| 11 | **Error-message / explain / stats oracles**: `explain` of every command at every verbosity, `collStats`, `dbStats`, `dataSize`, `validate`, `dbHash`, `top`, `listCollections` with filters over `name`/`options`, `listDatabases`, `distinct` on `tenantId`/`secret`/dotted keys, `currentOp`/`killOp`, `hello`/`buildInfo`/`connectionStatus`/`getParameter`/`getCmdLineOpts`/`getLog`/`hostInfo`/`serverStatus` in `app` and `admin`. | catalogue `admin-leak` | Stats are recomputed per tenant (exact counts, scaled sizes); `validate` and non-tenant `explain` shapes are refused; `listCollections`/`listDatabases` are filtered; privilege and topology commands are not on the command allow-list. **Known leak:** index names and key patterns appear in `explain` plans and `listIndexes` (below). |
| 12 | **Administrative command abuse**: ~150 commands (users/roles, `setParameter`, `shutdown`, `fsync`, `compact`, `applyOps`, `eval`, `saslStart`, `setFeatureCompatibilityVersion`, sharding commands, `killAllSessions`, `configureFailPoint`, …) in `app` and `admin`. The invariant includes "upstream user list unchanged". | catalogue `admin-leak` | Default-deny command allow-list. |
| 13 | **Index tampering**: `dropIndexes` (`*`, victim name, victim physical name, array, by key, suffix tricks), `collMod` index (`hidden`, `expireAfterSeconds`), `createIndexes` colliding on name, TTL on `_id`/`tenantId`, TTL with partial filters naming the victim, `$or` filters, duplicate keys, wildcard/text/hashed, 70-index batches. | catalogue `index-tampering`; `TestSecurityIndexPrivacy` (unique indexes are per tenant, TTL indexes upstream carry the owner's partial filter); `TestSecurityKnownGaps` | Keys are tenant-prefixed, unique indexes are per tenant, TTL indexes are made tenant-private. **Known gaps:** see below. |
| 14 | **`bulkWrite` namespace smuggling** (`nsInfo` pointing at `admin.system.users`, `system.js`, `__mtp_views`, index out of range, duplicate keys, victim filters, upsert with tenant `$set`) | catalogue `namespace-smuggling` (only reaches the server on 8.0+; on older servers the upstream refuses the command, which still satisfies the invariants) | Every `nsInfo` entry is validated as a top-level namespace and every op rewritten like its single-command equivalent. |
| 15 | **JavaScript escape**: `$where`/`$function`/mapReduce trying `db.getSiblingDB`, `db.getCollection`, `require`, `process`, global-object enumeration. | catalogue `admin-leak` | `mongod`'s JS runtime has no `db`/`require`/`process`; the tenant filter is applied around the JS stage. `disableJS` (global or per tenant) refuses it everywhere in a command. |
| 16 | **Differential correctness** (leaks *and* over-filtering): any benign workload must behave identically to a private database. | `TestDifferentialProxyVsPrivateDB`: 5 seeds × 250 operations × 3 `_id` policies, each op also replayed by two neighbours with identical data; random filters (≈14 leaf shapes combined with `$and`/`$or`/`$nor`), find with sort/skip/limit/projection, count, distinct, update/replace/upsert, delete, findAndModify, and aggregation pipelines from 20 stage templates (`$lookup` both forms, `$unionWith`, `$facet`, `$bucket`, `$graphLookup`, `$setWindowFields`, `$group`, …). Results, error codes and final collection contents must be equal. | n/a |

## Recent MongoDB CVEs and what the proxy can do about them

Taken from vendor/aggregator advisories found while writing this (version ranges are
as reported there and were not re-verified against MongoDB's own advisory pages —
check them before relying on this table).

| CVE | Summary | Proxy |
|---|---|---|
| CVE-2025-6713 | Low-privilege user can read collections beyond their grants using the internal `$mergeCursors` aggregation stage (fixed 6.0.22 / 7.0.19 / 8.0.7). | The stage is not on the allow-list; the suite sends it at top level, nested, and in `admin` (catalogue `stage $mergeCursors`). Still patch the server. |
| CVE-2025-6706 | Memory safety bug in the SBE engine reachable via certain aggregations. | Cannot be filtered by a proxy; reduce exposure with the stage allow-list and `maxTimeMSCap`/`maxResultBytes`. Patch the server. |
| CVE-2026-13076 | Authenticated DoS: a type conversion in an aggregation exhausts memory (8.3.x). | Same: patch; the proxy's per-tenant `maxInFlight`/`maxTimeMS` limits bound blast radius. |
| CVE-2026-18697 | Unauthenticated aggregation command crashes `mongos`. | The proxy only forwards allow-listed, fully validated commands, from authenticated tenants. It is mitigation by narrowing, not a guarantee. |
| CVE-2026-55253 (langgraph-checkpoint-mongodb) and the Budibase advisory | Application-level operator injection (`$regex`/`$where`) in user-supplied filters defeats per-tenant equality filtering. | This is exactly the class the proxy is built for: class 1 above shows injected operators cannot escape the tenant predicate even when the application is vulnerable. |

## Findings of this exercise

* **Fixed:** none were needed in `internal/` — every attack in the catalogue and every
  differential workload satisfied the invariants against the production code, apart
  from the documented limitations below.
* **Known limitations pinned by tests** (`TestSecurityKnownGaps`; each fails with an
  instruction to update this document when it stops being true):
  1. *Shared indexes — metadata leak.* Non-TTL indexes are shared physical objects, so
     `listIndexes` and `explain` show every tenant's index names and key patterns
     (only TTL indexes are hidden). Low–medium: no document data, but names can encode
     business information.
  2. *Shared indexes — cross-tenant drop.* `dropIndexes` by name or by key pattern
     drops the shared physical index, whoever created it (`"*"` is refused). Medium: a
     tenant can silently remove another tenant's *unique* index (integrity) or degrade
     its performance. Mitigation today: `denyCommands: ["dropIndexes"]`. A real fix is
     a durable ownership registry (per index: set of owning tenants; drop = disown, drop
     physically at zero owners; `listIndexes`/`explain` filtered to owned indexes) — not
     done here because it adds persistent state and changes `createIndexes` semantics.
  3. *Shared namespace.* A tenant can create a collection whose name equals another
     tenant's view name; both coexist, `listCollections` shows it to everyone, but the
     view owner's reads still resolve to the view. Cosmetic.
  4. `idPolicy: native` shares the `_id` space (documented in the README): an E11000
     response confirms that another tenant owns that `_id` and quotes it.
* Not tested for lack of a deployment: Atlas Search/`$vectorSearch` data paths (the
  stages are rejected without `mongot`), sharded clusters, x.509/OIDC client modes
  (covered by the dedicated auth tests; SCRAM and appname are run through the full
  catalogue).
