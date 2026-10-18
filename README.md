# mongodb-tenant-proxy

A MongoDB wire-protocol proxy that confines every client connection to **one tenant's documents** in shared collections. Applications keep using their normal driver and queries; the proxy rewrites each command so it can only read, write, count, aggregate or index documents whose `tenantId` equals the connection's tenant.

```
app (driver) ──► mongodb-tenant-proxy ──► MongoDB (replica set / standalone)
                 • identifies the tenant
                 • rewrites every command
                 • allow-list of commands/stages
```

## How isolation is enforced

| Operation | Rewrite |
|---|---|
| `find`, `count`, `distinct`, `delete`, `update`/`findAndModify` filters | `{$and: [{tenantId: T}, <original>]}` – a client `$or`/`$nor`/`tenantId` clause can never widen it |
| `insert`, replacement updates, upserts | `tenantId` stamped on every document; a different value is **rejected** |
| update operators | any operator touching `tenantId` (`$set`, `$unset`, `$rename`, `tenantId.x`…) is rejected; pipeline updates get a final `$set: {tenantId: T}` |
| `aggregate` | tenant `$match` injected first (merged into a leading `$match` so `$text` still works; `$geoNear.query` scoped); `$lookup`, `$graphLookup`, `$unionWith` (incl. nested and `$facet` branches) are scoped on the foreign side |
| `createIndexes` | keys prefixed with `tenantId`, so unique indexes are **per tenant** and every query uses the index; `listIndexes` hides the prefix |
| `drop` | becomes "delete this tenant's documents" |
| `getMore` / `killCursors` | only cursors opened on the same connection are usable |
| `listDatabases` | filtered to accessible databases |
| `explain` | inner command is rewritten |
| `$changeStream` | collection- and database-level, on by default – see below |
| `$merge` / `$out` | matched on `(tenantId, …)` with an auto-created unique index; documents stamped with the tenant; `$out` replaces only the tenant's documents |
| views (`create`+`viewOn`, `collMod`, `drop`) | per-tenant hidden physical views with a tenant-scoped pipeline; see below |
| `mapReduce` | inline output, query scoped |

Everything else is **denied** by default: `$currentOp`, `$collStats`, `$indexStats`, `$search`/`$vectorSearch` (Atlas), `$documents`, cluster-level change streams, `dropDatabase`, `renameCollection`, `collMod` on collections, `mapReduce` output to a collection, `system.*` and `__mtp_*` collections, `admin`/`local`/`config`, duplicate command keys, and unknown commands. Denials are returned as `Unauthorized (13)` and logged. Server-side JavaScript (`$where`, `$function`, `$accumulator`, `mapReduce`) is **allowed** — it runs inside `mongod` with the tenant filter wrapped around it and cannot reach other documents or collections; set `disableJS` to reject it.

## Views

A physical view is shared by every tenant, so it can't hold a per-tenant definition (a `$group` view would mix tenants). Each tenant view therefore becomes its own hidden physical view `__mtp_v.<hash>.<name>` whose pipeline starts with the tenant filter, and the proxy maps the tenant's name to it. Definitions live in `__mtp_views` (per database), so two tenants can have different views with the same name, `listCollections` shows only a tenant's own views (`type: "view"`), view-on-view works, and `collMod`/`drop` affect only the caller's view. Views are read-only; names can't collide with the tenant's collections. Disable with `disableViews`.

## `$merge` / `$out`

Output collections are shared, so writes are matched on `(tenantId, <on fields>)` using a unique index with exactly that key (created automatically). A tenant can never overwrite another tenant's document, and the stage re-stamps the tenant on every document. `$out` is emulated as "replace this tenant's documents": it merges with a run marker, then deletes the tenant's documents that weren't part of the run — so unlike a real `$out` it is **not atomic** (other tenants are unaffected). `$merge`/`$out` are allowed only as the last stage of a top-level aggregate.

## Identifying the tenant (`auth.mode`)

* **`scram`** – clients connect with `mongodb://user:pass@proxy/?authMechanism=SCRAM-SHA-256`; each user is bound to a tenant in the config. Generate entries with `MTP_PASSWORD=… mongodb-tenant-proxy hash-password -user acme -tenant acme`.
* **`appname`** – tenant = the driver's `appName`. With `appNameSecret` set the name must be `<tenant>.<hmac>` (`mongodb-tenant-proxy sign-appname -secret … -tenant acme`); without it, the proxy must only be reachable by trusted services.
* **`static`** – every connection belongs to `staticTenant` (one proxy/port per tenant, e.g. behind per-tenant network policy).

The proxy authenticates to MongoDB itself (SCRAM-SHA-256, optional TLS) and presents itself to drivers as a `mongos`, so drivers never discover and bypass it via replica-set member addresses.

## Change streams

On by default (MongoDB 6.0+), collection level. Tenants get the stream a real server would give them, filtered to their own documents:

* **Shared fan-out.** A fresh stream (optionally with `fullDocument`, `fullDocumentBeforeChange` and a `$match` on `operationType`) is served from **one upstream change stream per collection**. The proxy routes each event to the subscribers of the tenant that owns it, so 40 watchers across 5 tenants cost 1 upstream cursor and one oplog scan instead of 40. Streams are anchored at the cluster's operation time when opened, resume tokens are the real ones, and each subscriber has a bounded buffer; one that falls behind gets a resumable error and the driver resumes it privately.
* **Private server-side stream.** Anything else (`resumeAfter`/`startAfter`/`startAtOperationTime`, `$project` and other stages, `showExpandedEvents`) runs as a normal change stream with a `$match` placed directly after `$changeStream`, so client stages never see other tenants' events.
* **Tenant on every event.** Updates and deletes don't carry `tenantId`, so the proxy forces `fullDocument`/`fullDocumentBeforeChange: "required"` (collection pre/post images) and removes them again unless the client asked. The proxy enables `changeStreamPreAndPostImages` itself the first time a collection is watched (disable with `changeStreams.disableAutoImages`).
* **Lifecycle events** (`drop`, `rename`, `dropDatabase`, `invalidate`) carry no document data and are delivered to every watcher of the collection, closing the stream after `invalidate`, as on a real server.
* **Database-level streams** (`db.watch()`) use one shared stream per database. The proxy enables images on the database's existing collections when the stream opens, and on collections written to afterwards; events from the proxy's own `__mtp_*` collections are never delivered. Cluster-level streams are refused. Config: `changeStreams.{disabled, disableAutoImages, disableFanout}`. (With several proxy instances, only the instance serving the watcher enables images for collections created later.)

Cost: pre/post images add oplog/storage on watched collections.

## Run

```bash
go build -o mongodb-tenant-proxy ./cmd/mongodb-tenant-proxy
./mongodb-tenant-proxy serve -config proxy.json
```

See [`proxy.example.json`](proxy.example.json). Metrics (`/metrics`, Prometheus text) and `/healthz` are served on `metricsAddr`. Client-facing TLS: `clientTLS.certFile/keyFile`.

## Performance

* Raw BSON rewriting – no struct decoding. A `find` rewrite is ≈0.85 µs / 33 allocs; stamping a 1,000-document insert is ≈125 µs.
* One goroutine and one dedicated upstream connection per client connection (cursors, sessions and transactions keep native semantics). Unmodified replies are forwarded as raw bytes.
* Measured on a laptop over loopback: point `findOne` ≈24 µs through the proxy vs ≈16 µs direct.

## `_id` uniqueness (`tenant.idPolicy`)

All tenants share each physical collection and MongoDB's `_id` index is unique per collection, so by default two tenants cannot use the same natural `_id`, and the duplicate-key error tells the second tenant that the first one has such a document. `tenant.idPolicy` selects how to deal with that:

| policy | behaviour |
| --- | --- |
| `native` (default) | Unchanged. Reusing another tenant's `_id` fails with a duplicate-key error. |
| `require-generated` | `_id` must be an **ObjectId or UUID (binary subtype 4)**; anything else is rejected on insert, on upserts (filter equality, `$set`/`$setOnInsert`, replacement documents, pipeline upserts that set `_id`) and on findAndModify upserts. Collisions then need a guessed 96/122-bit value. Duplicate-key errors on `_id` are rewritten to a generic `E11000 duplicate key error` with `keyPattern`/`keyValue`/`errInfo` removed; duplicates on other (tenant-prefixed) indexes are reported as before. `$merge`/`$out` get a run-time check that rejects documents whose `_id` is not an ObjectId (UUID `_id`s produced by a pipeline are refused too, because aggregation cannot test the binary subtype). |
| `namespace` | **Experimental**, requires `"experimentalNamespace": true`. Stores `_id` as `{t: <tenant>, id: <client _id>}`, so different tenants can use any natural `_id`, and unwraps it on every supported read path. Change streams and views are switched off. |

```json
"tenant": { "field": "tenantId", "idPolicy": "require-generated" }
"tenant": { "field": "tenantId", "idPolicy": "namespace", "experimentalNamespace": true }
```

Do not change the policy on a collection that already holds data written under another policy: existing `_id`s are not migrated.

### Limits of `namespace`

`namespace` rewrites queries on the way in and documents on the way out, so anything that would expose or depend on the stored form is rejected with an `Unauthorized`-style error that names the policy, rather than being silently wrong.

Supported: `insert` (missing `_id` is generated as an ObjectId), `find`/`count`/`distinct`/`aggregate`/`getMore`, `update`/`delete`/`findAndModify` (including upserts) and `explain` of those. Conditions on `_id` may use equality, `$eq $ne $gt $gte $lt $lte $in $nin $exists`, `$not`, and may be combined with `$and`/`$or`/`$nor` and dotted sub-paths (`"_id.a"`). `distinct("_id")`, `upserted` ids, findAndModify `value` and cursor batches are unwrapped.

Rejected:

* `_id` conditions with `$regex`, `$type`, `$mod`, `$size`, `$all`, `$elemMatch`, regular-expression literals, `$expr`/`$where`/`$jsonSchema` filters, and `find` `min`/`max`.
* Expressions that read `_id` or the whole document (`"$_id"`, `$$ROOT`, `$$CURRENT`) inside aggregation or update pipelines and projections, because they would return the wrapped value. That includes `$group: {_id: "$_id"}` and `$push: "$$ROOT"`. Grouping by other fields is fine, and `$group`'s own `_id` is returned untouched (the proxy tracks which stages produce a computed `_id`).
* Aggregation stages that read other collections or reshape output into nested documents: `$lookup`, `$graphLookup`, `$unionWith`, `$facet`, `$merge`, `$out`, `$changeStream`; `mapReduce`; views; change streams (database- and collection-level).
* Updates that write `_id` (`$set`, `$setOnInsert`, `$rename`, pipeline stages); pipeline-style and replacement upserts whose filter does not pin `_id` by equality (operator-style upserts are fine: the proxy adds a wrapped `$setOnInsert` `_id`).
* Server-side JavaScript in aggregation (it could read `this._id`).

Semantic differences to be aware of: range operators (`$gt` …) compare the wrapper as a whole, so unlike native queries they are not restricted to values of the operand's BSON type; sort order by `_id` follows BSON order of the unwrapped value within one tenant; documents are about 25 bytes larger; direct access to the database shows wrapped ids; partial or collated indexes that mention `_id` are not rewritten.

## Sessions

A logical session id (`lsid.id`) is a bearer token on the upstream server, which authenticates the proxy rather than the tenant, so another tenant who knew a session id could continue its transactions and retryable writes. The proxy keeps a shared table `lsid → tenant` (first use wins). Every command carrying an `lsid`, and every id listed in `endSessions`, `refreshSessions` or `killSessions`, is checked: a session owned by another tenant is refused with `Unauthorized` (`tenant proxy: session is not accessible`), which covers `commitTransaction`/`abortTransaction`, `getMore` and writes alike. A request that lists any foreign session is rejected as a whole and binds nothing. Malformed `lsid` values are rejected.

Bindings are refreshed on every use and expire `logicalSessionTimeoutMinutes` of the upstream (default 30) plus 10 minutes after the last use (mongod reaps expired sessions lazily); a tenant may hold at most 100 000 sessions. Rejections are counted in `mtp_session_rejections_total{tenant}`. The table lives in the proxy process: run replicas behind a router that keeps a client on one proxy, or accept that a restart forgets bindings (sessions upstream outlive the proxy, so right after a restart the first tenant to present an id would claim it; ids are 122-bit random, so this requires the id to leak).

## Quotas (`tenant.limits`)

Defaults live in `tenant.limits`; `tenant.overrides.<tenantId>` replaces individual fields for one tenant (zero or absent = inherit). Everything is unlimited unless set.

```json
"tenant": {
  "field": "tenantId",
  "limits": {
    "opsPerSec": 500, "opsBurst": 1000,
    "bytesPerSec": 52428800,
    "maxOpenCursors": 100,
    "maxIndexes": 20,
    "maxCommandBytes": 16777216, "maxResultBytes": 33554432,
    "maxTimeMSCap": 60000, "defaultMaxTimeMS": 30000,
    "maxInFlight": 64,
    "jsPerSec": 5
  },
  "overrides": { "acme": { "opsPerSec": 5000, "disableJS": true } }
}
```

| field | meaning |
| --- | --- |
| `opsPerSec`, `opsBurst` | Token bucket over commands (burst defaults to one second). `hello`, `ping` and SASL are exempt. |
| `bytesPerSec`, `bytesBurst` | Token bucket over request plus reply bytes. A single large message is admitted and put the bucket into debt, so the tenant is throttled afterwards rather than being unable to send it. |
| `maxOpenCursors` | Cursors open at once across all the tenant's connections (released on exhaustion, `killCursors` and disconnect). |
| `maxIndexes` | Distinct indexes created through the proxy (counted in memory, so the count restarts from zero with the proxy; re-creating an existing index is free, `dropIndexes` gives the slot back). |
| `maxCommandBytes`, `maxResultBytes` | Largest accepted command message / largest upstream reply. An oversized reply is replaced by an error and its cursor is killed; use a smaller `batchSize` or a projection. |
| `maxTimeMSCap`, `defaultMaxTimeMS` | Client `maxTimeMS` values (including `0` = unlimited) are clamped to the cap; reads, `findAndModify`, `mapReduce` and `createIndexes` without `maxTimeMS` get the default. Change streams and `getMore` are left alone. |
| `maxInFlight` | Commands executing at the same time for the tenant (`getMore` is exempt so long-polling tails don't hold slots). |
| `disableJS`, `jsPerSec` | Forbid server-side JavaScript (`$where`, `$function`, `$accumulator`, `mapReduce`) for the tenant, or cap commands that use it. The global `disableJS` still switches it off for everyone. |

Rejections return `code: 8000`, `codeName: "TenantQuotaExceeded"` and a message naming the quota, and are counted in `mtp_quota_rejections_total{tenant,reason}` (reasons: `ops_rate`, `bytes_rate`, `open_cursors`, `indexes`, `in_flight`, `command_size`, `result_size`, `js_disabled`, `js_rate`). Gauges `mtp_open_cursors{tenant}` and `mtp_inflight_operations{tenant}` show current usage. Limits are per proxy process.

## Requirements and limitations

* MongoDB **5.0+** (uses `$lookup` with both `localField` and `pipeline`). Transactions and retryable writes need a replica-set upstream, like with any driver.
* `_id` is unique per *collection*, not per tenant unless you pick an [`idPolicy`](#_id-uniqueness-tenantidpolicy). With the default (`native`) a natural `_id` reused by two tenants collides (and reveals existence).
* Indexes are shared physical objects: one tenant creating an index affects all; `dropIndexes: "*"` is refused. Deny `createIndexes`/`dropIndexes` via `denyCommands` if tenants must not manage indexes. TTL indexes cannot carry the tenant prefix (unique TTL indexes are refused).
* The `tenantId` field is visible in returned documents.
* `mapReduce` can't write to a collection (use `$merge`); `listCollections` filters other than `name`/`type` don't apply to views.
* No wire compression (not advertised), no `SCRAM-SHA-1`/x.509 on the client side.
* Session ids are bound to the first tenant that uses them ([Sessions](#sessions)); quotas are per proxy process, not shared between proxy replicas ([Quotas](#quotas-tenantlimits)).

## Tests

```bash
go test ./internal/...            # rewriter unit tests
go test ./test/ -count=1          # integration: real mongod replica set + official Go driver
go test ./test/ -bench FindOne -run xxx
```
Integration tests start their own `mongod` (must be on `PATH`) and cover isolation for CRUD, aggregation stages, cursors, bulk writes, transactions, indexes, and all three auth modes including an auth-enabled upstream.
