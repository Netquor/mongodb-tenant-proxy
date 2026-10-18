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
| `mapReduce` | query scoped; inline output, or `out` to a collection (replace / merge / reduce) installed per tenant |
| `bulkWrite` (MongoDB 8.0 `client.bulkWrite`) | every op rewritten like insert/update/delete; every namespace validated; views are read-only |
| `$search`, `$searchMeta`, `$vectorSearch` (Atlas) | tenant `equals` clause injected into the search (see below) |
| `dropDatabase`, `renameCollection`, `collMod` (validators), `dbStats`, `collStats`/`$collStats`, `currentOp`/`$currentOp`, `killOp`, `serverStatus` | tenant-scoped versions, see "Admin commands" |

Everything else is **denied** by default: `$indexStats`, `$documents` (outside `$collStats`), cluster-level change streams, `validate`, `collMod` options other than a validator (see below), `system.*` and `__mtp_*` collections, `admin`/`local`/`config`, duplicate command keys, and unknown commands. Denials are returned as `Unauthorized (13)` and logged. Server-side JavaScript (`$where`, `$function`, `$accumulator`, `mapReduce`) is **allowed** — it runs inside `mongod` with the tenant filter wrapped around it and cannot reach other documents or collections; set `disableJS` to reject it.

## Views

A physical view is shared by every tenant, so it can't hold a per-tenant definition (a `$group` view would mix tenants). Each tenant view therefore becomes its own hidden physical view `__mtp_v.<hash>.<name>` whose pipeline starts with the tenant filter, and the proxy maps the tenant's name to it. Definitions live in `__mtp_views` (per database), so two tenants can have different views with the same name, `listCollections` shows only a tenant's own views (`type: "view"`), view-on-view works, and `collMod`/`drop` affect only the caller's view. Views are read-only; names can't collide with the tenant's collections. Disable with `disableViews`.

## `$merge` / `$out`

Output collections are shared, so writes are matched on `(tenantId, <on fields>)` using a unique index with exactly that key (created automatically). A tenant can never overwrite another tenant's document, and the stage re-stamps the tenant on every document. `$out` means "replace this tenant's documents". On a replica-set or sharded upstream it is **atomic**: the pipeline writes to a private staging collection (`__mtp_out_<run>`), then one transaction deletes the tenant's documents from the target and inserts the staged ones, so readers see the old or the new set, never a mix. If the transaction can't be used (standalone upstream, or it fails, e.g. because it is too large) the proxy falls back to the older emulation: merge with a run marker, then delete the tenant's documents that weren't part of the run — **not atomic**, other tenants unaffected. `$merge`/`$out` are allowed only as the last stage of a top-level aggregate.

## Atlas Search and Vector Search

`$search`, `$searchMeta` and `$vectorSearch` must be the first stage of a collection aggregate (or of a `$lookup`/`$unionWith` pipeline). The tenant restriction is made part of the search itself:

* `$search` / `$searchMeta`: the client's operator is nested as `compound.must` and `{equals: {path: "tenantId", value: <tenant>}}` is added to `compound.filter` (filter clauses don't affect scoring). `$searchMeta` `facet.operator` is scoped the same way, `knnBeta` gets the tenant in its own `filter`. A `$match` on the tenant follows `$search`/`$vectorSearch` as defence in depth (skipped with `returnStoredSource`, where the tenant field may not be stored).
* `$vectorSearch`: `filter` becomes `{$and: [{tenantId: {$eq: <tenant>}}, <client filter>]}`.

**Index requirements:** the search index must map the tenant field as `token` (string tenant ids), `objectId` or `number`, and the vector index must declare the tenant field as a `{"type": "filter"}` field. Without that the server rejects the query; it never returns unscoped results. These stages only exist on Atlas / with `mongot`; they are verified by unit tests, not by the integration suite.

## Admin commands

All of these are computed from the tenant's own documents; none of them reads or changes another tenant's data.

| Command | Behaviour |
|---|---|
| `dropDatabase` | deletes the tenant's documents in every collection of the database, drops the tenant's views and removes their validators. Collections are shared, so they are never dropped. |
| `renameCollection` | tenant-scoped copy: the tenant's documents are `$merge`d into the target (secondary indexes of the source are recreated there, except TTL indexes) and deleted from the source. Same or another allowed database. Fails with `NamespaceExists` if the tenant already has documents in the target unless `dropTarget: true`. **Not atomic**: a crash between copy and delete leaves the documents in both collections, never in neither. |
| `collMod` on a collection | only `validator`. It is stored per tenant (`__mtp_validators`) and the collection gets the AND of every tenant's validator, each wrapped as `{$or: [{tenantId: {$ne: T}}, <validator>]}`, so a validator only constrains its owner's documents. `listCollections` shows the caller's own validator. `validationLevel: "strict"` and `validationAction: "error"` (the defaults) are accepted as no-ops. Refused, because they change a property of the shared physical collection: `validationLevel`/`validationAction` otherwise, `index` (TTL expiry or `hidden` of a shared index would affect/delete other tenants' data), `expireAfterSeconds`, `cappedSize`/`cappedMax`, `changeStreamPreAndPostImages`, `timeseries`. `collMod` on views keeps working as before. Concurrent `collMod` calls on the same collection from different tenants can race while the combined validator is recomputed. |
| `dbStats`, `collStats` | `count`, `objects`, `size`/`dataSize` and `avgObjSize` are exact for the tenant (one scan of the tenant's documents per collection). `storageSize`, `indexSize`, `totalIndexSize`, `indexSizes` are **estimates**: the real totals scaled by the tenant's share of the data; `nindexes`/`indexes` are real. `dbStats` counts a collection if the tenant has at least one document in it. Replies carry `tenantScoped: true`. |
| `$collStats` | `count` and `storageStats` (same numbers as `collStats`), then the rest of the pipeline over that one document (needs `$documents`, MongoDB 5.1+). `latencyStats`/`queryExecStats` describe the whole shared collection and are refused. |
| `validate` | refused: it scans and locks the entire shared collection and reports counts of every tenant's documents. |
| `currentOp`, `$currentOp` | only operations on the tenant's own connections. Every client connection owns a dedicated upstream connection, and `$currentOp` reports the upstream peer of each operation, so the proxy filters on that. `$all`/`idleConnections` control idle entries; extra `currentOp` fields are a filter. Operations of the same tenant on *other proxy instances* are not listed. |
| `killOp` | kills an operation only if it is listed by the tenant's `currentOp`; any other opid is answered like an unknown one (`ok: 1`, nothing killed). |
| `serverStatus` | synthesized: `host`, `version`, `process`, `uptime`, `localTime`, `connections.current` (the tenant's connections). Real counters aggregate every tenant's activity and are not exposed. |

These commands run on the tenant's upstream connection and cannot take part in a client transaction (they are refused inside one).

## mapReduce output

`mapReduce` with `out: "coll"`, `{replace|merge|reduce: "coll", db: "other"}` runs the map/reduce over the tenant's documents into a private staging collection, then installs the result for the tenant only: every result document carries `tenantId`; `replace` replaces just the tenant's results (atomically in one transaction on a replica set, like `$out`); `merge` overwrites results with the same key; `reduce` combines new and existing values with the command's `reduce` function (run through `$function`; `finalize` is applied to the new results but not again after combining, a small difference from the real command). `sharded` and `nonAtomic` are accepted and ignored. Output `_id`s are the map keys and `_id` is unique per collection, so two tenants emitting the same key into the same output collection collide (`E11000`) — the general `_id` limitation below. The reply is `{result, counts, timeMillis, ok}`. `mapReduce` is deprecated by MongoDB; prefer `$merge`.

## `bulkWrite`

MongoDB 8.0's cross-namespace `bulkWrite` (`client.bulkWrite` in current drivers) is supported with `ops`/`nsInfo` as document sequences or arrays. Each op is rewritten exactly like the single-collection handlers (inserts stamped, filters scoped, update operators/pipelines/replacements guarded, unknown op fields refused); each `nsInfo` namespace must be in an allowed database and not `system.*`/`__mtp_*`; a namespace that is the tenant's view is refused; `ordered` and `errorsOnly` are passed through. Cursors for large result sets are tracked like any other. Integration tests need mongod 8.0 and skip with a message otherwise.

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

## Requirements and limitations

* MongoDB **5.0+** (uses `$lookup` with both `localField` and `pipeline`). Transactions and retryable writes need a replica-set upstream, like with any driver.
* `_id` is unique per *collection*, not per tenant. Use generated ObjectIds/UUIDs; a natural `_id` reused by two tenants will collide (and reveals existence).
* Indexes are shared physical objects: one tenant creating an index affects all; `dropIndexes: "*"` is refused. Deny `createIndexes`/`dropIndexes` via `denyCommands` if tenants must not manage indexes. TTL indexes cannot carry the tenant prefix, so they are made tenant-private instead: the proxy adds the tenant to the index's `partialFilterExpression` (expiry only ever deletes the creator's documents) and appends a `__mtp_t<tag>` suffix to the index name (shown by `listIndexes`, used by `dropIndexes`); unique TTL indexes are refused. Other tenants' private indexes are hidden from `listIndexes`.
* `create` accepts no collection options (`capped`, `validator`, `collation`, `clusteredIndex`, ...) because the physical collection is shared. Collations weaker than strength 3 (or `alternate: shifted`, `numericOrdering`) are rejected on every command, since they could make one tenant id compare equal to another. A default collation set out of band on a shared collection has the same effect and must be avoided.
* Requests are validated before rewriting: malformed BSON, nesting deeper than 100 levels and pipelines longer than 1000 stages are rejected, and server-side JavaScript (`$where`, `$function`, `$accumulator`) is refused anywhere in a command when `disableJS` is set.
* The `tenantId` field is visible in returned documents.
* `listCollections` filters other than `name`/`type` don't apply to views.
* No wire compression (not advertised), no `SCRAM-SHA-1`/x.509 on the client side.
* Session ids (`lsid`) are unguessable UUIDs but are not bound to a tenant.

## Tests

```bash
go test ./internal/...            # rewriter unit tests
go test ./test/ -count=1          # integration: real mongod replica set + official Go driver
go test ./test/ -bench FindOne -run xxx
```
Integration tests start their own `mongod` (must be on `PATH`) and cover isolation for CRUD, aggregation stages, cursors, bulk writes, transactions, indexes, and all three auth modes including an auth-enabled upstream.
