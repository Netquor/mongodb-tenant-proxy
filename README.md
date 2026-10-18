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

## High availability (replica sets)

Point the proxy at a replica set with a multi-host URI or `upstream.hosts`:

```json
"upstream": {
  "uri": "mongodb://proxy-user:CHANGE_ME@m1:27017,m2:27017,m3:27017/?replicaSet=rs0&authSource=admin&tls=true",
  "heartbeatInterval": "5s", "serverSelectionTimeout": "15s", "localThreshold": "15ms"
}
```

or, with per-member TLS (each entry is `"host:port"` or an object; unset fields inherit the global `tls`/`caFile`/`insecureSkipVerify`):

```json
"upstream": {
  "replicaSet": "rs0",
  "hosts": ["m1:27017", {"addr": "m2:27017", "tls": true, "caFile": "/etc/ssl/m2-ca.pem", "serverName": "m2.internal"}],
  "hostMap": {"mongo-2.cluster.local:27017": "10.0.0.12:27017"}
}
```

* **Monitoring.** One monitor per member polls `hello` (SDAM): server type (primary / secondary / arbiter / hidden), `setName`, tags, `lastWrite`, `setVersion`/`electionId` (a primary from an older election is ignored), RTT. Members the set advertises are discovered; ones it drops are forgotten. `hostMap` rewrites advertised addresses the proxy can't reach (containers, NAT). A single host without `replicaSet` is used as-is, like `directConnection=true` (set `directConnection=false` to discover from one seed). Standalone servers and mongos work too, with no routing.
* **Routing.** Writes and default reads go to the primary. Clients still see the proxy as a single mongos-like endpoint, so drivers send `$readPreference` and the proxy honours it for `find`, `aggregate` (without `$out`/`$merge`/`$changeStream`), `count`, `distinct`, `listCollections`, `listIndexes`, `dbStats`, `collStats`: `primary`, `primaryPreferred`, `secondary`, `secondaryPreferred`, `nearest`, `tags` (ordered tag sets) and `maxStalenessSeconds` (≥ 90, estimated as in the SDAM spec). Among eligible members it picks within `localThreshold` of the lowest RTT, preferring the less busy one. An unsatisfiable preference fails after `serverSelectionTimeout` with `FailedToSatisfyReadPreference` (133).
* **Affinity.** A cursor lives on the member that opened it: `getMore` and `killCursors` are sent back there. Change-stream and tailable cursors also keep their connection; transactions keep their connection from `startTransaction` until commit/abort (an abandoned transaction is aborted when the client disconnects). If the owning member is gone the client gets `CursorNotFound` / `NoSuchTransaction`.
* **Failover.** Network errors and "not primary" / "shutting down" replies mark the member unknown, flush its pool and trigger an immediate re-check, so the new primary is found in a heartbeat or two instead of a full interval. Commands that waited for no primary retry for up to `serverSelectionTimeout`. `NotWritablePrimary` / `NotPrimaryNoSecondaryOk` / `NotPrimaryOrSecondary` (10107, 13435, 13436) mean the command never ran, so outside transactions the proxy repeats it on the new primary itself. Other failover outcomes are handed to the driver to retry, with the labels it needs: `RetryableWriteError` (writes carrying a `txnNumber` that hit 189 / 11600 / 11602 / 91, or lost their upstream connection) and `TransientTransactionError` (anything that kills a transaction). A read whose connection breaks before any reply byte arrived, and a request that could not be written at all, are repeated on a fresh connection. Housekeeping commands the proxy runs for itself (index setup, view lookups, change-stream image setup) are idempotent and retried once the same way.
* Metrics: `mtp_upstream_pool_connections{member,state}`, `mtp_upstream_member_info{member,type}`, `mtp_upstream_topology_events_total`, `mtp_upstream_retries_total`.

## Connection pooling

```json
"upstream": { "pool": { "mode": "pooled", "maxSize": 100, "idleTimeout": "5m", "maxLifetime": "30m", "waitTimeout": "15s" } }
```

* `mode: "pooled"` (default): a client connection borrows an upstream connection from its member's bounded pool for the duration of one command and gives it back, so thousands of idle or chatty clients share a handful of upstream connections (`maxSize` per member). A connection is held back only while it must be: during a transaction, and for change-stream / tailable cursors. Ordinary cursors, sessions and retryable-write state are server-side and keyed by `lsid`, not by connection, so they need only *member* affinity (above), not a pinned connection. Idle connections are closed after `idleTimeout`, old ones after `maxLifetime`, and a connection the server dropped while idle is detected at checkout. If the pool is exhausted, commands wait up to `waitTimeout` (default `serverSelectionTimeout`) and then fail with `HostUnreachable`.
* `mode: "dedicated"`: the previous behaviour, one upstream connection per client connection (per member it talks to), for its whole lifetime. Use it if you need strict connection-level semantics or are debugging.
* A pinned connection counts against `maxSize`: `maxSize` should comfortably exceed the number of concurrent transactions and change streams per member.

## Large replies

Replies up to `streaming.thresholdBytes` (default 256 KiB) are read into memory. Larger replies that need no rewriting (ordinary `find`/`aggregate`/`getMore` batches - the common large case) are relayed to the client in 32 KiB chunks while the proxy follows the BSON structure just far enough to learn the `ok` flag and the cursor id/namespace it must track; memory per relayed reply is constant whatever the batch size. Replies the proxy has to rewrite (`listDatabases`, `listIndexes`, view results, `drop`) are buffered but never beyond `streaming.maxPatchBytes` (default `maxMessageBytes`); larger ones fail with `BSONObjectTooLarge` instead of exhausting memory. `thresholdBytes: -1` disables streaming. `mtp_streamed_replies_total` counts streamed replies.

Benchmark (`go test ./internal/proxy -bench RelayLargeBatch -benchmem`, Apple M4, loopback-free pure relay of one batch of 1 KiB documents):

| batch | mode | time/op | allocated/op | peak heap |
|---|---|---|---|---|
| 1 MiB | buffered (before) | 235 µs | 2.1 MB | 7 MiB |
| 1 MiB | streaming | 91 µs | 352 B | 0.03 MiB |
| 8 MiB | buffered (before) | 1.47 ms | 17 MB | 16 MiB |
| 8 MiB | streaming | 0.73 ms | 352 B | 0.03 MiB |
| 32 MiB | buffered (before) | 6.5 ms | 68 MB | 130 MiB |
| 32 MiB | streaming | 4.0 ms | 352 B | 0.03 MiB |

## Run

```bash
go build -o mongodb-tenant-proxy ./cmd/mongodb-tenant-proxy
./mongodb-tenant-proxy serve -config proxy.json
```

See [`proxy.example.json`](proxy.example.json). Metrics (`/metrics`, Prometheus text) and `/healthz` are served on `metricsAddr`. Client-facing TLS: `clientTLS.certFile/keyFile`.

## Performance

* Raw BSON rewriting – no struct decoding. A `find` rewrite is ≈0.85 µs / 33 allocs; stamping a 1,000-document insert is ≈125 µs.
* One goroutine per client connection; upstream connections are pooled and shared (see above), and unmodified large replies are streamed in chunks with constant memory. Cursors, sessions and transactions keep native semantics.
* Measured on a laptop over loopback: point `findOne` ≈24 µs through the proxy vs ≈16 µs direct.

## Requirements and limitations

* MongoDB **5.0+** (uses `$lookup` with both `localField` and `pipeline`). Transactions and retryable writes need a replica-set upstream, like with any driver.
* `_id` is unique per *collection*, not per tenant. Use generated ObjectIds/UUIDs; a natural `_id` reused by two tenants will collide (and reveals existence).
* Indexes are shared physical objects: one tenant creating an index affects all; `dropIndexes: "*"` is refused. Deny `createIndexes`/`dropIndexes` via `denyCommands` if tenants must not manage indexes. TTL indexes cannot carry the tenant prefix (unique TTL indexes are refused).
* The `tenantId` field is visible in returned documents.
* `mapReduce` can't write to a collection (use `$merge`); `listCollections` filters other than `name`/`type` don't apply to views.
* No wire compression (not advertised), no `SCRAM-SHA-1`/x.509 on the client side.
* Upstream routing: `hedge` reads, a proxy-side default read preference (only what the client sends per command is honoured), SRV (`mongodb+srv://`) upstream URIs, and load-balanced mode are not supported. `exhaust` (moreToCome) cursors are not enabled upstream; clients fall back to ordinary getMore. If the primary changes mid-cursor on a *primary* read, the cursor is lost with the old primary, as on a real server.
* Session ids (`lsid`) are unguessable UUIDs but are not bound to a tenant.

## Tests

```bash
go test ./internal/...            # rewriter unit tests
go test ./test/ -count=1          # integration: real mongod replica set + official Go driver
go test ./test/ -bench FindOne -run xxx
go test ./internal/proxy -bench RelayLargeBatch -benchmem -run xxx   # streaming vs buffered relay
```
Integration tests start their own `mongod` (must be on `PATH`), including a 3-node replica set for topology discovery, tag/`maxStaleness` secondary reads, cursor affinity, transactions under pool contention, 80 clients multiplexed over a 4-connection pool, repeated `replSetStepDown` failovers with and without driver retries, a leak check at shutdown, and dedicated mode. They cover isolation for CRUD, aggregation stages, cursors, bulk writes, transactions, indexes, and all three auth modes including an auth-enabled upstream.
