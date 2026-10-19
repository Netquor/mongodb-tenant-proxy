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

## Authentication (`auth.mode`)

`auth.mode` is a string or a **list** of mechanisms; `scram`, `scram-sha-1`, `x509` and `oidc` can be combined (`"mode": ["scram", "scram-sha-1", "x509", "oidc"]`) and are all advertised to drivers through `saslSupportedMechs` in `hello` (SCRAM mechanisms are filtered to the ones the named user has a credential for; unknown users get the full list so existence isn't revealed). `appname` and `static` stand alone.

| mode | client connects with | tenant comes from |
|---|---|---|
| `scram` | `authMechanism=SCRAM-SHA-256` (the default negotiation) | the user's `tenantId` |
| `scram-sha-1` | `authMechanism=SCRAM-SHA-1` (legacy MD5-digested password) | the user's `tenantId` |
| `x509` | `authMechanism=MONGODB-X509`, client certificate | `auth.x509` rule matching the certificate |
| `oidc` | `authMechanism=MONGODB-OIDC` with a machine (JWT) callback | a claim of the validated JWT |
| `appname` | nothing; tenant = the driver's `appName` (`<tenant>` or `<tenant>.<hmac>` with `appNameSecret`, see `sign-appname`) | `appName` |
| `static` | nothing; every connection belongs to `staticTenant` (one proxy per tenant) | config |

**SCRAM.** Generate user entries with `MTP_PASSWORD=… mongodb-tenant-proxy hash-password -user acme -tenant acme [-mechanism sha256|sha1|both]`. `sha256` (default) writes the flat `salt/iterations/storedKey/serverKey` fields; `sha1` writes a nested `"sha1": {…}` credential (derived from `md5("<user>:mongo:<password>")`, as MongoDB does); `both` writes both so a user can use either. A user without a SCRAM-SHA-1 credential cannot log in with SCRAM-SHA-1 and vice versa. SCRAM-SHA-1 is weaker; enable it only for old drivers.

**x.509.** Needs `clientTLS.clientCAFile` (mutual TLS): the listener verifies client certificates against that CA. If `x509` is the only mode a certificate is mandatory; combined with other modes it is optional, so password users keep working without one. Map certificates to tenants by subject (RFC 2253, compared case-insensitively) or by any SAN (DNS, e-mail, URI, IP):

```json
"clientTLS": { "certFile": "server.pem", "keyFile": "server.key", "clientCAFile": "client-ca.pem" },
"auth": { "mode": "x509", "x509": [
  { "subject": "CN=billing,O=acme", "tenantId": "acme" },
  { "san": "reports.svc.example.com", "tenantId": "globex" } ] }
```
A trusted certificate with no matching rule is rejected. Connect with `?tls=true&tlsCAFile=…&tlsCertificateKeyFile=client.pem&authMechanism=MONGODB-X509&authSource=$external`.

**OIDC / JWT.** `MONGODB-OIDC` machine flow: the client's callback returns a JWT and the proxy validates signature (RS256/384/512, ES256/384/512 against the JWKS, matched by `kid`; `none` and HMAC algorithms are refused), `iss`, `aud`, `exp`/`nbf` (with `clockSkew`), then takes the tenant from `tenantClaim` (a claim name, or a dotted path; default `tenant`). The human (browser) flow is not supported.

```json
"auth": { "mode": "oidc", "oidc": {
  "issuer": "https://idp.example.com/", "audience": "mongo-proxy",
  "jwksUri": "https://idp.example.com/.well-known/jwks.json",
  "tenantClaim": "tenant", "clockSkew": "30s" } }
```
Use `jwksFile` for a static key set instead of `jwksUri`. A JWKS URI is cached (`jwksRefresh`, default 10m) and re-fetched at most every 30 s when an unknown `kid` appears, so key rotation works without restarts.

### Upstream authentication

`upstream.authMechanism` (or `?authMechanism=` in `upstream.uri`) selects how the proxy logs in to MongoDB:

* `SCRAM-SHA-256` (default when a username is set) and `SCRAM-SHA-1`.
* `MONGODB-X509` – the proxy's client certificate (`upstream.certFile`/`keyFile`, requires `upstream.tls`); `upstream.username` is optional (the subject is derived from the certificate). The matching `$external` user must exist in MongoDB.
* `MONGODB-AWS` – SigV4-signed STS `GetCallerIdentity` handed to the server. Credentials come from `upstream.awsAccessKeyId`/`awsSecretAccessKey`/`awsSessionToken`, else `username`/`password`, else `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`, else the ECS container endpoint (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`). EC2 instance-profile (IMDS) and web-identity/IRSA credentials are not implemented – export them as environment variables or run a refresher sidecar. The signature is verified against the official driver's, but the exchange has not been run against a real AWS-enabled mongod.

The proxy presents itself to drivers as a `mongos`, so drivers never discover and bypass it via replica-set member addresses.

## TLS

* **Client side:** `clientTLS.certFile`/`keyFile` enables TLS on the listener (TLS 1.2+). Add `clientTLS.clientCAFile` to verify client certificates (required by `x509`, see above).
* **Upstream:** `upstream.tls`, `upstream.caFile`, `upstream.insecureSkipVerify`, and `upstream.certFile`/`keyFile` for a client certificate (mutual TLS to mongod, needed for `MONGODB-X509`).

## Wire compression

`compressors` (top level) lists what the proxy advertises to clients in `hello`: any of `snappy`, `zlib`, `zstd`, in preference order (default none, so behaviour is unchanged). Drivers pick from the intersection (`compressors=zstd,snappy` / `SetCompressors`). Requests arrive as `OP_COMPRESSED` and are decompressed; replies are compressed with the compressor of the request they answer, as `mongod` does. `hello`, `saslStart`, `saslContinue`, `authenticate`, `createUser`, `updateUser` and the other handshake/auth commands are never compressed. A request using a compressor that was not advertised closes the connection, and declared uncompressed sizes are checked against `maxMessageBytes` before allocating.

`upstream.compressors` negotiates compression to MongoDB independently of the client side: the proxy compresses the commands it forwards (never the handshake/auth ones) and mongod compresses the replies. When the upstream reply uses the same compressor the client expects and the proxy has nothing to rewrite in it, the compressed bytes are relayed untouched. Without compression on either side the forward path is the same raw-byte relay as before. Pure Go (`klauspost/compress` for snappy/zstd, stdlib zlib).

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

See [`proxy.example.json`](proxy.example.json). Metrics (`/metrics`, Prometheus text) and `/healthz` are served on `metricsAddr`. TLS, authentication and compression options are described above.

## Operations

### Hot reload
`kill -HUP <pid>` (or `systemctl reload`, or `POST /v1/reload` on the admin API) re-reads the config file. The file is fully validated first; on any error the running config is kept and the error is logged / returned (HTTP 422). Open connections are **not** dropped.

Applied live: `auth.users`, `auth.appNameSecret`, `tenants`, `databases`, `denyCommands`, `disableJS`, `disableViews`, `maxConnsPerTenant`, `idleTimeout`, `connLimits`, `maxMessageBytes`, `logLevel`, `audit.sampleReads`. Everything else (listen address, upstream, `tenant`, `auth.mode`, `clientTLS`, `changeStreams`, `store`, `audit` sink, `metricsAddr`, `adminAddr`) needs a restart – a reload that changes them applies the rest and lists them in `restartRequired`.

After every reload, and after every tenant/user change, live connections re-check their tenant: a connection whose tenant is disabled, or whose user was removed, is closed immediately (and re-checked before each subsequent command).

### Tenants and the admin API
Tenants are implicit (a user binds to a tenant id). You can also declare them in config (`tenants: [{id, disabled, maxConns}]`, read-only via the API) or create them at runtime through the admin API. Set `adminAddr` (e.g. `127.0.0.1:9103`) and authenticate with a bearer token (`admin.token`, `admin.tokenFile` or `$MTP_ADMIN_TOKEN`, ≥16 chars) and/or mTLS (`admin.tls.{certFile,keyFile,clientCAFile}`; a client certificate signed by the CA is sufficient). `/healthz` is the only unauthenticated path. Always bind the admin listener to a private interface.

| Method & path | |
|---|---|
| `GET /v1/tenants`, `POST /v1/tenants` `{id, maxConns?, disabled?}` | list / create |
| `GET/PATCH/DELETE /v1/tenants/{id}` | read / change `maxConns`,`disabled` / delete (kills its connections) |
| `POST /v1/tenants/{id}/enable`, `.../disable` | disabling disconnects live clients |
| `GET/POST /v1/tenants/{id}/users` | list / create `{username, password?}` – omit `password` to have one generated (returned once) |
| `PUT/DELETE /v1/tenants/{id}/users/{name}` | reset password / delete (kills that user's connections) |
| `GET /v1/connections`, `GET /v1/tenants/{id}/connections` | live connections (id, user, remote, bytes, commands, cursors, streams) |
| `DELETE /v1/connections/{id}`, `DELETE /v1/tenants/{id}/connections` | kill one / all |
| `GET /v1/tenants/{id}/stats` | counters per command/outcome, errors, denials, bytes, avg latency, gauges |
| `POST /v1/reload` | hot reload |

```bash
curl -H "Authorization: Bearer $TOKEN" -d '{"id":"acme"}' :9103/v1/tenants
curl -H "Authorization: Bearer $TOKEN" -d '{"username":"acme-app"}' :9103/v1/tenants/acme/users   # {"password":"…"}
```
Users are stored as SCRAM-SHA-256 credentials only (plaintext is never persisted or logged). Users/tenants from the config file are read-only through the API (409).

**Persistence** – `store.type`: `file` (default when `store.path` is set; atomic JSON file, mode 0600) or `mongo` (collections `<collection>_tenants` / `_users` in `store.database`, default `mtp_control`; `store.uri` defaults to the upstream). Use `mongo` when running several replicas; each replica re-reads the store every `store.refreshInterval` (default `30s`) so changes propagate. Authentication consults the registry on every login.

### Metrics
`/metrics` keeps the original series (`mtp_connections_*`, `mtp_client_bytes_total`, `mtp_commands_total`) and adds, labelled with `tenant`: `mtp_tenant_commands_total{command,outcome}`, `mtp_tenant_errors_total`, `mtp_tenant_denials_total`, `mtp_tenant_client_bytes_total{direction}`, `mtp_tenant_command_duration_seconds` (histogram), `mtp_tenant_connections_active`, `mtp_tenant_connections_total`, `mtp_tenant_open_cursors`, `mtp_tenant_changestream_subscribers`. Cardinality is bounded by `metrics.tenantLabel`: `mode` = `top` (default; first `topN`=50 tenants, declared ones first, get their own label, the rest are `other`), `hash` (`hashBuckets`=32 labels `b00…`), `all` (unbounded) or `off`. Per-tenant counters are tracked for at most 10 000 tenants; `GET /v1/tenants/{id}/stats` always shows the exact tenant. Span hooks: `internal/trace` calls a `Tracer` around every command when `tracing.enabled` is true; wire an OpenTelemetry tracer in with `trace.Set` (kept out of `go.mod` by default).

### Audit log
`audit.enabled` writes append-only JSON lines (one event per line) to `audit.sink`: `stdout`, `stderr`, `file` (`path`, rotated at `maxSizeMB`=100 keeping `maxBackups`=5, mode 0600), `syslog` (`syslog`: empty for local, or `udp://host:514`) or `http` (`url`, `header`; NDJSON batches, retried, never blocks the proxy). Events: `connect`, `disconnect`, `connection.killed`, `auth.success`/`auth.failure`, `command.denied` (with reason), `command.error`, `command.ddl`, `command.write`, `command.read` (sampled by `audit.sampleReads`, 0–1), `admin.action` (actor, action, target; never passwords) and `config.reload`. Each carries `session` (per connection) and `corr` (`<session>-<n>` per command, or the request id returned in `X-Correlation-Id` for admin calls), tenant, user, remote, db, command, latency. **Document contents, filter values and passwords are never logged**; denial reasons are length-limited and quoted literals are scrubbed.

### Packaging
* `make build` / `make docker` stamp `main.version/commit/date` via `-ldflags`; `mongodb-tenant-proxy version` prints them.
* **Docker** – distroless, runs as uid 65532, `HEALTHCHECK` runs `mongodb-tenant-proxy healthcheck -config …` against `/healthz` (no shell/curl needed). State dir `/var/lib/mongodb-tenant-proxy`.
* **docker-compose** – [`deploy/compose`](deploy/compose): mongod replica set + proxy with the admin API.
* **systemd** – [`deploy/systemd`](deploy/systemd): hardened unit, `ExecReload` sends SIGHUP.
* **Helm** – [`deploy/helm/mongodb-tenant-proxy`](deploy/helm/mongodb-tenant-proxy): Deployment, Service, ConfigMap/Secret (upstream password, admin token and appName secret are injected as `MTP_*` env vars), PodDisruptionBudget, HPA, ServiceMonitor and NetworkPolicy (each toggled in `values.yaml`). Use `store.type: mongo` when `replicaCount > 1`.

## Performance

* Raw BSON rewriting – no struct decoding. A `find` rewrite is ≈0.85 µs / 33 allocs; stamping a 1,000-document insert is ≈125 µs.
* One goroutine per client connection; upstream connections are pooled and shared (see above), and unmodified large replies are streamed in chunks with constant memory. Cursors, sessions and transactions keep native semantics.
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
* Indexes are shared physical objects: one tenant creating an index affects all; `dropIndexes: "*"` is refused. Deny `createIndexes`/`dropIndexes` via `denyCommands` if tenants must not manage indexes. TTL indexes cannot carry the tenant prefix, so they are made tenant-private instead: the proxy adds the tenant to the index's `partialFilterExpression` (expiry only ever deletes the creator's documents) and appends a `__mtp_t<tag>` suffix to the index name (shown by `listIndexes`, used by `dropIndexes`); unique TTL indexes are refused. Other tenants' private indexes are hidden from `listIndexes`.
* `create` accepts no collection options (`capped`, `validator`, `collation`, `clusteredIndex`, ...) because the physical collection is shared. Collations weaker than strength 3 (or `alternate: shifted`, `numericOrdering`) are rejected on every command, since they could make one tenant id compare equal to another. A default collation set out of band on a shared collection has the same effect and must be avoided.
* Requests are validated before rewriting: malformed BSON, nesting deeper than 100 levels and pipelines longer than 1000 stages are rejected, and server-side JavaScript (`$where`, `$function`, `$accumulator`) is refused anywhere in a command when `disableJS` is set.
* The `tenantId` field is visible in returned documents.
* `listCollections` filters other than `name`/`type` don't apply to views.
* Not supported: `GSSAPI`/`PLAIN`/LDAP client authentication, the interactive OIDC (human) flow, speculative authentication in `hello` (drivers fall back to a normal login), and `OP_COMPRESSED` for the legacy `OP_QUERY` handshake.
* Session ids are bound to the first tenant that uses them ([Sessions](#sessions)); quotas are per proxy process, not shared between proxy replicas ([Quotas](#quotas-tenantlimits)).
* Upstream routing: `hedge` reads, a proxy-side default read preference (only what the client sends per command is honoured), SRV (`mongodb+srv://`) upstream URIs, and load-balanced mode are not supported. `exhaust` (moreToCome) cursors are not enabled upstream; clients fall back to ordinary getMore. If the primary changes mid-cursor on a *primary* read, the cursor is lost with the old primary, as on a real server.

## Tests

```bash
go test ./internal/...            # unit tests (rewriter, audit, metrics, tenants, admin, config)
go test ./test/ -count=1          # integration: real mongod replica set + official Go driver
go test ./test/ -bench FindOne -run xxx
go test ./internal/proxy -bench RelayLargeBatch -benchmem -run xxx   # streaming vs buffered relay
```
See [docs/security-testing.md](docs/security-testing.md) for the adversarial isolation suite (attack catalogue, differential testing, known limitations).

Integration tests start their own `mongod` (must be on `PATH`) and cover isolation for CRUD, aggregation stages, cursors, bulk writes, transactions, indexes, and every auth mode (SCRAM-SHA-256/SHA-1, x.509 with generated certificates, OIDC/JWT, appname, static) including auth-enabled and TLS/x.509 upstreams, plus wire compression for each algorithm. `go test ./test/ -bench Compression -run xxx` compares compressors. The replica-set suite adds a 3-node set for topology discovery, tag/`maxStaleness` secondary reads, cursor affinity, transactions under pool contention, 80 clients multiplexed over a 4-connection pool, repeated `replSetStepDown` failovers with and without driver retries, a shutdown leak check, and dedicated mode.
