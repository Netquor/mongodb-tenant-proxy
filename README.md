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

## Run

```bash
go build -o mongodb-tenant-proxy ./cmd/mongodb-tenant-proxy
./mongodb-tenant-proxy serve -config proxy.json
```

See [`proxy.example.json`](proxy.example.json). Metrics (`/metrics`, Prometheus text) and `/healthz` are served on `metricsAddr`. TLS, authentication and compression options are described above.

## Performance

* Raw BSON rewriting – no struct decoding. A `find` rewrite is ≈0.85 µs / 33 allocs; stamping a 1,000-document insert is ≈125 µs.
* One goroutine and one dedicated upstream connection per client connection (cursors, sessions and transactions keep native semantics). Unmodified replies are forwarded as raw bytes.
* Measured on a laptop over loopback: point `findOne` ≈24 µs through the proxy vs ≈16 µs direct.

## Requirements and limitations

* MongoDB **5.0+** (uses `$lookup` with both `localField` and `pipeline`). Transactions and retryable writes need a replica-set upstream, like with any driver.
* `_id` is unique per *collection*, not per tenant. Use generated ObjectIds/UUIDs; a natural `_id` reused by two tenants will collide (and reveals existence).
* Indexes are shared physical objects: one tenant creating an index affects all; `dropIndexes: "*"` is refused. Deny `createIndexes`/`dropIndexes` via `denyCommands` if tenants must not manage indexes. TTL indexes cannot carry the tenant prefix (unique TTL indexes are refused).
* The `tenantId` field is visible in returned documents.
* `mapReduce` can't write to a collection (use `$merge`); `listCollections` filters other than `name`/`type` don't apply to views.
* Not supported: `GSSAPI`/`PLAIN`/LDAP client authentication, the interactive OIDC (human) flow, speculative authentication in `hello` (drivers fall back to a normal login), and `OP_COMPRESSED` for the legacy `OP_QUERY` handshake.
* Session ids (`lsid`) are unguessable UUIDs but are not bound to a tenant.

## Tests

```bash
go test ./internal/...            # rewriter unit tests
go test ./test/ -count=1          # integration: real mongod replica set + official Go driver
go test ./test/ -bench FindOne -run xxx
```
Integration tests start their own `mongod` (must be on `PATH`) and cover isolation for CRUD, aggregation stages, cursors, bulk writes, transactions, indexes, and every auth mode (SCRAM-SHA-256/SHA-1, x.509 with generated certificates, OIDC/JWT, appname, static) including auth-enabled and TLS/x.509 upstreams, plus wire compression for each algorithm. `go test ./test/ -bench Compression -run xxx` compares compressors.
