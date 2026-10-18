# Threat model

This document lists who may attack the proxy, what each attacker can do, which
controls stop them and which tests prove it. A control with no test is not
listed as a control.

The proxy's job is to confine every client connection to one tenant's data and
to survive hostile clients. It is **not** a replacement for network
segmentation: the client listener should not be reachable from the internet,
and the admin and metrics listeners should be bound to loopback or an internal
network.

Tests named below live in `test/attack_*_test.go` (integration; need `mongod`
in `PATH`, or `MTP_MONGOD_URI`) and in `internal/*/attack_test.go` (unit).

## Trust boundaries

```
 clients ──(TCP/TLS, wire protocol)──▶ proxy ──(TCP/TLS, upstream creds)──▶ MongoDB
 operators ──(HTTP/HTTPS, bearer or mTLS)──▶ admin API ─┐
 scrapers ──(HTTP)──▶ metrics                            └─ same process
 config file, tenants store, JWKS endpoint, audit sink: read/written by the proxy
```

The proxy holds the upstream credentials and talks to MongoDB as a privileged
user. Tenants never see them.

## Attacker 1: the malicious tenant

Holds valid credentials for one tenant. Wants another tenant's data, more than
their share of capacity, or the upstream credentials.

| Goal | Controls | Tests |
|---|---|---|
| Read/write another tenant's documents | Every command is rewritten to carry the tenant filter/stamp; cursors, sessions and change streams are owned per connection (see the isolation suites) | `test/isolation_test.go`, `internal/rewrite/*_test.go`, sibling `isolation` work |
| Switch tenant on a live connection | `authenticated()` refuses a second, different tenant; the user record is only attached after the bind succeeds | `TestAttackSCRAMProtocolAbuse/auth_after_auth` |
| Use JavaScript to burn CPU or escape the filter | `disableJS` refuses every JS entry point (`$where`, `$function`, `$accumulator`, `mapReduce`, in any position) | `TestAttackExpensiveOperators` |
| Starve other tenants | Per-tenant ops/bytes rate, in-flight cap, cursor cap, index cap, connection cap; pooled upstream connections are borrowed per command | `TestAttackNoisyNeighbour`, `TestAttackCursorFlood`, `TestAttackSessionsViewsIndexes`, `TestAttackConnectionCaps` |
| Open unbounded cursors | 10 000 cursors per connection (refused before the cursor exists, so none are leaked upstream) plus the per-tenant `maxOpenCursors` quota; all are killed when the connection ends | `TestAttackCursorFlood` |
| Open unbounded change streams | Streams count against `maxOpenCursors` | `TestAttackChangeStreamSubscribers` |
| Pin memory with a stalled change-stream subscriber | Subscriber queue is capped by count **and** bytes (64 MiB); an overflowed subscriber is resumed privately by the driver | `internal/fanout/attack_test.go` |
| Pathological commands (deep nesting, 50k stages, 800k-element `$in`, 300k-key filters) | BSON depth ≤ 100, message size cap, `maxTimeMS` default/cap per tenant; the rewrite is linear (measured in `TestAttackHugeCommands`) | `TestAttackHugeCommands`, `internal/rewrite/adversarial_test.go` |
| ReDoS / slow operators | `defaultMaxTimeMS` and `maxTimeMSCap` apply to every command. mongod enforces them for regexes, `$lookup` and `$where` | `TestAttackExpensiveOperators` |
| Never read replies to hold an upstream connection | Every write to a client has a deadline (`connLimits.writeTimeout`) | `TestAttackNeverReadsReply` |
| Reload storms | `ReloadConfig` is serialised and atomic; 1 280 concurrent reloads under load lose no client operation | `TestAttackReloadStorm` |
| Learn upstream credentials | Never in replies, logs, audit or metrics | `TestAttackSecretsNeverLeak` |

**Residual risk.** mongod does not interrupt a `$function`/`$accumulator`
busy loop on `maxTimeMS` (verified on 7.0). A tenant that is allowed JavaScript
can therefore burn one upstream CPU core per request until killed. Set
`disableJS: true` for every tenant that is not fully trusted, or kill runaway
operations from outside. The default quotas are all off; production deployments
should set `tenant.limits` (ops rate, in-flight, cursors, indexes, maxTimeMS).

## Attacker 2: the network attacker

Can open TCP connections to the client listener, with no credentials. May also
sit on the path between client and proxy.

### Framing and parsing

| Attack | Control | Tests |
|---|---|---|
| Negative, zero, below-header or enormous lengths; length/body mismatch | `ReadFrame` validates; the body buffer **grows as bytes arrive** rather than being allocated from the declared length | `TestAttackMalformedFrames`, `wire.TestReadFrameDoesNotTrustTheDeclaredLength` |
| Unknown opcodes, legacy `OP_INSERT/GET_MORE/KILL_CURSORS` | Connection closed | `TestAttackMalformedFrames` |
| OP_MSG: bad section kinds, two bodies, no body, bad sizes, unterminated documents | Strict `ParseMsg`; connection closed | `TestAttackMalformedFrames` |
| OP_MSG unknown *required* flag bits | Rejected per the spec | `wire.TestParseMsgFlags` |
| OP_MSG bad checksum | CRC-32C verified when `checksumPresent` is set | `TestAttackOpMsgChecksum`, `wire.TestVerifyChecksum` |
| 48 MB of 5-byte documents (slice-header amplification) | ≤ 100 000 documents and ≤ 16 sections per message | `wire.TestParseMsgLimits` |
| OP_QUERY used for anything but the handshake | Everything except `hello`/`isMaster` is refused, never forwarded | `TestAttackOpQueryAbuse` |
| Decompression bombs, lying `uncompressedSize`, nested or unknown compressors | Declared size is capped *before* any allocation; output buffers grow with real output; the stream must end exactly at the declared size; snappy's expansion ratio is checked; zstd window is capped; compressors that were not negotiated are refused | `TestAttackCompressionBombs`, `TestAttackCompressionNotNegotiated`, `wire.TestDecompressBombs` |
| `moreToCome` misuse, pipelining, duplicate request ids | Stream stays in sync; replies carry the right `responseTo` | `TestAttackMoreToComeAndPipelining` |
| Reset in the middle of a large reply | Handler unwinds; upstream connection is discarded; pool unaffected | `TestAttackResetMidReply` |
| Any of the above panicking a handler | `safely()` converts panics to a closed connection; the tests fail if one is ever *logged* | `atkEnv.noPanics` in every attack test |

### Connection exhaustion and slow clients

| Attack | Control (config under `connLimits`) | Tests |
|---|---|---|
| Idle / half-open / header-only connections | `handshakeTimeout` (30 s) is an absolute deadline until a tenant is bound; an unauthenticated peer cannot extend it with pings | `TestAttackSlowloris` |
| Trickling a body | `frameTimeout` (2 m) from the first byte of a message to its end, authenticated or not | `TestAttackSlowloris` |
| Idle authenticated connections | `idleTimeout` (opt-in, as before) | `TestAttackSlowloris` |
| Large pre-auth messages | `preAuthMaxBytes` (256 KiB): nothing before authentication needs more | `TestAttackFloodMemory` |
| Connection floods | `maxPreAuthConns` (4 096), `maxPreAuthPerIP` (256), opt-in `maxConns`, `maxConnsPerIP`, plus `maxConnsPerTenant` | `TestAttackConnectionCaps`, `TestAttackFloodMemory` |
| fd exhaustion killing the accept loop | Accept errors back off and retry; only a closed listener ends `Serve` | `TestAttackAcceptErrorsDoNotStopServing` |
| TLS handshake stalls | Same handshake deadline (the TLS handshake happens on the first read) | `TestAttackTLSPolicy` |

### Authentication

| Attack | Control | Tests |
|---|---|---|
| Password guessing | Lockout per client address after `auth.bruteForce.maxFailures` (10 / minute), doubling lock time up to 15 min; optional per-user limit; a success does not reset the counter. Refused attempts get the ordinary failure and the connection is closed | `TestAttackSCRAMBruteForceLockout`, `TestAttackSCRAMGuessesOnOneConnection`, `auth.TestThrottle` |
| User enumeration | Unknown users receive a stable decoy challenge (same shape, same iteration count) and fail at the proof exactly like a wrong password | `auth.TestSCRAMUserEnumeration` |
| SCRAM downgrade | Only enabled mechanisms; a user without a SHA-1 credential cannot be authenticated over SHA-1 | `auth.TestSCRAMDowngrade` |
| Replay of a recorded conversation | Server nonce is fresh each time | `auth.TestSCRAMReplay` |
| `conversationId` confusion, `saslContinue` without start, hostile payloads | Id must be 1; conversation is dropped on mismatch | `TestAttackSCRAMProtocolAbuse`, `auth.TestSCRAMMalformedPayloads` |
| appName forgery (truncated/long/case-changed MAC, other tenant's MAC, dotted tenants) | Full-length HMAC-SHA-256 prefix, `hmac.Equal`, last-dot split | `auth.TestAppNameForgery` |
| x509 subject spoofing (comma injection, case, extra RDNs, SAN substrings/wildcards), unverified chains, rules matching two tenants | Names compared exactly (attribute types case-folded only); chain must be verified by the listener; ambiguous matches fail | `auth.TestX509IdentitySpoofing`, `TestClientX509` |
| JWT: `alg: none`, HS256 keyed with the public key, wrong key/alg pairing, `kid`/`jwk`/`jku` header tricks, wrong `iss`/`aud`, missing/expired `exp`, future `nbf`/`iat`, tenant claim of the wrong type | Algorithm allow-list of RS/ES only; key type must match algorithm; claims strictly typed; 16 KiB token cap | `auth.TestJWTForgeries`, `TestJWTKidInjection`, `TestJWTClaimAttacks`, `TestECDSAAlgorithmConfusion` |
| JWKS SSRF via redirect, huge or slow responses, refresh stampede | Redirects not followed; 1 MiB cap; 10 s timeout; one refresh per 30 s however many tokens arrive; `jwksUri` must be http(s) | `auth.TestJWKSFetchHardening` |
| TLS downgrade | TLS ≥ 1.2, Go's default (AEAD-only) cipher suites; client certificates verified against the configured CA | `TestAttackTLSPolicy` |

**Residual risks.**
* `auth.mode: appname` without `appNameSecret`, and `static`, trust the network
  entirely. The proxy logs a warning at startup. Use them only on isolated
  networks.
* A bearer JWT can be replayed until it expires. Keep access-token lifetimes
  short; there is no `jti` cache.
* `saslSupportedMechs` reveals which mechanisms a *known* SCRAM user has
  credentials for (as mongod does). With only one mechanism enabled this is not
  an oracle.
* The lockout is keyed on the TCP peer address. Behind a NAT or load balancer
  that does not preserve addresses, one client's failures lock everyone behind
  it out; set `auth.bruteForce.maxFailures` accordingly or put the proxy where
  it sees real client addresses.
* Traffic is only confidential/authentic when `clientTLS` is configured.

## Attacker 3: a compromised admin token

Holds the admin bearer token (or a client certificate accepted by the admin
listener), or can reach the admin port and tries to get in.

| Attack | Control | Tests |
|---|---|---|
| Authentication bypass (path tricks, case, encoded slashes, `/healthz` prefixes, header spoofing, wrong schemes, truncated/extended tokens) | Authentication precedes routing; only the exact path `/healthz` is open | `admin.TestAdminAuthBypass`, `TestAdminTokenComparison` |
| Token guessing | Token compared as SHA-256 digests in constant time; ≥ 16 characters required; failures locked out per address (429 + `Retry-After`) | `admin.TestAdminBruteForceLockout` |
| Request flooding / reload storms | Token-bucket limit on authenticated requests (`admin.ratePerSec`, default 50/s) | `admin.TestAdminRateLimit` |
| CSRF from a browser holding a client certificate | Requests carrying `Origin` or `Sec-Fetch-Site: cross-site` are refused | `admin.TestAdminCSRF` |
| Request smuggling, oversized or slow headers/bodies | `net/http` framing; 64 KiB header cap, 1 MiB body cap, read/write/idle timeouts | `admin.TestAdminRequestSmuggling`, `TestAdminSlowClients`, `TestAdminInputAbuse` |
| Hostile identifiers (path traversal, NUL, huge, `$`) | Validated by the registry; errors are 4xx | `admin.TestAdminInputAbuse` |
| Covering tracks | Every mutating call, every unauthenticated attempt and every reload is audited with actor, remote address and correlation id; identifier fields are length-capped | `admin.TestAdminSecretsStayOutOfAudit`, `TestAdminBruteForceLockout` |
| Harvesting secrets from the audit trail or error text | Tokens and passwords are never logged; generated passwords are returned once; unexpected errors are reported as `internal error` | `admin.TestAdminSecretsStayOutOfAudit`, `TestAdminInternalErrorsAreNotEchoed` |

**What a stolen token can still do** (by design): create/delete tenants and
users, reset passwords, disable tenants, kill connections and trigger reloads.
It cannot read tenant data through the admin API, and cannot change the
config file. Rotate it by changing `admin.token`/`tokenFile` and reloading;
prefer mTLS (`admin.tls.clientCAFile`) and bind the admin listener to an
internal address.

## Secrets handling

* Secrets (client passwords, `appNameSecret`, admin token, upstream password,
  JWTs) are never written to the proxy log, the audit trail, metrics or error
  replies: `TestAttackSecretsNeverLeak`.
* Audit `reason` fields have quoted literals scrubbed and are length-limited;
  identifier fields are capped at 256 bytes.
* `hash-password` stores only salted SCRAM keys; plaintext passwords are never
  kept.

## Out of scope

* A compromised proxy host or upstream (the proxy holds privileged upstream
  credentials).
* A malicious MongoDB deployment.
* Volumetric network DoS below the TCP layer.

## Running the suites

```
go test ./... -race                      # everything (needs mongod for ./test)
go test ./test -run TestAttack           # attack-oriented integration tests
go test ./internal/auth ./internal/admin ./internal/wire ./internal/fanout
```
