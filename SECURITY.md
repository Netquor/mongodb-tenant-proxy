# Security

## What this proxy is

`mongodb-tenant-proxy` sits between MongoDB drivers and a MongoDB deployment and
confines each client connection to one tenant's documents by rewriting the
commands it forwards. Treat it as a **tenant gate**, not as a replacement for
database authorization.

## Threat model

### Guarantees (what the proxy is designed to enforce)

- **Document isolation.** After authentication a connection is bound to exactly
  one tenant. Every supported read, write, aggregation, change stream, cursor
  (`getMore`/`killCursors`), transaction, index and collection command is
  rewritten so it can only see and modify that tenant's documents. Commands
  whose isolation cannot be guaranteed are refused rather than passed through.
- **Fail closed.** Unknown commands, malformed BSON, JavaScript operators
  (unless explicitly enabled), weak collations, deeply nested documents and
  oversized messages are rejected.
- **Tenant binding comes from authentication only**, never from anything the
  client puts in a command (SCRAM user, x509 subject/SAN or OIDC claim).
- **Credential handling.** Proxy users are stored as SCRAM verifiers, never as
  plaintext. Audit events are scrubbed of credentials. Admin tokens are
  compared in constant time and must be at least 16 characters.
- **Resource bounds.** Message size, decompressed size, JWKS size, admin request
  size (1 MiB), connection counts and per-tenant quotas are capped.

### Non-goals (what it does NOT protect against)

- **A compromised proxy host or upstream credential.** The proxy holds a
  privileged upstream credential; anyone who owns the process or its
  configuration owns every tenant's data.
- **Side channels between tenants** on shared infrastructure: timing, resource
  contention beyond the configured quotas, `serverStatus`-style aggregate
  metrics, or storage-engine-level effects.
- **Direct access to MongoDB.** If clients can reach the upstream directly, the
  proxy is bypassed. Keep the upstream on a private network and require TLS.
- **Confidentiality on the wire without TLS.** Enable `clientTLS` and
  `upstream.tls`; plaintext is only for loopback or tightly controlled networks.
  `upstream.insecureSkipVerify` disables certificate validation and is for
  testing only.
- **Denial of service by an authenticated tenant** beyond the configured limits.
- **Features it intentionally refuses** (see the README's limitations list).
  Refusal is the safe default, not a bug.

### Trust boundaries and cryptography notes

- **SCRAM-SHA-1 uses SHA-1 and MD5 because the MongoDB protocol requires
  them** (`hex(md5("<user>:mongo:<password>"))` feeds the SHA-1 SCRAM exchange).
  This is implemented in `internal/auth` (server side) and `internal/upstream`
  (client side) and flagged `#nosec G401/G501` with that reason. Prefer
  SCRAM-SHA-256 (the default for `hash-password`); keep SHA-1 only for old
  drivers or upstreams.
- **TLS** requires 1.2 or newer. Certificate verification is on unless
  `insecureSkipVerify` is configured explicitly.
- **Randomness** for identifiers, nonces and tokens uses `crypto/rand`;
  `math/rand/v2` is used only to choose between replica set members.
- **OIDC.** Keys come from `jwksFile` or `jwksUri` set by the operator, never
  from a token's `jku`/`x5u` headers. `jwksUri` must be `https` (plain `http` only
  for loopback), carries no credentials, follows at most 3 redirects and never
  downgrades to `http`; the response is capped at 1 MiB; RSA keys under 2048 bits
  and invalid EC points are ignored.
- **Admin API.** Bearer token (constant-time digest comparison) and/or mutual
  TLS; request bodies capped at 1 MiB; server timeouts set. Browsers cannot
  drive it: requests carrying an `Origin` header on state-changing methods are
  rejected, which closes CSRF for mTLS clients whose certificate a browser
  would present automatically. Bind it to a management network.
- **Files.** The tenant store and audit logs are created `0600` (directories
  `0700`/`0750`). Paths come from operator configuration only; no client input
  ever reaches the filesystem.
- **Integer conversions** between wire `int32`/`uint32` and Go `int` go through
  `internal/safeconv`, which centralises the reinterpretation or saturation and
  its justification.

## Automated checks

CI (`.github/workflows`) runs on every push and pull request, and weekly:
`govulncheck` (source and binary), `gosec` (SARIF to code scanning; fails at
medium and above), `staticcheck`, CodeQL (`security-and-quality`), Trivy
(dependencies, Dockerfile/Helm misconfiguration, container image), `gitleaks`
(history), dependency review on pull requests, and the whole test suite under
`-race`. Dependabot covers Go modules, the Dockerfile and GitHub Actions. All
actions are pinned by commit SHA. Run the local subset with `make security`
(`make security-tools` installs the scanners).

Triaged, intentionally unflagged findings:

- `gosec` G104 (low): unchecked `Close`, `SetDeadline` and cleanup commands on
  paths that are already failing or shutting down. They are below the CI gate;
  security-relevant ones (audit rotation, audit sink writes) are handled
  explicitly.
- Every `#nosec` and `//lint:ignore` in the tree carries a written reason; grep
  for them to audit.

Releases (`release.yml`) publish a CycloneDX SBOM, a keyless
[cosign](https://github.com/sigstore/cosign) signature and SBOM attestation for
the image, and signed binaries.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
"Report a vulnerability" (Security → Advisories) on
`Netquor/mongodb-tenant-proxy`. Include the
version, configuration relevant to the issue and a reproduction (a driver script
or raw command is ideal). Cross-tenant data exposure, authentication bypass and
rewriter bypasses are treated as the highest severity.

We aim to acknowledge within 3 working days, give an assessment within 10, and
ship a fix or mitigation for confirmed high-severity issues within 30 days,
crediting reporters who want it. Supported versions: the latest release and
`main`.
