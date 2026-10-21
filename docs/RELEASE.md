# v0.1.0 release readiness — 21 October 2026

## Decision

The new standalone source and API are ready for public review and integration testing. Production hosting is conditional on the deployment gates below. This is not a certified identity provider. Use a fresh database and adapt clients to the documented bearer-only API.

## Completed local evidence

- Clean independent Go module; no private monorepo imports in the release. A fresh extraction of the source archive independently passes unit tests, vet and build, and every manifest hash matches.
- Go 1.27.3 build, unit tests, go vet and API route/contract consistency checks.
- Real PostgreSQL 18 tests against an isolated cluster with a restricted runtime role. They exercise actual router calls, single-use grants, pending MFA lifecycle, TOTP/recovery replay, current account/tenant checks, admin reset, invitations, immediate revocation and privilege denials.
- Concurrent reset-versus-refresh and two-consumer refresh tests. Persisted audit-write failure rolls back session issuance; limiter and identity lookup failures deny access without false email success.
- SMTP STARTTLS delivery to a synthetic TLS server; rejection of missing STARTTLS and an untrusted certificate; durable encrypted queue retry on failure. This does not establish delivery through your provider.
- Actual compiled binary migration, restricted-role startup, readiness and browser security-header smoke. Linux SIGTERM exits cleanly with status zero.
- Linux/amd64 Go 1.27.3 real-PostgreSQL acceptance suite with the race detector: passed, including concurrent reset/refresh and refresh reuse. An initial run under competing build/scanner load hit request deadlines; the isolated rerun passed without race reports.
- Actual Docker Compose stack with a restricted, non-root/read-only application and a non-root/read-only Caddy proxy. Verified local-CA HTTPS, HSTS, cross-origin rejection, no cookies/no-store, account verification, reset, revocation, refresh and logout pass through the real proxy. The actual mail worker delivers verification and reset messages over verified STARTTLS with SMTP authentication to a synthetic server. Invalid SMTP credentials, missing STARTTLS and an untrusted certificate are rejected.
- All three deployed images pass an unfiltered Trivy 0.76.1 high/critical gate. The database has zero reported findings. Application/proxy raw reports retain only the reviewed UNKNOWN-severity module-only OpenPGP advisory; neither imports OpenPGP. Original vulnerable supporting images were replaced with a security-updated Alpine PostgreSQL image and Caddy built with patched Go/networking dependencies. Base digests and proxy module versions are pinned.
- Transactional encryption-key rotation, pg_dump/pg_restore into a separate private database and decryption of restored MFA records using the new key.
- A small local workload of 120 identity reads at concurrency eight with zero errors and p95 below the two-second development acceptance threshold. This is not a production throughput or availability claim.
- Live govulncheck review: zero reachable findings, zero imported-package findings. One non-imported OpenPGP advisory in the x/crypto module is documented in DEPENDENCY-REVIEW.md.
- Dedicated Gitleaks v8.24.2 scan of the clean public archive: zero findings. Initial manifest-hash false positives were resolved by an unambiguous manifest structure, without source-scanner exclusions.
- Public-source allowlist packaging, SHA-256 manifest and included third-party license notices. Private test databases, caches, real environment files and attachments are excluded.

Detailed test logs/environment records are retained locally under .local/acceptance-*/ and .local/production-20261021/. They contain only synthetic test accounts and are deliberately excluded from distribution. dist/SHA256SUMS identifies the exact packaged source. The workspace initially had no Git metadata; the supplied GitHub target had no refs before initial publication. Only the reviewed standalone source is included. Published source is identified by its Git commit/tag; the corresponding GitHub Actions artifacts hold the published build's image identities and scan reports. Earlier local image IDs in RELEASE-EVIDENCE.json are historical baseline evidence from before the Go module was aligned to the GitHub repository.

## Developer self-hosting integration

The self-hosting/configuration/upgrade guides and runnable examples/product-app use the operator's own instance, with no hosted NVUTO account. The configuration helper passes tests for independent secrets and no-overwrite behavior. The product backend passes TLS trust-boundary tests and a live acceptance smoke against the compiled auth binary and fresh PostgreSQL: login, workspace/owner-scoped projects, TOTP enrollment, MFA/recovery, refresh invalidation and logout revocation. Backup/restore also validates the example's generated factor. This is an example adapter, not a production product database or an OAuth/OIDC client.

## Deployment gates not yet established

- Real SMTP account configuration, verified sender/inbox delivery and a public-domain certificate/lifecycle on the intended production server. Local proxy/SMTP tests use synthetic identities and local test certificates.
- Workload/instance-count capacity, failure recovery and availability targets for the intended hosting environment.
- Operator alert destinations, production backup/key custody, incident responsibilities and applicable retention/privacy requirements.
- Establish ongoing operator monitoring of private vulnerability reports and incident ownership. Private reporting is enabled and verified on https://github.com/billyronks/NVUTO-Auth; no acknowledgement SLA is promised.
- Review any existing remote Git history and rotate any real credentials exposed there. This new source archive does not establish the state of a previous repository or running NVUTO service.

Do not advertise those unverified gates as passed. The supplied Docker/Compose and CI definitions make the checks concrete and repeatable; the full stack has been exercised locally, and no public production deployment has been performed. Repository publication is tracked at https://github.com/billyronks/NVUTO-Auth and its release/Actions pages.
