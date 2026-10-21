# NVUTO Auth

[![Validate](https://github.com/billyronks/NVUTO-Auth/actions/workflows/ci.yml/badge.svg)](https://github.com/billyronks/NVUTO-Auth/actions/workflows/ci.yml)

A standalone, self-hosted authentication service for one product/workspace. MIT licensed. Go 1.27.3, PostgreSQL 18, HTTPS and a STARTTLS SMTP provider are required.

Use a fresh dedicated database for your NVUTO Auth installation.

Supported: optional public member registration, verified email, owner invitations with resend/revoke, password recovery, TOTP MFA and recovery codes, session listing/revocation, refresh rotation with reuse detection, current-state authorization, step-up authentication, encrypted mail outbox, and local one-time owner bootstrap.

Unsupported: central OIDC/OAuth identity provider, social SSO, SMS, native SDKs, custom role administration, owner transfers, push notifications, and multi-region deployment. The built-in owner can invite and administer members; members cannot grant privileges. Public registration never creates an owner.

## Self-host it in your infrastructure

Developers run their own instance alongside their product. No sign-in to auth.nvuto.com, activation key or NVUTO-hosted account is required. You control its database, users, email provider and keys. You may keep the service's source inside your product repository under the MIT license; preserve its license and notices.

Download a [source release](https://github.com/billyronks/NVUTO-Auth/releases), or clone the repository below. Start with the **[self-hosting quickstart](docs/SELF-HOSTING.md)**. It covers a fresh Docker installation, local verification, initial owner setup, your own HTTPS hostname and an existing reverse proxy.

    git clone https://github.com/billyronks/NVUTO-Auth.git
    cd NVUTO-Auth
    python3 scripts/init_env.py

This creates a private .env with independent database passwords and an encryption key and refuses to overwrite existing configuration. Fill its SMTP and initial-owner values, then start a fresh local instance:

    docker compose -p nvuto-auth config --quiet
    docker compose -p nvuto-auth up -d --build auth
    docker compose -p nvuto-auth run --rm bootstrap

Verify the owner's email and open http://localhost:8081/account. These commands are for a new local installation; the guide covers remote HTTPS before inviting real users. On Windows, use python if that is your Python command. Docker/Compose and Python are required; Docker builds the Go binary. A fresh database and verified STARTTLS email service are required for this manual walkthrough.

| Developer task | Guide |
| --- | --- |
| Install on your own server | [Self-hosting quickstart](docs/SELF-HOSTING.md) |
| Understand every setting, secrets and private networking | [Configuration](docs/CONFIGURATION.md) |
| Add authentication to an existing product | [Integration contract](docs/INTEGRATION.md) |
| Run a product with login, MFA and protected resources | [Working product example](examples/product-app/README.md) |
| Preserve data and keys across updates | [Upgrades and rollback](docs/UPGRADING.md) |
| Backups, cleanup, monitoring and incidents | [Operations](docs/OPERATIONS.md) |

For a native deployment, build with go build -trimpath -o nvuto-auth . and inject process environment yourself. The binary does not load .env. Provision separate migration/runtime database roles, run migrate with RUNTIME_DATABASE_ROLE, bootstrap once, and serve using the restricted runtime role; see the configuration and operations guides. This service is a standalone HTTP API, not a drop-in package for an existing application's routers or database.

## API and integration

The machine-readable contract is openapi.json. All API paths begin /api/v1/auth. Responses are {data: ...} or {error: stable_code}. Credentials are opaque 256-bit bearer values, not JWTs. Products validate them by calling GET /me; they must not decode them or infer permissions from unsigned headers.

- POST /login with tenant, email, password returns access_token and refresh_token, or mfa_required plus challenge. Complete MFA with POST /mfa/verify using token: challenge and either code or recovery_code.
- Send Authorization: Bearer <access_token> on protected requests. GET /me returns only identity, tenant, built-in role and MFA state. A product must still enforce its own resource authorization.
- Logout accepts either a current access bearer or its stored refresh_token, so an expired access token does not prevent revoking renewal authority.
- Access lasts up to 15 minutes. Sessions last an absolute seven days. POST /refresh takes refresh_token and replaces both tokens. The previous access token stops working. Reusing any old refresh token revokes the entire session family, including the concurrent winner; clients must serialize refreshes and sign in after an ambiguous refresh network failure.
- POST /step-up with password and an enrolled factor returns a proof valid for five minutes, one operation, and the same session. Password alone cannot step up an MFA account.
- POST /change-password takes new_password and proof. MFA setup takes proof and returns secret, otpauth_url and enrollment_token. Confirm with POST /mfa/confirm using token: enrollment_token and code. Factor changes and password changes revoke all sessions, grants and pending setup. Sign in again afterward.
- POST /mfa/disable takes proof. Admin MFA reset requires an owner's fresh proof, rejects self/cross-workspace reset, revokes target credentials, and forces the target to enroll a new factor before accessing general resources. A restricted enrollment session permits only step-up, MFA setup/confirmation and logout.
- POST /forgot-password and /resend-verification take tenant and email and return a generic response. Links expire after 15 minutes (initial verification and invitations: 24 hours). Reset takes token and new_password, never issues a session and preserves enrolled MFA.
- Owner POST /invitations takes email, optional name and proof; returned user_id identifies the pending invitation. Resend and revoke require new proofs. Invitation acceptance takes token and new_password, verifies email possession and returns to sign-in.

No endpoint authenticates using cookies, query parameters, X-Access-Token, X-User-ID, X-Tenant-ID or caller-selected roles. There are no auth cookies. Browser fetches use credentials: omit, an explicit Authorization header, same-origin delivery and no token persistence. No CORS is enabled; use your own same-origin backend-for-frontend if needed. The configured Origin is checked whenever a browser supplies Origin. This contract avoids ambient cookie authority and its CSRF requirement. Do not add cookie authentication without designing and testing a new CSRF contract.

Password policy: at least 15 Unicode characters, at most 72 UTF-8 bytes, no forced composition or periodic expiration. Recovery codes are random, single-use 256-bit values. TOTP accepts one adjacent 30-second interval and prevents reuse of a consumed time step.

## Validation

Run python scripts/check.py for formatting, unit tests, vet and build. Run python scripts/integration.py for a fresh private PostgreSQL cluster, restricted-role route tests, concurrency/failure tests, encryption rotation and backup/restore checks. Set PG_BIN if PostgreSQL binaries are elsewhere; on Linux pg_config supplies the default. Integration tests fail when invoked without the isolated runner; no database tests are silently counted as passed.

The account-management browser integration is /account and internal/service/account.js. The runnable product integration is [examples/product-app](examples/product-app/README.md); examples/resource-server/main.go is a smaller bearer-validation sketch. See docs/ARCHITECTURE.md, docs/OPERATIONS.md and docs/AUDIT-REMEDIATION.md for boundaries and audit disposition.

For production HTTPS setup and plain-language hosting instructions, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Repeat the isolated HTTPS/SMTP container acceptance check with `python scripts/container_check.py`; scan the application and pinned supporting images with `python scripts/image_scan.py` (Trivy required).
