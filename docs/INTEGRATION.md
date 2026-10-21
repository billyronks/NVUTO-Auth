# Integrate into an existing product

Deploy your own NVUTO Auth beside your application. The runtime uses your PostgreSQL and outgoing-email provider; no auth.nvuto.com login or endpoint is required. Keep it as a separate service with an HTTP boundary, even if you store its source inside your product repository. Directly merging Go packages into an existing backend requires adapting module paths, routing, configuration and migrations yourself; this release is not a plug-in library.

## Request flow

    Browser -> your product backend -> your NVUTO Auth instance
                 |
                 +-> your product database (tenant_id AND user_id)

The working [product example](../examples/product-app/README.md) implements this flow. Its browser calls same-origin /api/auth/login, /api/auth/mfa/verify, /api/auth/refresh and /api/auth/logout. A small backend adapter forwards only these allowlisted operations to the configured auth instance over verified HTTPS (loopback HTTP only for local development). The adapter does not trust caller identity, cookies or forwarded headers. It rejects a browser Origin belonging to another site and never follows an upstream redirect with credentials.

NVUTO's /account page is available for email actions, signup, invitations, password recovery and MFA management. Products can build their own UI against the same [OpenAPI contract](../openapi.json). The example deliberately delegates these account-management screens rather than recreating every auth operation.

## Login and session handling

All auth endpoints are under /api/v1/auth. Successful responses use a data envelope; errors contain error. POST /login takes tenant (workspace slug), email and password. A successful ordinary login returns opaque access_token/refresh_token values, not JWTs.

If mfa_required is true, pass its challenge to POST /mfa/verify as token with code or recovery_code. If mfa_enrollment_required is true, the account has a restricted session: require enrollment using /account before entering your product. Never grant application access based on that flag or an unvalidated login response.

The browser example keeps credentials only in tab memory, sets fetch credentials: omit and sends Authorization: Bearer on protected calls. There is no localStorage, cookie or query-string token transport. Reloading loses the local credentials; server sessions still exist until logout/revocation/expiry. Use account session management to revoke lost sessions. If you implement persistent cookie sessions, design a separate backend session, CSRF protection and secure cookie policy; this sample does not supply that contract.

Access expires within 15 minutes. Refresh replaces BOTH access and refresh values and invalidates the old access value. Serialize refreshes for a session. Reusing an old refresh token revokes the entire family, even a concurrent winner. After a refresh network timeout with an unknown outcome, clear credentials and sign in again; do not blindly retry the old token. Sessions have an absolute seven-day lifetime. Logout accepts the stored refresh token even when access has expired.

## Authenticate every protected product request

For a protected endpoint:

1. Read only its Authorization bearer; reject missing credentials.
2. Call GET /api/v1/auth/me on your trusted instance with that bearer. Never decode the opaque value, accept a user ID supplied by the browser, or cache a positive identity indefinitely.
3. Treat revoked/expired/restricted credentials as unauthenticated. Fail closed on connection failures, malformed identities or upstream errors. Distinguish an unavailable auth dependency (503) from a rejected credential (401).
4. Check tenant_id against the workspace provisioned for this product. The workspace slug used at login is not its UUID.
5. Enforce your application's permissions and ownership in your own database. A query should constrain BOTH tenant_id and the current user_id unless a separately authorized product role permits wider access. Do not assume NVUTO's owner/member role grants access to every product record.

The example's /api/projects returns only a synthetic project whose owner and workspace match the verified identity. Replace that block with your product's parameterized query and explicit permissions. Keep auth tables in the dedicated auth database and avoid coupling your product to their internal schema.

## Existing infrastructure

Set AUTH_URL in the consuming application to your instance's trusted origin. For private inter-host traffic, use HTTPS with a trusted matching certificate; do not disable verification or follow redirects. The sample allows HTTP only on literal loopback hosts for a local walkthrough. It can use internal DNS and certificates issued by your organization's CA, provided that CA is installed in the application's trust store.

The auth browser UI uses its configured PUBLIC_URL; your product browser uses its own APP_PUBLIC_URL. Because the product adapter performs server-to-server calls, a separate auth hostname does not require enabling cross-origin browser access. Direct cross-origin fetch from the browser is not supported by the default auth CORS policy.

The adapter aggregates requests at its own source IP. Apply per-client rate limiting at your product edge as appropriate. Do not forward arbitrary X-Forwarded-For into auth to bypass its limits. A direct deployment proxy must overwrite that header and be explicitly trusted; see CONFIGURATION.md.

For multiple independently operated products, run separate instances/databases/keys and configure each product with its own expected workspace. A shared developer dashboard, OAuth/OIDC federation and central product onboarding are outside this standalone release's contract.
