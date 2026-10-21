# Existing product + self-hosted NVUTO Auth

A runnable, intentionally small product with its own login screen and protected projects API. It connects to YOUR auth instance. It has no dependency on auth.nvuto.com and is not a hosted-service SDK.

## Run it

First complete the repository's [self-hosting quickstart](../../docs/SELF-HOSTING.md): start auth, bootstrap your workspace, verify your email and optionally enroll MFA. Install Go 1.27.3 to run this example from source. Run all commands from the repository root.

Get the workspace UUID from your own local Compose database:

    docker compose -p nvuto-auth exec -T db psql -U postgres -d auth -c "SELECT id,slug FROM auth_tenants;"

Copy the id for the workspace you created. This UUID is an identifier, not a credential. Keep the matching workspace slug for the login form. For an existing managed deployment, ask its operator for the provisioned workspace UUID instead of exposing its database.

Linux/macOS shell:

    export AUTH_URL=http://localhost:8081
    export APP_PUBLIC_URL=http://localhost:8090
    export EXPECTED_TENANT_ID=PASTE_YOUR_WORKSPACE_UUID
    go run ./examples/product-app

Windows PowerShell:

    $env:AUTH_URL = 'http://localhost:8081'
    $env:APP_PUBLIC_URL = 'http://localhost:8090'
    $env:EXPECTED_TENANT_ID = 'PASTE_YOUR_WORKSPACE_UUID'
    go run ./examples/product-app

Replace the UUID placeholder; startup rejects an invalid or missing UUID. Open http://localhost:8090, enter your workspace slug, verified email and password. If MFA is enrolled, complete its authenticator/recovery challenge. Select Load my projects. Try Refresh session, then Sign out; the old credentials no longer authorize projects. The page never displays or persists credentials. Reloading requires signing in again.

Use the account-management link for verification/reset links, invitations, MFA enrollment and session management on your instance. MFA-required enrollment accounts must complete enrollment there before using this product. /account is a separate example UI; it does not provide automatic single sign-on into the product tab.

## Map this onto an existing application

- main.go's four /api/auth/* POST routes are a same-origin adapter to the instance selected by AUTH_URL. They forward no cookies or caller-supplied user/tenant/proxy identity and reject unexpected redirects. No general-purpose proxy is exposed.
- /api/projects validates every bearer against auth /me, checks EXPECTED_TENANT_ID and scopes its synthetic project to the verified user. Replace the synthetic record with a query against YOUR product database, constrained by tenant_id and user_id plus your product's authorization rules.
- app.js demonstrates ordinary login, TOTP/recovery verification, memory-only credentials, serialized refresh and logout. Refresh is manual in this example; network ambiguity clears credentials rather than retrying a used refresh token.
- Identity IDs and tenant UUIDs can be stored as foreign identifiers in your product. Do not add product tables to auth's private schema or treat a UUID supplied in a request body as verified identity.

In production set AUTH_URL to your own trusted HTTPS auth origin and APP_PUBLIC_URL to your product's exact HTTPS origin. Keep this example's listener private behind your product reverse proxy; APP_LISTEN_ADDR defaults to 127.0.0.1:8090 and can be changed explicitly for an internal container interface. Certificates are verified with the system trust store, and upstream redirects are never followed. HTTP is accepted only on loopback for the local walkthrough. Do not publish this development listener as a public HTTP application.

This sample is not a complete product, persistent project database, distributed session store or user-management dashboard. It shows the integration boundary you can adapt in Go or another backend language. Cookie authentication requires its own CSRF/session design; the sample intentionally uses explicit bearer credentials and no cookies. See [integration guidance](../../docs/INTEGRATION.md).

## Verify it

    go test ./examples/product-app
    python3 scripts/integration.py

The first command exercises a real TLS test upstream: missing credentials, forged identity headers, cross-origin calls, wrong workspaces, revocation, upstream failure/malformed identity, redirect refusal and body limits. The second creates a fresh private PostgreSQL cluster and runs the example against the actual compiled NVUTO Auth server, exercising login, protected projects, refresh and logout revocation. It requires the database test prerequisites in the root README. It does not connect to your production database or send real email.
