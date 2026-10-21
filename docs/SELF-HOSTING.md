# Self-hosting quickstart

Run NVUTO Auth in your infrastructure, alongside your existing application. No NVUTO account, activation key or connection to auth.nvuto.com is required. You own the database, domain, email account and encryption keys. The MIT license permits copying and modifying the source with its license notice retained.

This is a standalone HTTP service, not an OIDC provider or a drop-in authentication library. Keep your product's data and authorization in your product; NVUTO manages credentials and sessions. Use a fresh dedicated auth database. The old HR database/API is not supported.

## 1. Get the source and prerequisites

Download and extract a [source release](https://github.com/billyronks/NVUTO-Auth/releases), or clone it:

    git clone https://github.com/billyronks/NVUTO-Auth.git
    cd NVUTO-Auth

 Work from its root directory (the folder containing compose.yaml). You can also keep that directory inside your existing repository, for example vendor/nvuto-auth. Retain LICENSE, NOTICE and third-party notices.

Install Docker Engine with Compose v2.24.4+ and Python 3. Run:

    docker version
    docker compose version
    python3 --version

On Windows, use python instead of python3 if that is your installed command. Go is not required to build the service with Docker; Docker downloads its pinned build toolchain. The source-only example app below uses Go 1.27.3. Build images on a machine with enough memory for compilation; a small runtime host may need images built elsewhere. Production capacity must be measured for your workload.

## 2. Generate private configuration

    python3 scripts/init_env.py

This creates .env with three independent random secrets and refuses to overwrite an existing file. It does not print the secrets or connect to any server. .env is excluded from Git, release ZIPs and Docker build contexts. Restrict its filesystem access; on Linux it is created owner-readable/writable only, and on Windows restrict its ACL as appropriate.

Open .env locally in your editor. Fill in:

| Setting | Your value |
| --- | --- |
| SMTP_HOST, SMTP_PORT | Your outgoing-email server and its STARTTLS port, usually 587 |
| SMTP_USER, SMTP_PASSWORD | Your provider's SMTP credentials; configure both or neither for a trusted relay |
| MAIL_FROM | A sender address verified with that provider |
| BOOTSTRAP_EMAIL | Your initial owner's real email |
| BOOTSTRAP_TENANT | A lowercase workspace slug, for example my-product |
| BOOTSTRAP_NAME | Initial owner's display name |

Keep PUBLIC_URL=http://localhost:8081 for your first local run and REGISTRATION_MODE=invite. Do not reuse SMTP sample values. Quote credentials containing dollar signs using Compose's literal single-quote syntax; see [configuration](CONFIGURATION.md). The generated database passwords and key are already filled in.

You need a verified STARTTLS email provider even for this manual local walkthrough. For an automated isolated test with synthetic mail and local certificates instead, use python3 scripts/container_check.py (Docker and OpenSSL required). That command cleans up its own test stack and is not an interactive inbox or a production deployment.

## 3. Start a fresh instance

These commands use a stable Compose project name, nvuto-auth. Use a different stable name for each independent installation. Existing installations must retain their original project name and volumes.

    docker compose -p nvuto-auth config --quiet
    docker compose -p nvuto-auth up -d --build auth
    docker compose -p nvuto-auth ps -a

The database initializes its restricted runtime role, the migration job applies the baseline, then auth starts. The application is reachable only at http://localhost:8081; PostgreSQL has no published port.

    curl --fail http://localhost:8081/ready

Expect HTTP 200 and a ready status. To diagnose startup:

    docker compose -p nvuto-auth logs --tail=100 db migrate auth

Use config --quiet for validation. Full docker compose config output includes resolved secrets; do not post it publicly.

## 4. Create the first owner

    docker compose -p nvuto-auth run --rm bootstrap

Enter a unique password containing at least 15 characters and no more than 72 UTF-8 bytes. It is read from stdin, hidden in an interactive terminal. Do not put it in command arguments or source files.

Open the verification email, follow its link and select Complete email action. Sign in at http://localhost:8081/account with the workspace slug, email and password. If an email was delayed or expired, use resend verification on that page. Bootstrap works once, while the database has no users; later users are invited by the owner. Configure TOTP MFA and retain the one-time recovery codes before administering real users.

A link to localhost works only on the machine running this local instance. For a remote server, configure its real HTTPS origin before bootstrap so email links point to that server.

## 5. Connect an existing product

Run the [working product example](../examples/product-app/README.md). It includes a login form, TOTP/recovery challenge, a protected projects API, refresh rotation and logout. Its backend validates credentials against your auth instance on every protected request and checks its expected workspace.

Your application stores its own records using NVUTO's user UUID and tenant UUID as foreign identifiers. Do not read the auth database directly or treat an auth role as permission to access arbitrary product records. See [integration guidance](INTEGRATION.md) and the [OpenAPI contract](../openapi.json).

## 6. Put your own instance online

Use a hostname you control, such as auth.your-product.com. Choose one TLS arrangement:

- **Bundled Caddy proxy:** set AUTH_DOMAIN in .env, point DNS to your server and allow TCP 80/443. Run the commands below. The overlay derives PUBLIC_URL from AUTH_DOMAIN and removes the direct application port.
- **Existing reverse proxy:** keep the base Compose stack private, set PUBLIC_URL to the exact HTTPS origin and route that hostname to the application. A host proxy can use 127.0.0.1:8081. A container proxy needs an explicitly shared private Docker network and the auth:8081 service address; localhost inside another container is not the host. Configure only the proxy's controlled source address in TRUSTED_PROXIES and overwrite incoming X-Forwarded-For. Do not publish PostgreSQL or the application directly.

Bundled proxy, for a fresh production installation configured before bootstrap:

    docker compose -p nvuto-auth -f compose.yaml -f compose.production.yaml config --quiet
    docker compose -p nvuto-auth -f compose.yaml -f compose.production.yaml up -d --build auth edge
    docker compose -p nvuto-auth -f compose.yaml -f compose.production.yaml run --rm bootstrap

If you already bootstrapped locally, keep that database/project, change to the production configuration and recreate the services; do not bootstrap again. Reissue expired or localhost verification links using resend verification. The bundled proxy reserves 172.30.83.0/28: adjust the subnet, static addresses and trusted proxy entry together if it overlaps your existing network.

Verify real HTTPS, actual inbox delivery, login, reset and revocation. Configure monitoring, scheduled cleanup, backups of the database and separate key material, and test a restore before inviting customers. See [operations](OPERATIONS.md), [configuration](CONFIGURATION.md), [upgrades](UPGRADING.md) and the [release evidence](RELEASE.md). A passing local test is not a guarantee about your hosting environment.
