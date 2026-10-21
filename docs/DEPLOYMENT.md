# Put NVUTO Auth online

The repository contains the application and a tested container setup. To make it available to real people, it still needs a server, a website address and an outgoing-email account. You do not need to send passwords in a chat.

## What you need

1. A Linux server with Docker Engine and Docker Compose v2.24.4 or newer. This is the computer that stays online and runs the application.
2. A domain such as auth.your-company.com. Point its DNS A record to that server. Only add an AAAA record if the server actually serves IPv6.
3. An email provider with STARTTLS submission on port 587, an SMTP username/password and a verified sender address. SMTP is simply the outgoing-email connection. Port 465 implicit TLS is not supported. Configure the provider's required SPF/DKIM records and DMARC policy.
4. An operator who keeps the database backups and encryption keys safe and receives service alerts. Losing the keys makes encrypted factors and queued mail unreadable.

## Configure the server

Use a fresh standalone database. This release cannot be pointed at the old HR database.

Copy .env.example to a private .env file on the server. Restrict access to its owner and never commit or publish it. Replace every placeholder. Generate each database password and the encryption key separately with this command (run it three times):

    python3 -c "import secrets; print(secrets.token_hex(32))"

Set AUTH_DOMAIN to your hostname, without https:// or a path. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD and MAIL_FROM from your email provider. Use single quotes around SMTP credentials in the .env file if they contain dollar signs or other special characters; follow Docker Compose's .env escaping rules. Set BOOTSTRAP_EMAIL to the initial owner's real address and BOOTSTRAP_TENANT to the workspace name used at login. Keep REGISTRATION_MODE=invite unless you deliberately want public signup into existing workspaces.

The production overlay sets PUBLIC_URL from AUTH_DOMAIN, removes the direct app port and trusts only the dedicated proxy address. It reserves 172.30.83.0/28; if this overlaps an existing network, change its subnet, both static addresses and TRUSTED_PROXIES together before starting. PostgreSQL has no published port. Its connection is confined to the Docker bridge; remote databases require verify-full TLS and a matching trusted certificate.

Allow incoming TCP 80 and 443. Caddy obtains and renews public certificates automatically and redirects HTTP to HTTPS. Preserve its edge-data volume so certificate state survives restarts. Do not place another proxy/CDN in front without reviewing forwarded-address trust.

    docker compose -f compose.yaml -f compose.production.yaml config --quiet
    docker compose -f compose.yaml -f compose.production.yaml up -d --build auth edge
    docker compose -f compose.yaml -f compose.production.yaml run --rm bootstrap

The last command asks for the owner's password without displaying it. Open the verification email, follow its link, then sign in at https://YOUR_HOSTNAME/account. The example browser keeps bearer tokens in memory, so a reload requires signing in again.

## Confirm the live deployment

Check that https://YOUR_HOSTNAME/ready returns 200 with a valid public certificate, and that HTTP redirects to HTTPS. Confirm the verification email arrives in the intended inbox, then request and complete a password reset. Check the provider's delivery logs and spam folder if it does not arrive. Local test delivery does not prove that a provider will deliver to a real inbox.

Back up the database and encryption key material separately, test a restore, configure alerts for readiness failures, exhausted mail retries, restarts and backup failures, and agree on incident ownership. Read OPERATIONS.md for rotation, restore, retention and cleanup procedures. Do not use docker compose down --volumes against a live deployment: it deletes persisted data.

## Repeat the local acceptance checks

    python3 scripts/container_check.py

This creates a uniquely named, temporary Compose project with synthetic accounts and a private mail server. It validates the production Caddy routing using a local test certificate, actual encrypted/authenticated mail delivery, non-root/read-only app settings, session revocation and graceful shutdown. It removes only that project's containers/networks/volumes afterwards. It does not publish a website or send real email. OpenSSL and a Docker daemon are required. Run it on a test machine with no overlapping 172.30.83.0/28 network.

The Go integration suite also rejects missing STARTTLS, untrusted SMTP certificates, rejected SMTP credentials and legacy HTTPS TLS versions. Run scripts/integration.py as an unprivileged user with PostgreSQL tools installed; set AUTH_TEST_RACE=1 for its race detector.

Base images are pinned to tested digests. The proxy is built from locked Caddy source/module versions using the patched Go toolchain. The database build applies available Alpine security updates and replaces its obsolete Go-built privilege helper with su-exec. Review updates and scan every resulting image before deployment. The scratch application image has no package manager or shell. Application and supporting-image scans are recorded separately; a clean scan cannot establish the absence of all vulnerabilities.

References: [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https), [Docker Compose environment-file syntax](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/).
