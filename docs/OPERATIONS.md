# Deployment and operations

For a step-by-step first deployment, start with [DEPLOYMENT.md](DEPLOYMENT.md).

## Configuration

Required: DATABASE_URL, PUBLIC_URL, AUTH_ACTIVE_KEY, AUTH_ENCRYPTION_KEYS, SMTP_HOST and MAIL_FROM. Optional: LISTEN_ADDR (127.0.0.1:8081), REGISTRATION_MODE (invite; public enables member signup), SMTP_PORT (587), SMTP_USER, SMTP_PASSWORD, SMTP_CA_FILE (PEM trust bundle), TRUSTED_PROXIES (comma-separated trusted CIDRs).

AUTH_ENCRYPTION_KEYS is a comma-separated map such as v1:<64 hex chars>,v2:<64 hex chars>; AUTH_ACTIVE_KEY chooses the write key. Provision independent random 256-bit keys. Missing/malformed keys and unknown key IDs fail closed. Back them up separately from the database. JWT_SECRET is not used. The binary reads process environment; Compose reads .env. No source defaults confer credentials.

Use HTTPS at a reverse proxy. Bind the application privately; the provided Compose port binds loopback. Set PUBLIC_URL to the exact external origin, without a path. The browser example is same-origin, and no cross-origin CORS policy is enabled. TLS termination does not change token policy: the service ignores forwarded scheme/identity headers. Only explicitly trusted proxy peers may supply client IP chains; X-Forwarded-For is read from right to left through configured CIDRs. Never trust arbitrary public networks. Without proxy configuration, rate limits aggregate at the direct peer.

PostgreSQL 18 is the tested target. External DATABASE_URL connections require sslmode=verify-full. Loopback development and the private Compose hostname db may use disabled transport TLS; protect that Docker network and use verified database TLS across hosts. The runtime role must not be superuser, BYPASSRLS, table owner, or a member of the migration owner role.

## Database ownership and upgrades

Use a new dedicated database; migrate rejects the legacy public.users table. Run nvuto-auth migrate using the migration role and RUNTIME_DATABASE_ROLE=<existing runtime role>. The role receives DML and sequence usage, with audit/schema write restrictions. Run serve as that restricted role. Migration/bootstrap do not run from HTTP routes and the server does not apply migrations automatically.

Version 1 has one transactional, idempotent empty-database baseline and no supported HR upgrade. Back up before upgrades. Future versions must add forward-only migration files and explicit upgrade tests; do not edit an applied baseline in a deployed release. Restore the prior database and binary to roll back. Never apply migrations to an unrelated product database.

The local bootstrap works only with zero existing users. It creates one owner/workspace and queues email verification. Keep bootstrap/migration access private. A pending owner can request another verification email. Losing owner access is an operator incident; there is no public administrative backdoor or owner-transfer API.

## Availability and limits

GET /health is process liveness. GET /ready checks the schema/database and sustained outbox failure (three failed attempts or an overdue queue). Readiness does not prove inbox delivery. Every API operation has a 15-second dependency budget, 16 KiB request cap, and bounded HTTP read/header/write/idle timeouts. SIGTERM triggers a 30-second HTTP shutdown budget. SMTP calls use a 15-second connection deadline and require verified STARTTLS with TLS 1.2 or newer.

Database-coordinated rate limits cannot be disabled by an environment flag. Per direct/trusted client IP and endpoint: 60 requests per 15 minutes for mutations, 1,200 for reads. Account operations add 20 per account/workspace per 15 minutes; step-up adds 10 per user. A database/limiter failure denies requests. MFA challenges and pending enrollment have five attempts. Avoid public unauthenticated access through a shared unconfigured proxy. Serialize refreshes in each client.

Queueing is durable and transactional. SMTP delivery is at-least-once; a crash after SMTP acceptance may send a duplicate email. Retries back off from one minute, capped at one hour, for at most ten attempts. Inspect undelivered rows with attempts>=3 and alert on delivery age, rate-limit failures, HTTP 401/403/429/503, refresh_reuse and privileged audit events. To retry a repaired dead letter, use a maintenance transaction to reset attempts=0 and next_attempt=now(); expired links must be reissued through the API. Never print encrypted bodies, tokens, passwords or seeds into logs.

Run nvuto-auth cleanup daily with the maintenance role. It expires rate buckets after one day, expired grants, sessions one day after absolute expiry (refresh tombstones cascade), delivered bodies after one day, overdue undelivered bodies after 30 days and audit events after 180 days. Adjust retention in a reviewed migration/process to match your requirements. The repository does not install a scheduler or configure external alert destinations.

The local acceptance workload is an engineering check, not a production capacity promise. Set your own latency/error/availability targets and test your actual proxy, SMTP provider, network, database, instance count and traffic mix. Multi-region operation is unsupported.

## Backup, restore and rotation

Use pg_dump --format=custom with a restricted backup operator, and store an encrypted, access-controlled backup separately from AUTH_ENCRYPTION_KEYS. Restore into a new database with pg_restore --exit-on-error; validate schema version, row counts, SMTP queue behavior and MFA with synthetic users before switching traffic. Never send replayed queued mail to real users during a restore drill. Restore revives the backed-up credential state; revoke all auth_sessions and delete auth_grants after an incident restore before allowing traffic.

To rotate encryption: stop serving and mail workers; take a backup and verify old-key recovery; configure both old and new keys with a new AUTH_ACTIVE_KEY; run nvuto-auth rotate-encryption; verify encrypted active/pending factors and queued mail; take and restore a new backup; restart; retire the old key only after the backup-retention policy permits it. Rotation is transactional and leaves data unchanged on decryption/write failure. Removing an old key before rotation makes its records unreadable. No signing-key rotation exists because credentials are opaque, not signed tokens.

For compromised accounts: disable the user through an owner's fresh step-up proof or an operator transaction, increment version, revoke sessions, remove grants/pending enrollment, record the intervention and notify the verified channel. If the application/DB host or encryption key was compromised, isolate traffic, rotate database/SMTP credentials, revoke all sessions/grants, investigate factor exposure, require appropriate factor re-enrollment, restore carefully and review audit evidence. Deployments own this response.

## Publication and deployment gates

Before public hosting, enable private vulnerability reporting on the actual repository, configure verified SMTP delivery and HTTPS, verify backups and alerts, and pass the CI container build/scanner and deployed lifecycle smoke tests. Docker and local HTTPS/authenticated SMTP checks are now exercised in an isolated Linux environment; see RELEASE-EVIDENCE.json for the exact scope. A real SMTP provider and live public-domain certificate/inbox delivery still require the hosting configuration. No deployment or publication is performed by this repository change.

CI installs PostgreSQL 18 using the [official PostgreSQL Ubuntu repository instructions](https://www.postgresql.org/download/linux/ubuntu/). Pin and review deployment image digests for your release process.

For a private SMTP CA in Compose, mount the PEM bundle read-only through a compose.override.yaml file and set SMTP_CA_FILE to its path inside the container. Do not set a host-only path without a corresponding mount.

Keep application and database clocks synchronized with a monitored time service. TOTP depends on wall-clock time; security grant predicates use the database wall clock.
