# Configuration reference

NVUTO Auth reads process environment. Docker Compose loads .env to interpolate its service definitions; the native Go binary does not load .env itself. No NVUTO-hosted account or service URL is required.

Start with python3 scripts/init_env.py, then edit the private .env. This is a Compose helper, not a native database installer. Use your platform's secret manager/process environment for a native deployment. Do not source a Compose .env as a shell script: its quoting/interpolation rules differ.

## Service settings

| Variable | Requirement/default | Meaning |
| --- | --- | --- |
| DATABASE_URL | Required by native binary | PostgreSQL URL for the command's role. Compose generates this from its own database passwords, so changing this entry alone does not change Compose's connection. |
| PUBLIC_URL | Required; base Compose defaults to http://localhost:8081 | Exact user-facing origin, with no path, query, credentials or fragment. HTTPS except loopback development. Determines browser Origin validation and email links. |
| LISTEN_ADDR | Native: 127.0.0.1:8081; Compose: :8081 | Internal listener, not the public URL. A container must listen on its container interface. |
| AUTH_ENCRYPTION_KEYS | Required | Comma-separated key-id:64-hex entries. Keys encrypt MFA secrets and queued mail. Keep old keys until rotation and backup-retention requirements are satisfied. |
| AUTH_ACTIVE_KEY | Required | ID of the configured key used for new writes, initially v1. |
| REGISTRATION_MODE | invite | invite or public. Public permits member signup into an existing workspace; it never creates a workspace owner. |
| SMTP_HOST | Required | Outgoing-email hostname whose certificate must verify. |
| SMTP_PORT | 587 | Provider's STARTTLS port. Other STARTTLS ports such as 2587 work when supported by the provider and allowed by hosting. Port 465 implicit TLS is unsupported. |
| SMTP_USER / SMTP_PASSWORD | Optional pair | Set both for authenticated SMTP. Both may be empty only for an appropriately restricted relay that still supports verified STARTTLS. |
| MAIL_FROM | Required | Valid sender mailbox authorized by your email provider. |
| SMTP_CA_FILE | Optional | PEM certificate bundle inside the running process/container for a private SMTP CA. Public CAs use the system bundle. Never disable certificate verification. |
| TRUSTED_PROXIES | Empty | Comma-separated CIDRs of proxies you control. Other callers' forwarded headers are ignored. Without this setting, rate limits aggregate at the direct peer. |

Remote database URLs require sslmode=verify-full and trusted matching certificates. Only loopback and the private Compose hostname db permit disabled database TLS. This exception is for the private local Docker network, not a remote database renamed db. Provision a non-owner runtime role without superuser/BYPASSRLS or membership in the migration owner role. Run migrate with the separate migration role and set RUNTIME_DATABASE_ROLE to the existing runtime role to grant the required privileges.

## Compose and initial-owner settings

| Variable | Meaning |
| --- | --- |
| POSTGRES_PASSWORD | Independent random hexadecimal password for the local migration/admin database role. Initialization-only: changing .env does not rotate an existing database role password. |
| AUTH_DATABASE_PASSWORD | Different random hexadecimal runtime-role password. Also initialized only when the database volume is empty. Coordinate SQL password rotation with configuration updates. |
| AUTH_DOMAIN | Hostname for the bundled production proxy, without scheme/path. The production overlay derives PUBLIC_URL=https://AUTH_DOMAIN for auth, migrate and bootstrap. |
| BOOTSTRAP_TENANT | Initial workspace slug: 2-63 lowercase letters/digits/hyphens, beginning with a letter or digit. Used at login. |
| BOOTSTRAP_EMAIL | Initial owner's email; actual verification is required. |
| BOOTSTRAP_NAME | Display name; Compose defaults to Workspace Owner. |

Bootstrap settings must be filled even when Compose validates a configuration containing the tools-profile service. After initialization, editing them does not change an existing owner or workspace. There is no HTTP bootstrap endpoint. Never point this baseline at a legacy HR database.

## Credentials, quoting and persistent state

Generate independent secrets with the helper or python3 -c "import secrets; print(secrets.token_hex(32))". Keep generated hexadecimal passwords in Compose database URLs so URL encoding is unambiguous. For native/managed database passwords containing reserved URL characters, percent-encode the password component.

Compose unquoted and double-quoted values expand dollar signs. Literal single-quoted SMTP values preserve them, for example SMTP_PASSWORD='your-provider-value'. A single quote inside such a value is escaped with a backslash. Never paste real credentials into documentation, commits, tickets or logs. Shell environment variables can override .env values; validate using docker compose config --quiet. See [Docker's environment syntax](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/).

The auth-db volume persists credentials, users and sessions. edge-data persists TLS certificates and private keys; edge-config is Caddy configuration state. Preserve the same Compose project name between releases. Deleting volumes deletes state. Encryption keys must be backed up separately from the database and preserved across restarts/upgrades. Generating a fresh .env for an existing database is not an upgrade.

For a private SMTP CA, use an override file that mounts the host PEM read-only at the SMTP_CA_FILE container path on auth and bootstrap (and any maintenance command reading that configuration). A host path alone is not visible in a container. Do not bake keys or SMTP credentials into images.

## Example application settings

The [product example](../examples/product-app/README.md) uses AUTH_URL (your auth origin), APP_PUBLIC_URL (its own browser-facing origin), EXPECTED_TENANT_ID (the UUID from your own instance), and optional APP_LISTEN_ADDR. These belong to your product process and are not NVUTO Auth server settings. No shared signing secret or JWT decoding is used.

## Use an existing PostgreSQL service or orchestrator

The bundled Compose stack provisions its own private PostgreSQL database. To use a managed/existing PostgreSQL 18 server, create a NEW dedicated auth database and use the native binary or your own container/orchestrator definition instead of assuming that .env's DATABASE_URL overrides the bundled Compose database service.

1. Create the database and migration owner using your provider's administration tools. Keep product tables in their existing product database.
2. Create a separate login role named auth_runtime, with no superuser, BYPASSRLS, database/role creation, replication, schema/table ownership or membership in the migration owner role. Set its password privately with the provider UI or psql's interactive password command. Revoke public schema creation and grant connection to this dedicated database. A database administrator can use:

       CREATE ROLE auth_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
       REVOKE CREATE ON SCHEMA public FROM PUBLIC;
       GRANT CONNECT ON DATABASE nvuto_auth TO auth_runtime;

   Substitute the actual dedicated database name. In an interactive psql session, use \password auth_runtime to set its secret without embedding it in SQL/history. Providers may require their supported role-management UI instead.
3. Inject the common key/SMTP/public-origin configuration and the migration owner's DATABASE_URL through your secret manager, with sslmode=verify-full for a remote server. Set RUNTIME_DATABASE_ROLE=auth_runtime and run nvuto-auth migrate once as a private job. This grants the runtime table/sequence privileges and restricts audit/schema writes.
4. Replace DATABASE_URL with the runtime role's URL in the bootstrap and server processes; bootstrap once, then run nvuto-auth serve. Do not reuse the migration owner's URL for serve; the binary rejects an owner/privileged runtime role.
5. In an existing container platform, build the root Dockerfile, inject environment at runtime, keep the app network private, and use your existing ingress/reverse proxy for HTTPS. Use /health for liveness and /ready for readiness, allow at least 45 seconds for termination, and schedule cleanup through a separate maintenance identity. Keep migration credentials out of the long-running app container.

Install your provider's trusted CA material where the database client can read it when required. Preserve hostname verification. These are infrastructure integration instructions; the supplied local acceptance test does not establish compatibility or availability for a particular managed provider.
