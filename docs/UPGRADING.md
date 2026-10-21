# Upgrades, backups and rollback

Keep your auth instance under your own infrastructure and release process. No hosted NVUTO sign-in is involved. The v0.1.0 baseline supports a fresh standalone database and repeat execution of that same baseline. It does not provide a PostgreSQL major upgrade or an arbitrary migration path from future releases. A later release must document its supported predecessor and forward-only migration steps before you use it.

The commands below are for a Linux shell, the bundled production stack and the project name nvuto-auth used by the quickstart. Substitute your EXISTING project name, environment-file location and Compose files. Do not change project names or regenerate .env while upgrading: that can select an empty volume or lose decryption/password access. An installation with its own proxy omits compose.production.yaml and edge.

## Prepare a release

1. Read the target release notes and compare configuration and schema requirements. Acquire a trusted source release, verify its published checksum and build/scan it in staging. Do not deploy a floating branch or assume a database image tag change is safe.
2. Record the running image IDs, source version, schema version, project name and volume names. Retain the old images in your own registry or image archive, the old source and its Compose definitions. Rebuilding old source later does not necessarily reproduce old OS-package updates.
3. Preserve .env and all old/new encryption keys in restricted storage, separately from the database backup. Provider credentials and encryption keys must not be bundled into the public source archive.
4. Restore a recent backup into an isolated staging database with the matching keys. Keep its outbound mail disabled at the network boundary so restored queued messages cannot reach real users. Test migrations, login, MFA, refresh/revocation and your consuming product against that copy.
5. Arrange a maintenance window and an operator who can restore the prior release. Define an acceptable outage and recovery point. A single-server Compose deployment does not promise zero-downtime upgrades.

From the release root, this convenience function keeps every command on the same installation:

    dc() { docker compose -p nvuto-auth -f compose.yaml -f compose.production.yaml "$@"; }
    dc config --quiet
    dc ps -a
    dc images
    dc exec -T db psql -U postgres -d auth -At -c 'SELECT version FROM auth_schema'

Archive immutable images using their recorded IDs before building replacement tags. Store these archives in your restricted release/backup location. The bundled PostgreSQL and Caddy image names are local build tags; they are not public registry images supplied by NVUTO.

## Back up before changes

Pause auth traffic and the mail worker before the final backup:

    dc stop edge auth
    dc exec -T db pg_dump -U postgres -d auth --format=custom > /secure-backup/auth-before-upgrade.dump
    dc exec -T db pg_restore --list < /secure-backup/auth-before-upgrade.dump

Create /secure-backup yourself with restricted permissions or substitute your encrypted backup destination. The dump contains credential material and encrypted factors; protect it and upload it to your encrypted backup store. A successful listing is only a format check; rehearse an actual restore in staging. Preserve encryption keys separately and preserve Caddy's edge-data volume. Never paste a dump or .env into an issue.

Do not use docker compose down --volumes, docker volume prune, or delete auth-db as an upgrade step. Do not change PostgreSQL major version or switch libc/locale image families against an existing data directory. Those require a separately planned dump/restore or supported database upgrade, including collation review.

## Apply a reviewed, compatible update

After switching the source checkout to the reviewed release, retain the same private environment and project/volume identity. Inspect target-release migration instructions first. For rebuilding the SAME v0.1.0 baseline or a release explicitly documenting these steps:

    dc config --quiet
    dc build db auth migrate edge
    dc up -d --no-deps db

Wait for the database container to be healthy (dc ps). Then run the migration as a fresh one-off job rather than relying on an old completed migration container:

    dc run --rm --no-deps migrate
    dc up -d --no-deps auth edge

Stop if migration fails. Do not start the application against an unknown schema. Migration uses the separate admin role; auth still uses its restricted runtime role. Bootstrap is not an upgrade command and must not be rerun. Changing database password entries in .env alone does not rotate initialized roles; use coordinated SQL/configuration rotation described in CONFIGURATION.md.

Check https://YOUR_AUTH_HOST/ready with certificate verification enabled. Confirm a synthetic user's email verification/reset delivery, MFA, login, session rotation/revocation and protected access in your existing application. Check logs and alerts for delivery failures or repeated 503 responses, then reopen traffic. Keep the backup and old immutable release until the rollback window closes.

## Roll back or restore

If there was no schema/data change, redeploy the recorded old immutable images and old source/configuration, preserving the existing volumes and keys. Do not rely on a mutable local tag that a build already replaced.

If schema/data changed, stop application and mail workers and restore the matching backup into a NEW database with the old release's documented schema/roles and keys. Use pg_restore --exit-on-error; verify row counts and encrypted-factor decryption. Repoint the old release only after validation. Do not run a newer baseline as a substitute for a documented migration or attempt an improvised down-migration. Restoring a backup discards changes since that backup, and restores credential/session state from its timestamp.

For incident recovery, revoke all restored sessions and grants before permitting traffic and follow OPERATIONS.md. Keep real outbound email blocked during restore drills. Test restored MFA with synthetic users and verify that old keys remain available for every retained backup. See [operations](OPERATIONS.md) for cleanup, retention, key rotation and incident response.
