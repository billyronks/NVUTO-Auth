-- A fresh dedicated auth database is required.
CREATE TABLE IF NOT EXISTS auth_schema(version integer PRIMARY KEY);
CREATE TABLE IF NOT EXISTS auth_tenants (
 id uuid PRIMARY KEY, slug text NOT NULL UNIQUE CHECK(slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
 active boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS auth_users (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES auth_tenants(id),
 email text NOT NULL CHECK(email=lower(email)), name text NOT NULL CHECK(char_length(name)<=120),
 password_hash text NOT NULL, role text NOT NULL CHECK(role IN ('owner','member')),
 active boolean NOT NULL DEFAULT true, verified boolean NOT NULL DEFAULT false,
 version integer NOT NULL DEFAULT 0, mfa_required boolean NOT NULL DEFAULT false, mfa_secret text,
 last_totp_step bigint NOT NULL DEFAULT -1, pending_token text, pending_secret text, pending_expires timestamptz, pending_version integer,
 pending_attempts integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,email)
);
CREATE TABLE IF NOT EXISTS auth_grants (
 hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('verify','invite','reset','mfa','stepup')),
 version integer NOT NULL, expires timestamptz NOT NULL,
 attempts integer NOT NULL DEFAULT 0, session_id uuid
);
CREATE TABLE IF NOT EXISTS auth_sessions (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
 version integer NOT NULL, access_hash text NOT NULL UNIQUE,
 access_expires timestamptz NOT NULL, expires timestamptz NOT NULL,
 restricted boolean NOT NULL DEFAULT false, revoked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
-- Consumed refresh hashes are retained for family reuse detection.
CREATE TABLE IF NOT EXISTS auth_refresh (
 hash text PRIMARY KEY, session_id uuid NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
 used boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS auth_recovery (
 user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
 hash text NOT NULL, PRIMARY KEY(user_id,hash)
);
CREATE TABLE IF NOT EXISTS auth_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL, actor_id uuid NOT NULL, event text NOT NULL,
 target_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth_outbox (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 recipient text NOT NULL, encrypted_body text NOT NULL,
 attempts integer NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT now(),
 delivered_at timestamptz
);
CREATE TABLE IF NOT EXISTS auth_rate (
 bucket text PRIMARY KEY, window_start timestamptz NOT NULL,
 count integer NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_grants_user ON auth_grants(user_id);
CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id);
INSERT INTO auth_schema(version) VALUES(1) ON CONFLICT DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS auth_single_owner ON auth_users(tenant_id) WHERE role='owner';
