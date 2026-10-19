/* Migration 0010: devices */

CREATE TABLE IF NOT EXISTS theauth_devices (
  id             TEXT NOT NULL PRIMARY KEY,
  agent_id       TEXT NOT NULL,
  owner_id       TEXT NOT NULL,
  tenant_id      TEXT,
  name           TEXT NOT NULL,
  kind           TEXT,
  hardware_id    TEXT,
  status         TEXT NOT NULL,
  device_groups  JSONB NOT NULL,
  metadata       JSONB,
  enrollment_id  TEXT,
  attestation    JSONB,
  expires_at     BIGINT,
  last_seen_at   BIGINT,
  last_seen_ip   TEXT,
  status_reason  TEXT,
  created_at     BIGINT NOT NULL,
  updated_at     BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_devices_agent ON theauth_devices (agent_id);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_devices_owner_hw ON theauth_devices (owner_id, hardware_id);

CREATE INDEX IF NOT EXISTS theauth_devices_owner_status ON theauth_devices (owner_id, status);

CREATE INDEX IF NOT EXISTS theauth_devices_enrollment ON theauth_devices (enrollment_id);

CREATE TABLE IF NOT EXISTS theauth_device_credentials (
  id             TEXT NOT NULL PRIMARY KEY,
  device_id      TEXT NOT NULL,
  kind           TEXT NOT NULL,
  lookup         TEXT NOT NULL,
  secret_hash    TEXT,
  public_jwk     JSONB,
  status         TEXT NOT NULL,
  expires_at     BIGINT,
  last_used_at   BIGINT,
  created_at     BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_credentials_lookup ON theauth_device_credentials (kind, lookup);

CREATE INDEX IF NOT EXISTS theauth_device_credentials_device ON theauth_device_credentials (device_id);

CREATE TABLE IF NOT EXISTS theauth_device_enrollments (
  id             TEXT NOT NULL PRIMARY KEY,
  kind           TEXT NOT NULL,
  token_hash     TEXT NOT NULL,
  owner_id       TEXT NOT NULL,
  tenant_id      TEXT,
  template       JSONB NOT NULL,
  max_uses       INTEGER NOT NULL,
  uses           INTEGER NOT NULL,
  expires_at     BIGINT NOT NULL,
  revoked_at     BIGINT,
  created_at     BIGINT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_enrollments_hash ON theauth_device_enrollments (token_hash);

CREATE INDEX IF NOT EXISTS theauth_device_enrollments_owner ON theauth_device_enrollments (owner_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0010', 'devices', 'a63491dbc039b1791b3418ac8679219e2d9729a9c9966de715a860f79334260a', NOW());
