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
  device_groups  TEXT NOT NULL,
  metadata       TEXT,
  enrollment_id  TEXT,
  attestation    TEXT,
  expires_at     INTEGER,
  last_seen_at   INTEGER,
  last_seen_ip   TEXT,
  status_reason  TEXT,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
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
  public_jwk     TEXT,
  status         TEXT NOT NULL,
  expires_at     INTEGER,
  last_used_at   INTEGER,
  created_at     INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_credentials_lookup ON theauth_device_credentials (kind, lookup);

CREATE INDEX IF NOT EXISTS theauth_device_credentials_device ON theauth_device_credentials (device_id);

CREATE TABLE IF NOT EXISTS theauth_device_enrollments (
  id             TEXT NOT NULL PRIMARY KEY,
  kind           TEXT NOT NULL,
  token_hash     TEXT NOT NULL,
  owner_id       TEXT NOT NULL,
  tenant_id      TEXT,
  template       TEXT NOT NULL,
  max_uses       INTEGER NOT NULL,
  uses           INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  created_at     INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_device_enrollments_hash ON theauth_device_enrollments (token_hash);

CREATE INDEX IF NOT EXISTS theauth_device_enrollments_owner ON theauth_device_enrollments (owner_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0010', 'devices', '67101665735cb7c46ce81bc232fe82948c69d2fe56ad4d0f76a8944f35885209', CAST(strftime('%s', 'now') AS INTEGER));
