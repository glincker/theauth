/* Migration 0010: devices */

CREATE TABLE IF NOT EXISTS theauth_devices (
  id             VARCHAR(191) NOT NULL PRIMARY KEY,
  agent_id       VARCHAR(191) NOT NULL,
  owner_id       VARCHAR(191) NOT NULL,
  tenant_id      VARCHAR(191),
  name           TEXT NOT NULL,
  kind           TEXT,
  hardware_id    VARCHAR(191),
  status         VARCHAR(16) NOT NULL,
  device_groups  JSON NOT NULL,
  metadata       JSON,
  enrollment_id  VARCHAR(191),
  attestation    JSON,
  expires_at     BIGINT,
  last_seen_at   BIGINT,
  last_seen_ip   TEXT,
  status_reason  TEXT,
  created_at     BIGINT NOT NULL,
  updated_at     BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE UNIQUE INDEX theauth_devices_agent ON theauth_devices (agent_id);

CREATE UNIQUE INDEX theauth_devices_owner_hw ON theauth_devices (owner_id, hardware_id);

CREATE INDEX theauth_devices_owner_status ON theauth_devices (owner_id, status);

CREATE INDEX theauth_devices_enrollment ON theauth_devices (enrollment_id);

CREATE TABLE IF NOT EXISTS theauth_device_credentials (
  id             VARCHAR(191) NOT NULL PRIMARY KEY,
  device_id      VARCHAR(191) NOT NULL,
  kind           VARCHAR(16) NOT NULL,
  lookup         VARCHAR(191) NOT NULL,
  secret_hash    TEXT,
  public_jwk     JSON,
  status         VARCHAR(16) NOT NULL,
  expires_at     BIGINT,
  last_used_at   BIGINT,
  created_at     BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE UNIQUE INDEX theauth_device_credentials_lookup ON theauth_device_credentials (kind, lookup);

CREATE INDEX theauth_device_credentials_device ON theauth_device_credentials (device_id);

CREATE TABLE IF NOT EXISTS theauth_device_enrollments (
  id             VARCHAR(191) NOT NULL PRIMARY KEY,
  kind           VARCHAR(16) NOT NULL,
  token_hash     VARCHAR(191) NOT NULL,
  owner_id       VARCHAR(191) NOT NULL,
  tenant_id      VARCHAR(191),
  template       JSON NOT NULL,
  max_uses       INTEGER NOT NULL,
  uses           INTEGER NOT NULL,
  expires_at     BIGINT NOT NULL,
  revoked_at     BIGINT,
  created_at     BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE UNIQUE INDEX theauth_device_enrollments_hash ON theauth_device_enrollments (token_hash);

CREATE INDEX theauth_device_enrollments_owner ON theauth_device_enrollments (owner_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0010', 'devices', '0fc1c9ce19cfd796e624d4c401827e3d8308e38757930d66dec04a71d18e4e89', UTC_TIMESTAMP(3));
