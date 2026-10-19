/* Migration 0015: device-app-attest-counter */

ALTER TABLE theauth_devices ADD COLUMN IF NOT EXISTS app_attest_counter BIGINT NOT NULL DEFAULT 0;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0015', 'device-app-attest-counter', 'bafddeb1e72e359a5e3548bb50b2c0956560350e545c92d35acce84074ddae9f', NOW());
