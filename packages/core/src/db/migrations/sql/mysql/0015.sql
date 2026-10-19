/* Migration 0015: device-app-attest-counter */

ALTER TABLE theauth_devices ADD COLUMN app_attest_counter BIGINT NOT NULL DEFAULT 0;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0015', 'device-app-attest-counter', 'f2bb3d928649e24b9c3ba564cb4b687abdd49ac3693c5f11aee87bbe1afef098', UTC_TIMESTAMP(3));
