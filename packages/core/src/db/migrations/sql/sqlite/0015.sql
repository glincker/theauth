/* Migration 0015: device-app-attest-counter */

ALTER TABLE theauth_devices ADD COLUMN app_attest_counter INTEGER NOT NULL DEFAULT 0;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0015', 'device-app-attest-counter', '2a2286f6d486c7ba9b868e5d85684701a5734061425f4b7848c7dd3b4aef19b7', CAST(strftime('%s', 'now') AS INTEGER));
