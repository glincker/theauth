/* Migration 0003: epoch-timestamps */

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0003', 'epoch-timestamps', 'eb590993ead017129ddc183560412bd0d6c9e44972b86921c37620998b32b841', CAST(strftime('%s', 'now') AS INTEGER));
