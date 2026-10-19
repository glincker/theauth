import { MYSQL_TABLE_OPTIONS } from "../ddl/mysql.js";
import { ddlTypes } from "../ddl/types.js";
import type { Dialect, Migration } from "../migrate/types.js";

/**
 * IoT device registry: `theauth_devices` (one row per device, backed by an agent of type `device`), `theauth_device_credentials` (PSK hashes, JWK thumbprints, X.509 thumbprints) and `theauth_device_enrollments` (claim codes and bulk tokens, hashed).
 *
 * Additive only. Needs the agent tables (`requires`). Times are epoch seconds in plain integer columns.
 */
function statements(dialect: Dialect): string[] {
	const t = ddlTypes(dialect);
	const my = t.isMysql;
	const opts = my ? ` ${MYSQL_TABLE_OPTIONS}` : "";
	const small = my ? "VARCHAR(16)" : "TEXT";
	const idx = (name: string, table: string, cols: string, unique = false): string =>
		my
			? `CREATE ${unique ? "UNIQUE " : ""}INDEX ${name} ON ${table} (${cols})`
			: `CREATE ${unique ? "UNIQUE " : ""}INDEX IF NOT EXISTS ${name} ON ${table} (${cols})`;
	return [
		`CREATE TABLE IF NOT EXISTS theauth_devices (
  id             ${t.vc} NOT NULL PRIMARY KEY,
  agent_id       ${t.vc} NOT NULL,
  owner_id       ${t.vc} NOT NULL,
  tenant_id      ${t.vc},
  name           TEXT NOT NULL,
  kind           TEXT,
  hardware_id    ${t.vc},
  status         ${small} NOT NULL,
  device_groups  ${t.json} NOT NULL,
  metadata       ${t.json},
  enrollment_id  ${t.vc},
  attestation    ${t.json},
  expires_at     ${t.big},
  last_seen_at   ${t.big},
  last_seen_ip   TEXT,
  status_reason  TEXT,
  created_at     ${t.big} NOT NULL,
  updated_at     ${t.big} NOT NULL
)${opts}`,
		idx("theauth_devices_agent", "theauth_devices", "agent_id", true),
		idx("theauth_devices_owner_hw", "theauth_devices", "owner_id, hardware_id", true),
		idx("theauth_devices_owner_status", "theauth_devices", "owner_id, status"),
		idx("theauth_devices_enrollment", "theauth_devices", "enrollment_id"),
		`CREATE TABLE IF NOT EXISTS theauth_device_credentials (
  id             ${t.vc} NOT NULL PRIMARY KEY,
  device_id      ${t.vc} NOT NULL,
  kind           ${small} NOT NULL,
  lookup         ${t.vc} NOT NULL,
  secret_hash    TEXT,
  public_jwk     ${t.json},
  status         ${small} NOT NULL,
  expires_at     ${t.big},
  last_used_at   ${t.big},
  created_at     ${t.big} NOT NULL
)${opts}`,
		idx("theauth_device_credentials_lookup", "theauth_device_credentials", "kind, lookup", true),
		idx("theauth_device_credentials_device", "theauth_device_credentials", "device_id"),
		`CREATE TABLE IF NOT EXISTS theauth_device_enrollments (
  id             ${t.vc} NOT NULL PRIMARY KEY,
  kind           ${small} NOT NULL,
  token_hash     ${t.vc} NOT NULL,
  owner_id       ${t.vc} NOT NULL,
  tenant_id      ${t.vc},
  template       ${t.json} NOT NULL,
  max_uses       INTEGER NOT NULL,
  uses           INTEGER NOT NULL,
  expires_at     ${t.big} NOT NULL,
  revoked_at     ${t.big},
  created_at     ${t.big} NOT NULL
)${opts}`,
		idx("theauth_device_enrollments_hash", "theauth_device_enrollments", "token_hash", true),
		idx("theauth_device_enrollments_owner", "theauth_device_enrollments", "owner_id"),
	];
}

export const devicesMigration: Migration = {
	id: "0010",
	name: "devices",
	requires: ["agent"],
	up: {
		sqlite: statements("sqlite"),
		postgres: statements("postgres"),
		mysql: statements("mysql"),
	},
};
