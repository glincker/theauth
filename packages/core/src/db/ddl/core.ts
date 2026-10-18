import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "core" domain. `theauth_permissions.relation` is added by migration 0001. */
export function coreDdl(t: DdlTypes): TaggedStatement[] {
	const { isPostgres, isMysql, ts, tsNull, json, bool, ifne } = t;

	return [
		{
			feature: "core",
			sql: `CREATE TABLE ${ifne} theauth_users (
  id                   TEXT        NOT NULL PRIMARY KEY,
  email                TEXT        NOT NULL UNIQUE,
  username             TEXT        UNIQUE,
  name                 TEXT,
  external_id          TEXT,
  external_provider    TEXT,
  metadata             ${json},
  banned               ${bool}     NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  ban_reason           TEXT,
  ban_expires_at       ${tsNull},
  force_password_reset         ${bool}     NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  email_verified               ${bool}     NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  stripe_customer_id           TEXT        UNIQUE,
  stripe_subscription_id       TEXT,
  stripe_subscription_status   TEXT,
  stripe_price_id              TEXT,
  stripe_current_period_end    ${tsNull},
  stripe_cancel_at_period_end  ${bool}     NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  polar_customer_id            TEXT        UNIQUE,
  polar_subscription_id        TEXT,
  polar_subscription_status    TEXT,
  polar_product_id             TEXT,
  polar_current_period_end     ${tsNull},
  polar_cancel_at_period_end   ${bool}     NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  created_at                   ${ts}       NOT NULL,
  updated_at                   ${ts}       NOT NULL
)`,
		},

		{
			feature: "tenant",
			sql: `CREATE TABLE ${ifne} theauth_tenants (
  id         TEXT NOT NULL PRIMARY KEY,
  name       TEXT NOT NULL,
  slug       TEXT NOT NULL UNIQUE,
  settings   ${json},
  status     TEXT NOT NULL DEFAULT 'active',
  created_at ${ts} NOT NULL,
  updated_at ${ts} NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_agents (
  id              TEXT  NOT NULL PRIMARY KEY,
  owner_id        TEXT  NOT NULL REFERENCES theauth_users(id),
  tenant_id       TEXT  REFERENCES theauth_tenants(id),
  name            TEXT  NOT NULL,
  type            TEXT  NOT NULL,
  status          TEXT  NOT NULL DEFAULT 'active',
  token_hash      TEXT  NOT NULL,
  token_prefix    TEXT  NOT NULL,
  expires_at      ${tsNull},
  last_active_at  ${tsNull},
  metadata        ${json},
  created_at      ${ts} NOT NULL,
  updated_at      ${ts} NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_permissions (
  id          TEXT  NOT NULL PRIMARY KEY,
  agent_id    TEXT  NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  resource    TEXT  NOT NULL,
  actions     ${json} NOT NULL,
  constraints ${json},
  created_at  ${ts} NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_delegation_chains (
  id            TEXT    NOT NULL PRIMARY KEY,
  from_agent_id TEXT    NOT NULL REFERENCES theauth_agents(id),
  to_agent_id   TEXT    NOT NULL REFERENCES theauth_agents(id),
  permissions   ${json} NOT NULL,
  depth         INTEGER NOT NULL DEFAULT 1,
  max_depth     INTEGER NOT NULL DEFAULT 3,
  status        TEXT    NOT NULL DEFAULT 'active',
  expires_at    ${ts}   NOT NULL,
  created_at    ${ts}   NOT NULL
)`,
		},

		{
			feature: "rateLimit",
			sql: `CREATE TABLE ${ifne} theauth_rate_limits (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  resource     TEXT    NOT NULL,
  window_start ${ts}   NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0
)`,
		},

		{
			feature: "mcp",
			sql: `CREATE TABLE ${ifne} theauth_mcp_servers (
  id               TEXT    NOT NULL PRIMARY KEY,
  name             TEXT    NOT NULL,
  endpoint         TEXT    NOT NULL UNIQUE,
  tools            ${json} NOT NULL,
  auth_required    ${bool} NOT NULL DEFAULT ${isPostgres ? "TRUE" : "1"},
  rate_limit_rpm   INTEGER,
  status           TEXT    NOT NULL DEFAULT 'active',
  created_at       ${ts}   NOT NULL,
  updated_at       ${ts}   NOT NULL
)`,
		},

		{
			feature: "session",
			sql: `CREATE TABLE ${ifne} theauth_sessions (
  id         TEXT    NOT NULL PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES theauth_users(id),
  expires_at ${ts}   NOT NULL,
  metadata   ${json},
  created_at ${ts}   NOT NULL
)`,
		},

		{
			feature: "secondaryStorage",
			sql: `CREATE TABLE ${ifne} theauth_secondary_storage (
  storage_key ${isMysql ? "VARCHAR(255)" : "TEXT"} NOT NULL PRIMARY KEY,
  value       TEXT,
  counter     INTEGER,
  expires_at  BIGINT
)`,
		},
	];
}
