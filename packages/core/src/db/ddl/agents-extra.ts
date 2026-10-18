import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "agents-extra" domain. */
export function agentsExtraDdl(t: DdlTypes): TaggedStatement[] {
	const { ts, tsNull, json, ifne } = t;

	return [
		{
			feature: "budget",
			sql: `CREATE TABLE ${ifne} theauth_budget_policies (
  id            TEXT    NOT NULL PRIMARY KEY,
  agent_id      TEXT    REFERENCES theauth_agents(id) ON DELETE CASCADE,
  user_id       TEXT    REFERENCES theauth_users(id),
  tenant_id     TEXT    REFERENCES theauth_tenants(id),
  limits        ${json} NOT NULL,
  current_usage ${json} NOT NULL,
  action        TEXT    NOT NULL DEFAULT 'warn',
  status        TEXT    NOT NULL DEFAULT 'active',
  created_at    ${ts}   NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_agent_cards (
  id                TEXT    NOT NULL PRIMARY KEY,
  agent_id          TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  name              TEXT    NOT NULL,
  description       TEXT,
  version           TEXT    NOT NULL,
  protocols         ${json} NOT NULL,
  capabilities      ${json} NOT NULL,
  auth_requirements ${json} NOT NULL,
  endpoint          TEXT,
  metadata          ${json},
  created_at        ${ts}   NOT NULL,
  updated_at        ${ts}   NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_approval_requests (
  id            TEXT NOT NULL PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES theauth_users(id),
  action        TEXT NOT NULL,
  resource      TEXT NOT NULL,
  arguments     ${json},
  status        TEXT NOT NULL DEFAULT 'pending',
  expires_at    ${ts} NOT NULL,
  responded_at  ${tsNull},
  responded_by  TEXT,
  consumed_at   ${tsNull},
  created_at    ${ts} NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_trust_scores (
  agent_id    TEXT    NOT NULL PRIMARY KEY REFERENCES theauth_agents(id) ON DELETE CASCADE,
  score       INTEGER NOT NULL,
  level       TEXT    NOT NULL,
  factors     ${json} NOT NULL,
  computed_at ${ts}   NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_agent_registration_tokens (
  id                TEXT NOT NULL PRIMARY KEY,
  token_hash        TEXT NOT NULL UNIQUE,
  token_prefix      TEXT NOT NULL,
  label             TEXT,
  owner_id          TEXT NOT NULL REFERENCES theauth_users(id),
  tenant_id         TEXT,
  agent_type        TEXT NOT NULL DEFAULT 'autonomous',
  permissions       ${json} NOT NULL,
  name_prefix       TEXT,
  agent_ttl_seconds INTEGER,
  created_by        TEXT,
  expires_at        ${ts} NOT NULL,
  revoked_at        ${tsNull},
  used_at           ${tsNull},
  claim_nonce       TEXT,
  agent_id          TEXT,
  created_at        ${ts} NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_agent_dids (
  agent_id       TEXT NOT NULL PRIMARY KEY REFERENCES theauth_agents(id) ON DELETE CASCADE,
  did            TEXT NOT NULL UNIQUE,
  method         TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  did_document   TEXT NOT NULL,
  created_at     ${ts} NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_ephemeral_sessions (
  id             TEXT    NOT NULL PRIMARY KEY,
  agent_id       TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  owner_id       TEXT    NOT NULL REFERENCES theauth_users(id),
  token_hash     TEXT    NOT NULL UNIQUE,
  expires_at     ${ts}   NOT NULL,
  max_actions    INTEGER,
  actions_used   INTEGER NOT NULL DEFAULT 0,
  status         TEXT    NOT NULL DEFAULT 'active',
  audit_group_id TEXT    NOT NULL,
  created_at     ${ts}   NOT NULL,
  updated_at     ${ts}   NOT NULL
)`,
		},

		{
			feature: "agent",
			sql: `CREATE INDEX ${ifne} theauth_ephemeral_sessions_owner_status
  ON theauth_ephemeral_sessions (owner_id, status)`,
		},

		{
			feature: "agent",
			sql: `CREATE INDEX ${ifne} theauth_ephemeral_sessions_expires_at
  ON theauth_ephemeral_sessions (expires_at)`,
		},
	];
}
