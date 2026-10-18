import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "audit" domain. Columns added by migrations 0001 to 0003 (cache_hit, decision_code, recorded_at_ms) are not here: the migrations add them. */
export function auditDdl(t: DdlTypes): TaggedStatement[] {
	const { isMysql, ts, json, ifne } = t;

	return [
		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} theauth_audit_logs (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES theauth_agents(id),
  user_id      TEXT    NOT NULL REFERENCES theauth_users(id),
  action       TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  parameters   ${json},
  result       TEXT    NOT NULL,
  reason       TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  timestamp    ${ts}   NOT NULL,
  chain_seq    INTEGER,
  prev_hash    TEXT,
  hash         TEXT,
  hash_version INTEGER,
  subject_id   TEXT,
  actor_id     TEXT,
  policy_version TEXT,
  approver_id  TEXT,
  delegation_chain ${json},
  input_provenance ${json},
  id_pseudonyms ${json}
)`,
		},

		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} theauth_audit_secrets (
  id         TEXT  NOT NULL PRIMARY KEY,
  secret     TEXT  NOT NULL,
  created_at ${ts} NOT NULL
)`,
		},

		// Fork guard for the audit hash chain: two writers racing for the same
		// (agent, seq) slot cannot both win. NULL seq rows (legacy) never collide.
		// MySQL has no CREATE INDEX IF NOT EXISTS: the runner tolerates "duplicate key name".
		{
			feature: "audit",
			sql: isMysql
				? "CREATE UNIQUE INDEX theauth_audit_logs_chain ON theauth_audit_logs (agent_id(191), chain_seq)"
				: `CREATE UNIQUE INDEX ${ifne} theauth_audit_logs_chain
  ON theauth_audit_logs (agent_id, chain_seq)`,
		},

		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} theauth_cost_events (
  id                  TEXT    NOT NULL PRIMARY KEY,
  agent_id            TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  tool                TEXT    NOT NULL,
  input_tokens        INTEGER,
  output_tokens       INTEGER,
  cost_micros         INTEGER NOT NULL,
  currency            TEXT    NOT NULL DEFAULT 'USD',
  metadata            ${json},
  delegation_chain_id TEXT,
  recorded_at         ${ts}   NOT NULL
)`,
		},

		{
			feature: "audit",
			sql: `CREATE INDEX ${ifne} theauth_cost_events_agent_recorded
  ON theauth_cost_events (agent_id, recorded_at DESC)`,
		},

		{
			feature: "audit",
			sql: `CREATE INDEX ${ifne} theauth_cost_events_chain_id
  ON theauth_cost_events (delegation_chain_id)`,
		},

		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} theauth_stream_events (
  id        TEXT    NOT NULL PRIMARY KEY,
  type      TEXT    NOT NULL,
  timestamp ${ts}   NOT NULL,
  data      ${json} NOT NULL,
  agent_id  TEXT,
  user_id   TEXT
)`,
		},

		{
			feature: "audit",
			sql: `CREATE INDEX ${ifne} theauth_stream_events_timestamp
  ON theauth_stream_events (timestamp DESC)`,
		},

		{
			feature: "audit",
			sql: `CREATE INDEX ${ifne} theauth_stream_events_type_timestamp
  ON theauth_stream_events (type, timestamp DESC)`,
		},
	];
}
