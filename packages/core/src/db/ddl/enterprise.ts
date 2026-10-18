import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "enterprise" domain. */
export function enterpriseDdl(t: DdlTypes): TaggedStatement[] {
	const { isPostgres, ts, tsNull, json, bool, ifne, vc } = t;

	return [
		{
			feature: "tokenVault",
			sql: `CREATE TABLE ${ifne} theauth_vault_connections (
  id                  TEXT NOT NULL PRIMARY KEY,
  user_id             ${vc} NOT NULL,
  tenant_id           ${vc} NOT NULL DEFAULT '',
  provider            ${vc} NOT NULL,
  provider_account_id TEXT NOT NULL,
  access_token_enc    TEXT NOT NULL,
  refresh_token_enc   TEXT,
  key_id              TEXT NOT NULL,
  scopes              ${json} NOT NULL,
  status              TEXT NOT NULL DEFAULT 'active',
  expires_at          ${tsNull},
  created_at          ${ts} NOT NULL,
  updated_at          ${ts} NOT NULL,
  UNIQUE (user_id, tenant_id, provider)
)`,
		},

		{
			feature: "tokenVault",
			sql: `CREATE TABLE ${ifne} theauth_vault_consents (
  id                  TEXT NOT NULL PRIMARY KEY,
  user_id             TEXT NOT NULL,
  agent_id            TEXT NOT NULL,
  tenant_id           TEXT NOT NULL DEFAULT '',
  provider            TEXT NOT NULL,
  scopes              ${json} NOT NULL,
  delegation_chain_id TEXT,
  expires_at          ${tsNull},
  revoked_at          ${tsNull},
  created_at          ${ts} NOT NULL
)`,
		},

		{
			feature: "sharedSignals",
			sql: `CREATE TABLE ${ifne} theauth_ssf_streams (
  id                        TEXT NOT NULL PRIMARY KEY,
  owner                     TEXT NOT NULL,
  aud                       ${json} NOT NULL,
  events_requested          ${json} NOT NULL,
  events_delivered          ${json} NOT NULL,
  delivery_method           TEXT NOT NULL,
  endpoint_url              TEXT,
  authorization_header      TEXT,
  status                    TEXT NOT NULL DEFAULT 'enabled',
  status_reason             TEXT,
  subject_mode              TEXT NOT NULL DEFAULT 'all',
  description               TEXT,
  min_verification_interval INTEGER,
  last_verified_at          ${tsNull},
  created_at                ${ts} NOT NULL,
  updated_at                ${ts} NOT NULL
)`,
		},

		{
			feature: "sharedSignals",
			sql: `CREATE TABLE ${ifne} theauth_ssf_subjects (
  id               TEXT NOT NULL PRIMARY KEY,
  stream_id        ${vc} NOT NULL,
  subject_key_hash ${vc} NOT NULL,
  subject          ${json} NOT NULL,
  verified         INTEGER NOT NULL DEFAULT 1,
  created_at       ${ts} NOT NULL,
  UNIQUE (stream_id, subject_key_hash)
)`,
		},

		{
			feature: "sharedSignals",
			sql: `CREATE TABLE ${ifne} theauth_ssf_outbox (
  jti             ${vc} NOT NULL PRIMARY KEY,
  stream_id       ${vc} NOT NULL,
  jwt             TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at ${ts} NOT NULL,
  last_error      TEXT,
  created_at      ${ts} NOT NULL
)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} theauth_oidc_clients (
  id                          TEXT    NOT NULL PRIMARY KEY,
  client_id                   TEXT    NOT NULL UNIQUE,
  client_secret_hash          TEXT    NOT NULL,
  client_name                 TEXT    NOT NULL,
  redirect_uris               ${json} NOT NULL,
  grant_types                 ${json} NOT NULL,
  response_types              ${json} NOT NULL,
  scopes                      ${json} NOT NULL,
  token_endpoint_auth_method  TEXT    NOT NULL DEFAULT 'client_secret_post',
  created_at                  ${ts}   NOT NULL,
  updated_at                  ${ts}   NOT NULL
)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} theauth_oidc_auth_codes (
  id                     TEXT    NOT NULL PRIMARY KEY,
  code_hash              TEXT    NOT NULL UNIQUE,
  client_id              TEXT    NOT NULL,
  user_id                TEXT    NOT NULL,
  redirect_uri           TEXT    NOT NULL,
  scopes                 TEXT    NOT NULL,
  nonce                  TEXT,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  used                   ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  expires_at             ${ts}   NOT NULL,
  created_at             ${ts}   NOT NULL
)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} theauth_oidc_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  client_id   TEXT    NOT NULL,
  user_id     TEXT    NOT NULL,
  scopes      TEXT    NOT NULL,
  revoked     ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  expires_at  ${ts}   NOT NULL,
  created_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} theauth_oidc_logout_clients (
  client_id                   ${vc} NOT NULL PRIMARY KEY,
  post_logout_redirect_uris   ${json} NOT NULL,
  backchannel_logout_uri      TEXT,
  updated_at                  ${ts}   NOT NULL
)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} theauth_oidc_sessions (
  id          ${vc} NOT NULL PRIMARY KEY,
  sid         ${vc} NOT NULL,
  session_id  ${vc},
  user_id     ${vc} NOT NULL,
  client_id   ${vc} NOT NULL,
  code_hash   ${vc},
  created_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE INDEX ${ifne} theauth_oidc_sessions_sid
  ON theauth_oidc_sessions (sid)`,
		},

		{
			feature: "oidcProvider",
			sql: `CREATE INDEX ${ifne} theauth_oidc_sessions_session
  ON theauth_oidc_sessions (session_id)`,
		},

		{
			feature: "rebac",
			sql: `CREATE TABLE ${ifne} theauth_rebac_resources (
  id          TEXT NOT NULL PRIMARY KEY,
  type        TEXT NOT NULL,
  parent_id   TEXT,
  parent_type TEXT,
  created_at  ${ts} NOT NULL
)`,
		},

		{
			feature: "rebac",
			sql: `CREATE INDEX ${ifne} theauth_rebac_resources_parent
  ON theauth_rebac_resources (parent_id, parent_type)`,
		},

		{
			feature: "rebac",
			sql: `CREATE TABLE ${ifne} theauth_rebac_relationships (
  id           TEXT NOT NULL PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id   TEXT NOT NULL,
  relation     TEXT NOT NULL,
  object_type  TEXT NOT NULL,
  object_id    TEXT NOT NULL,
  created_at   ${ts} NOT NULL
)`,
		},

		{
			feature: "rebac",
			sql: `CREATE INDEX ${ifne} theauth_rebac_relationships_subject
  ON theauth_rebac_relationships (subject_type, subject_id)`,
		},

		{
			feature: "rebac",
			sql: `CREATE INDEX ${ifne} theauth_rebac_relationships_object
  ON theauth_rebac_relationships (object_type, object_id)`,
		},

		{
			feature: "rebac",
			sql: `CREATE UNIQUE INDEX ${ifne} theauth_rebac_relationships_tuple
  ON theauth_rebac_relationships (subject_type, subject_id, relation, object_type, object_id)`,
		},

		{
			feature: "federation",
			sql: `CREATE TABLE ${ifne} theauth_federation_instances (
  id            TEXT NOT NULL PRIMARY KEY,
  instance_id   TEXT NOT NULL UNIQUE,
  instance_url  TEXT NOT NULL,
  public_key_jwk TEXT,
  trust_level   TEXT NOT NULL DEFAULT 'verify-only',
  discovered_at ${tsNull},
  created_at    ${ts} NOT NULL,
  updated_at    ${ts} NOT NULL
)`,
		},

		{
			feature: "federation",
			sql: `CREATE TABLE ${ifne} theauth_federation_tokens (
  id                  TEXT    NOT NULL PRIMARY KEY,
  token_jti           TEXT    NOT NULL UNIQUE,
  agent_id            TEXT    NOT NULL,
  source_instance_id  TEXT    NOT NULL,
  target_instance_id  TEXT,
  direction           TEXT    NOT NULL,
  permissions         ${json} NOT NULL,
  trust_score         INTEGER,
  expires_at          ${ts}   NOT NULL,
  created_at          ${ts}   NOT NULL
)`,
		},

		{
			feature: "federation",
			sql: `CREATE INDEX ${ifne} theauth_federation_tokens_agent
  ON theauth_federation_tokens (agent_id)`,
		},

		{
			feature: "federation",
			sql: `CREATE INDEX ${ifne} theauth_federation_tokens_source
  ON theauth_federation_tokens (source_instance_id)`,
		},
	];
}
