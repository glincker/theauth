import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "oauth" domain. */
export function oauthDdl(t: DdlTypes): TaggedStatement[] {
	const { isPostgres, ts, tsNull, json, bool, ifne } = t;

	return [
		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} theauth_oauth_clients (
  id                          TEXT    NOT NULL PRIMARY KEY,
  client_id                   TEXT    NOT NULL UNIQUE,
  client_secret               TEXT,
  client_name                 TEXT,
  client_uri                  TEXT,
  redirect_uris               ${json} NOT NULL,
  grant_types                 ${json} NOT NULL,
  response_types              ${json} NOT NULL,
  token_endpoint_auth_method  TEXT    NOT NULL DEFAULT 'client_secret_basic',
  type                        TEXT    NOT NULL DEFAULT 'confidential',
  disabled                    ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  metadata                    ${json},
  created_at                  ${ts}   NOT NULL,
  updated_at                  ${ts}   NOT NULL
)`,
		},

		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} theauth_oauth_access_tokens (
  id                        TEXT NOT NULL PRIMARY KEY,
  access_token              TEXT NOT NULL UNIQUE,
  refresh_token             TEXT UNIQUE,
  client_id                 TEXT NOT NULL REFERENCES theauth_oauth_clients(client_id),
  user_id                   TEXT NOT NULL REFERENCES theauth_users(id),
  scopes                    TEXT NOT NULL,
  resource                  TEXT,
  access_token_expires_at   ${ts} NOT NULL,
  refresh_token_expires_at  ${tsNull},
  created_at                ${ts} NOT NULL
)`,
		},

		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} theauth_oauth_authorization_codes (
  id                     TEXT NOT NULL PRIMARY KEY,
  code                   TEXT NOT NULL UNIQUE,
  client_id              TEXT NOT NULL REFERENCES theauth_oauth_clients(client_id),
  user_id                TEXT NOT NULL REFERENCES theauth_users(id),
  redirect_uri           TEXT NOT NULL,
  scopes                 TEXT NOT NULL,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  resource               TEXT,
  expires_at             ${ts} NOT NULL,
  created_at             ${ts} NOT NULL
)`,
		},

		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} theauth_oauth_accounts (
  id                   TEXT NOT NULL PRIMARY KEY,
  user_id              TEXT NOT NULL,
  provider             TEXT NOT NULL,
  provider_account_id  TEXT NOT NULL,
  access_token         TEXT NOT NULL,
  refresh_token        TEXT,
  expires_at           ${tsNull},
  created_at           ${ts} NOT NULL,
  updated_at           ${ts} NOT NULL
)`,
		},

		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} theauth_oauth_states (
  state          TEXT NOT NULL PRIMARY KEY,
  code_verifier  TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  provider       TEXT NOT NULL,
  expires_at     ${ts} NOT NULL,
  created_at     ${ts} NOT NULL
)`,
		},
	];
}
