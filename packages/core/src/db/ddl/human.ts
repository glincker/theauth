import type { DdlTypes, TaggedStatement } from "./types.js";

/** Baseline DDL for the "human" domain. */
export function humanDdl(t: DdlTypes): TaggedStatement[] {
	const { isPostgres, ts, tsNull, big, json, bool, ifne } = t;

	return [
		{
			feature: "passkey",
			sql: `CREATE TABLE ${ifne} theauth_passkey_credentials (
  id            TEXT    NOT NULL PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES theauth_users(id),
  credential_id TEXT    NOT NULL UNIQUE,
  public_key    TEXT    NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,
  device_name   TEXT,
  transports    TEXT,
  created_at    ${ts}   NOT NULL,
  last_used_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "passkey",
			sql: `CREATE TABLE ${ifne} theauth_passkey_challenges (
  id         TEXT NOT NULL PRIMARY KEY,
  challenge  TEXT NOT NULL UNIQUE,
  user_id    TEXT,
  type       TEXT NOT NULL,
  expires_at ${ts} NOT NULL,
  created_at ${ts} NOT NULL
)`,
		},

		{
			feature: "oneTimeToken",
			sql: `CREATE TABLE ${ifne} theauth_one_time_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  purpose     TEXT    NOT NULL,
  identifier  TEXT    NOT NULL,
  metadata    ${json},
  used        ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  expires_at  ${ts}   NOT NULL,
  created_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "magicLink",
			sql: `CREATE TABLE ${ifne} theauth_magic_links (
  id         TEXT    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  token      TEXT    NOT NULL UNIQUE,
  expires_at ${ts}   NOT NULL,
  used       ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  created_at ${ts}   NOT NULL
)`,
		},

		{
			feature: "emailOtp",
			sql: `CREATE TABLE ${ifne} theauth_email_otps (
  id         TEXT    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  code_hash  TEXT    NOT NULL,
  expires_at ${ts}   NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at ${ts}   NOT NULL
)`,
		},

		{
			feature: "totp",
			sql: `CREATE TABLE ${ifne} theauth_totp (
  user_id      TEXT    NOT NULL PRIMARY KEY REFERENCES theauth_users(id),
  secret       TEXT    NOT NULL,
  enabled      ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  backup_codes ${json} NOT NULL,
  created_at   ${ts}   NOT NULL,
  updated_at   ${ts}   NOT NULL
)`,
		},

		{
			feature: "sso",
			sql: `CREATE TABLE ${ifne} theauth_sso_connections (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL,
  provider_id TEXT    NOT NULL,
  type        TEXT    NOT NULL,
  domain      TEXT    NOT NULL UNIQUE,
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "apiKey",
			sql: `CREATE TABLE ${ifne} theauth_api_keys (
  id           TEXT    NOT NULL PRIMARY KEY,
  user_id      TEXT    NOT NULL REFERENCES theauth_users(id),
  name         TEXT    NOT NULL,
  key_hash     TEXT    NOT NULL,
  key_prefix   TEXT    NOT NULL,
  permissions  ${json} NOT NULL,
  expires_at   ${tsNull},
  last_used_at ${tsNull},
  created_at   ${ts}   NOT NULL
)`,
		},

		{
			feature: "username",
			sql: `CREATE TABLE ${ifne} theauth_username_accounts (
  id            TEXT NOT NULL PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    ${ts} NOT NULL,
  updated_at    ${ts} NOT NULL
)`,
		},

		{
			feature: "phone",
			sql: `CREATE TABLE ${ifne} theauth_phone_verifications (
  id           TEXT    NOT NULL PRIMARY KEY,
  phone_number TEXT    NOT NULL,
  code_hash    TEXT    NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  expires_at   ${ts}   NOT NULL,
  created_at   ${ts}   NOT NULL
)`,
		},

		{
			feature: "device",
			sql: `CREATE TABLE ${ifne} theauth_trusted_devices (
  id          TEXT NOT NULL PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  label       TEXT NOT NULL,
  trusted_at  ${ts} NOT NULL,
  expires_at  ${ts} NOT NULL
)`,
		},

		{
			feature: "loginHistory",
			sql: `CREATE TABLE ${ifne} theauth_login_history (
  id         TEXT NOT NULL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  method     TEXT NOT NULL,
  ip         TEXT,
  user_agent TEXT,
  timestamp  ${ts} NOT NULL
)`,
		},

		{
			feature: "loginHistory",
			sql: `CREATE INDEX ${ifne} theauth_login_history_user_ts
  ON theauth_login_history (user_id, timestamp DESC)`,
		},

		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} theauth_jwt_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  user_id     TEXT    NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  used        ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  expires_at  ${ts}   NOT NULL,
  created_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "jwt",
			sql: `CREATE INDEX ${ifne} theauth_jwt_refresh_tokens_user_id
  ON theauth_jwt_refresh_tokens (user_id)`,
		},

		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} theauth_refresh_token_families (
  id                   TEXT    NOT NULL PRIMARY KEY,
  user_id              TEXT    NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  absolute_expires_at  ${ts}   NOT NULL,
  revoked              ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  created_at           ${ts}   NOT NULL
)`,
		},

		{
			feature: "jwt",
			sql: `CREATE INDEX ${ifne} theauth_refresh_token_families_user_id
  ON theauth_refresh_token_families (user_id)`,
		},

		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} theauth_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  family_id   TEXT    NOT NULL REFERENCES theauth_refresh_token_families(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  used        ${big} NOT NULL DEFAULT 0,
  expires_at  ${ts}   NOT NULL,
  created_at  ${ts}   NOT NULL
)`,
		},

		{
			feature: "jwt",
			sql: `CREATE INDEX ${ifne} theauth_refresh_tokens_family_id
  ON theauth_refresh_tokens (family_id)`,
		},
	];
}
