import type { KavachConfig } from "../types.js";
import type { Database, DatabaseConfig } from "./database.js";

// ──────────────────────────────────────────────────────────────────────────────
// Feature flag types
// ──────────────────────────────────────────────────────────────────────────────

interface EnabledFeatures {
	core: true; // always
	session: boolean;
	agent: boolean;
	audit: boolean;
	oauth: boolean;
	tenant: boolean;
	mcp: boolean;
	org: boolean;
	rateLimit: boolean;
	budget: boolean;
	magicLink: boolean;
	emailOtp: boolean;
	totp: boolean;
	passkey: boolean;
	sso: boolean;
	apiKey: boolean;
	username: boolean;
	phone: boolean;
	device: boolean;
	oneTimeToken: boolean;
	loginHistory: boolean;
	oidcProvider: boolean;
	jwt: boolean;
	rebac: boolean;
	federation: boolean;
}

const ALL_FEATURES_ENABLED: EnabledFeatures = {
	core: true,
	session: true,
	agent: true,
	audit: true,
	oauth: true,
	tenant: true,
	mcp: true,
	org: true,
	rateLimit: true,
	budget: true,
	magicLink: true,
	emailOtp: true,
	totp: true,
	passkey: true,
	sso: true,
	apiKey: true,
	username: true,
	phone: true,
	device: true,
	oneTimeToken: true,
	loginHistory: true,
	oidcProvider: true,
	jwt: true,
	rebac: true,
	federation: true,
};

function resolveEnabledFeatures(config?: KavachConfig): EnabledFeatures {
	if (!config) {
		// Backward compat: no config = create everything
		return ALL_FEATURES_ENABLED;
	}

	const hasAgents = !!config.agents || !!config.did; // DID module always requires agent tables
	const hasSession = !!config.auth?.session;
	const hasOAuth = config.plugins?.some((p) => p.id === "kavach-oauth") ?? false;
	const hasOidc = config.plugins?.some((p) => p.id === "kavach-oidc-provider") ?? false;

	return {
		core: true,
		session: hasSession,
		agent: hasAgents,
		audit: hasAgents,
		oauth: hasOAuth,
		tenant: hasAgents,
		mcp: !!config.mcp,
		org: !!config.org,
		rateLimit: hasAgents,
		budget: hasAgents,
		magicLink: !!config.magicLink,
		emailOtp: !!config.emailOtp,
		totp: !!config.totp,
		passkey: !!config.passkey,
		sso: !!config.sso,
		apiKey: !!config.apiKeys,
		username: !!config.username,
		phone: !!config.phone,
		device: hasSession,
		oneTimeToken: !!config.magicLink || !!config.emailOtp || !!config.passwordReset,
		loginHistory: hasSession,
		oidcProvider: hasOidc,
		jwt: hasSession,
		rebac: hasAgents,
		federation: false, // only when explicitly configured (no config key yet)
	};
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-provider DDL helpers
// ──────────────────────────────────────────────────────────────────────────────

interface TaggedStatement {
	feature: keyof EnabledFeatures;
	sql: string;
}

/**
 * Returns CREATE TABLE statements for all KavachOS tables, adapted to the
 * target SQL dialect, tagged with the feature that requires them.
 *
 * Dialect differences handled here:
 * - **Timestamps** – SQLite stores as INTEGER (Unix ms); Postgres uses
 *   TIMESTAMPTZ; MySQL uses DATETIME(3).
 * - **JSON columns** – SQLite stores as TEXT; Postgres uses JSONB;
 *   MySQL uses JSON.
 * - **Booleans** – SQLite stores as INTEGER (0/1); Postgres uses BOOLEAN;
 *   MySQL uses TINYINT(1).
 * - **Auto-increment** – Not used here (IDs are application-generated UUIDs /
 *   nanoids), so no SERIAL vs AUTO_INCREMENT difference applies.
 */
function buildStatements(provider: DatabaseConfig["provider"]): TaggedStatement[] {
	const isPostgres = provider === "postgres";
	const isMysql = provider === "mysql";

	// Timestamp column type
	const ts = isPostgres ? "TIMESTAMPTZ" : isMysql ? "DATETIME(3)" : "INTEGER";
	// Nullable timestamp (same type, just no NOT NULL)
	const tsNull = ts;
	// JSON column type
	const json = isPostgres ? "JSONB" : isMysql ? "JSON" : "TEXT";
	// Boolean column type
	const bool = isPostgres ? "BOOLEAN" : isMysql ? "TINYINT(1)" : "INTEGER";
	// IF NOT EXISTS is universally supported
	const ifne = "IF NOT EXISTS";

	return [
		// ------------------------------------------------------------------
		// kavach_users
		// ------------------------------------------------------------------
		{
			feature: "core",
			sql: `CREATE TABLE ${ifne} kavach_users (
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

		// ------------------------------------------------------------------
		// kavach_tenants  (must come before kavach_agents – agents FK to tenants)
		// ------------------------------------------------------------------
		{
			feature: "tenant",
			sql: `CREATE TABLE ${ifne} kavach_tenants (
  id         TEXT NOT NULL PRIMARY KEY,
  name       TEXT NOT NULL,
  slug       TEXT NOT NULL UNIQUE,
  settings   ${json},
  status     TEXT NOT NULL DEFAULT 'active',
  created_at ${ts} NOT NULL,
  updated_at ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_agents
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_agents (
  id              TEXT  NOT NULL PRIMARY KEY,
  owner_id        TEXT  NOT NULL REFERENCES kavach_users(id),
  tenant_id       TEXT  REFERENCES kavach_tenants(id),
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

		// ------------------------------------------------------------------
		// kavach_permissions
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_permissions (
  id          TEXT  NOT NULL PRIMARY KEY,
  agent_id    TEXT  NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  resource    TEXT  NOT NULL,
  actions     ${json} NOT NULL,
  constraints ${json},
  relation    TEXT,
  created_at  ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_delegation_chains
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_delegation_chains (
  id            TEXT    NOT NULL PRIMARY KEY,
  from_agent_id TEXT    NOT NULL REFERENCES kavach_agents(id),
  to_agent_id   TEXT    NOT NULL REFERENCES kavach_agents(id),
  permissions   ${json} NOT NULL,
  depth         INTEGER NOT NULL DEFAULT 1,
  max_depth     INTEGER NOT NULL DEFAULT 3,
  status        TEXT    NOT NULL DEFAULT 'active',
  expires_at    ${ts}   NOT NULL,
  created_at    ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_audit_logs
		// ------------------------------------------------------------------
		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} kavach_audit_logs (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES kavach_agents(id),
  user_id      TEXT    NOT NULL REFERENCES kavach_users(id),
  action       TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  parameters   ${json},
  result       TEXT    NOT NULL,
  reason       TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  cache_hit    ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  timestamp    ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_rate_limits
		// ------------------------------------------------------------------
		{
			feature: "rateLimit",
			sql: `CREATE TABLE ${ifne} kavach_rate_limits (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  resource     TEXT    NOT NULL,
  window_start ${ts}   NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0
)`,
		},

		// ------------------------------------------------------------------
		// kavach_mcp_servers
		// ------------------------------------------------------------------
		{
			feature: "mcp",
			sql: `CREATE TABLE ${ifne} kavach_mcp_servers (
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

		// ------------------------------------------------------------------
		// kavach_sessions
		// ------------------------------------------------------------------
		{
			feature: "session",
			sql: `CREATE TABLE ${ifne} kavach_sessions (
  id         TEXT    NOT NULL PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES kavach_users(id),
  expires_at ${ts}   NOT NULL,
  metadata   ${json},
  created_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_oauth_clients
		// ------------------------------------------------------------------
		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} kavach_oauth_clients (
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

		// ------------------------------------------------------------------
		// kavach_oauth_access_tokens
		// ------------------------------------------------------------------
		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} kavach_oauth_access_tokens (
  id                        TEXT NOT NULL PRIMARY KEY,
  access_token              TEXT NOT NULL UNIQUE,
  refresh_token             TEXT UNIQUE,
  client_id                 TEXT NOT NULL REFERENCES kavach_oauth_clients(client_id),
  user_id                   TEXT NOT NULL REFERENCES kavach_users(id),
  scopes                    TEXT NOT NULL,
  resource                  TEXT,
  access_token_expires_at   ${ts} NOT NULL,
  refresh_token_expires_at  ${tsNull},
  created_at                ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_oauth_authorization_codes
		// ------------------------------------------------------------------
		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} kavach_oauth_authorization_codes (
  id                     TEXT NOT NULL PRIMARY KEY,
  code                   TEXT NOT NULL UNIQUE,
  client_id              TEXT NOT NULL REFERENCES kavach_oauth_clients(client_id),
  user_id                TEXT NOT NULL REFERENCES kavach_users(id),
  redirect_uri           TEXT NOT NULL,
  scopes                 TEXT NOT NULL,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  resource               TEXT,
  expires_at             ${ts} NOT NULL,
  created_at             ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_oauth_accounts (provider account linking)
		// ------------------------------------------------------------------
		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} kavach_oauth_accounts (
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

		// ------------------------------------------------------------------
		// kavach_oauth_states (PKCE state for CSRF protection)
		// ------------------------------------------------------------------
		{
			feature: "oauth",
			sql: `CREATE TABLE ${ifne} kavach_oauth_states (
  state          TEXT NOT NULL PRIMARY KEY,
  code_verifier  TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  provider       TEXT NOT NULL,
  expires_at     ${ts} NOT NULL,
  created_at     ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_budget_policies
		// ------------------------------------------------------------------
		{
			feature: "budget",
			sql: `CREATE TABLE ${ifne} kavach_budget_policies (
  id            TEXT    NOT NULL PRIMARY KEY,
  agent_id      TEXT    REFERENCES kavach_agents(id) ON DELETE CASCADE,
  user_id       TEXT    REFERENCES kavach_users(id),
  tenant_id     TEXT    REFERENCES kavach_tenants(id),
  limits        ${json} NOT NULL,
  current_usage ${json} NOT NULL,
  action        TEXT    NOT NULL DEFAULT 'warn',
  status        TEXT    NOT NULL DEFAULT 'active',
  created_at    ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_agent_cards  (A2A discovery)
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_agent_cards (
  id                TEXT    NOT NULL PRIMARY KEY,
  agent_id          TEXT    NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
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

		// ------------------------------------------------------------------
		// kavach_approval_requests  (CIBA async approval flows)
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_approval_requests (
  id            TEXT NOT NULL PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES kavach_users(id),
  action        TEXT NOT NULL,
  resource      TEXT NOT NULL,
  arguments     ${json},
  status        TEXT NOT NULL DEFAULT 'pending',
  expires_at    ${ts} NOT NULL,
  responded_at  ${tsNull},
  responded_by  TEXT,
  created_at    ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_trust_scores  (graduated autonomy scoring)
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_trust_scores (
  agent_id    TEXT    NOT NULL PRIMARY KEY REFERENCES kavach_agents(id) ON DELETE CASCADE,
  score       INTEGER NOT NULL,
  level       TEXT    NOT NULL,
  factors     ${json} NOT NULL,
  computed_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_organizations
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} kavach_organizations (
  id         TEXT    NOT NULL PRIMARY KEY,
  name       TEXT    NOT NULL,
  slug       TEXT    NOT NULL UNIQUE,
  owner_id   TEXT    NOT NULL REFERENCES kavach_users(id),
  metadata   ${json},
  created_at ${ts}   NOT NULL,
  updated_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_org_members
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} kavach_org_members (
  id        TEXT    NOT NULL PRIMARY KEY,
  org_id    TEXT    NOT NULL REFERENCES kavach_organizations(id) ON DELETE CASCADE,
  user_id   TEXT    NOT NULL REFERENCES kavach_users(id),
  role      TEXT    NOT NULL DEFAULT 'member',
  joined_at ${ts}   NOT NULL,
  UNIQUE(org_id, user_id)
)`,
		},

		// ------------------------------------------------------------------
		// kavach_org_invitations
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} kavach_org_invitations (
  id         TEXT    NOT NULL PRIMARY KEY,
  org_id     TEXT    NOT NULL REFERENCES kavach_organizations(id) ON DELETE CASCADE,
  email      TEXT    NOT NULL,
  role       TEXT    NOT NULL DEFAULT 'member',
  invited_by TEXT    NOT NULL REFERENCES kavach_users(id),
  status     TEXT    NOT NULL DEFAULT 'pending',
  expires_at ${ts}   NOT NULL,
  created_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_org_roles
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} kavach_org_roles (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL REFERENCES kavach_organizations(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  permissions ${json} NOT NULL,
  UNIQUE(org_id, name)
)`,
		},

		// ------------------------------------------------------------------
		// kavach_passkey_credentials  (WebAuthn / FIDO2 passkeys)
		// ------------------------------------------------------------------
		{
			feature: "passkey",
			sql: `CREATE TABLE ${ifne} kavach_passkey_credentials (
  id            TEXT    NOT NULL PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES kavach_users(id),
  credential_id TEXT    NOT NULL UNIQUE,
  public_key    TEXT    NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,
  device_name   TEXT,
  transports    TEXT,
  created_at    ${ts}   NOT NULL,
  last_used_at  ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_passkey_challenges  (short-lived WebAuthn challenges)
		// ------------------------------------------------------------------
		{
			feature: "passkey",
			sql: `CREATE TABLE ${ifne} kavach_passkey_challenges (
  id         TEXT NOT NULL PRIMARY KEY,
  challenge  TEXT NOT NULL UNIQUE,
  user_id    TEXT,
  type       TEXT NOT NULL,
  expires_at ${ts} NOT NULL,
  created_at ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_one_time_tokens  (email verify, password reset, invitation)
		// ------------------------------------------------------------------
		{
			feature: "oneTimeToken",
			sql: `CREATE TABLE ${ifne} kavach_one_time_tokens (
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

		// ------------------------------------------------------------------
		// kavach_agent_dids  (W3C Decentralized Identifiers per agent)
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_agent_dids (
  agent_id       TEXT NOT NULL PRIMARY KEY REFERENCES kavach_agents(id) ON DELETE CASCADE,
  did            TEXT NOT NULL UNIQUE,
  method         TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  did_document   TEXT NOT NULL,
  created_at     ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_magic_links  (passwordless email login)
		// ------------------------------------------------------------------
		{
			feature: "magicLink",
			sql: `CREATE TABLE ${ifne} kavach_magic_links (
  id         TEXT    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  token      TEXT    NOT NULL UNIQUE,
  expires_at ${ts}   NOT NULL,
  used       ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  created_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_email_otps  (one-time password login)
		// ------------------------------------------------------------------
		{
			feature: "emailOtp",
			sql: `CREATE TABLE ${ifne} kavach_email_otps (
  id         TEXT    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  code_hash  TEXT    NOT NULL,
  expires_at ${ts}   NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_totp  (TOTP two-factor authentication)
		// ------------------------------------------------------------------
		{
			feature: "totp",
			sql: `CREATE TABLE ${ifne} kavach_totp (
  user_id      TEXT    NOT NULL PRIMARY KEY REFERENCES kavach_users(id),
  secret       TEXT    NOT NULL,
  enabled      ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  backup_codes ${json} NOT NULL,
  created_at   ${ts}   NOT NULL,
  updated_at   ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_sso_connections  (SAML 2.0 / OIDC enterprise SSO)
		// ------------------------------------------------------------------
		{
			feature: "sso",
			sql: `CREATE TABLE ${ifne} kavach_sso_connections (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL,
  provider_id TEXT    NOT NULL,
  type        TEXT    NOT NULL,
  domain      TEXT    NOT NULL UNIQUE,
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_api_keys  (static bearer tokens with permission scopes)
		// ------------------------------------------------------------------
		{
			feature: "apiKey",
			sql: `CREATE TABLE ${ifne} kavach_api_keys (
  id           TEXT    NOT NULL PRIMARY KEY,
  user_id      TEXT    NOT NULL REFERENCES kavach_users(id),
  name         TEXT    NOT NULL,
  key_hash     TEXT    NOT NULL,
  key_prefix   TEXT    NOT NULL,
  permissions  ${json} NOT NULL,
  expires_at   ${tsNull},
  last_used_at ${tsNull},
  created_at   ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_username_accounts  (username + password auth)
		// ------------------------------------------------------------------
		{
			feature: "username",
			sql: `CREATE TABLE ${ifne} kavach_username_accounts (
  id            TEXT NOT NULL PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES kavach_users(id) ON DELETE CASCADE,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    ${ts} NOT NULL,
  updated_at    ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_phone_verifications  (SMS OTP)
		// ------------------------------------------------------------------
		{
			feature: "phone",
			sql: `CREATE TABLE ${ifne} kavach_phone_verifications (
  id           TEXT    NOT NULL PRIMARY KEY,
  phone_number TEXT    NOT NULL,
  code_hash    TEXT    NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  expires_at   ${ts}   NOT NULL,
  created_at   ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_trusted_devices  (skip 2FA on trusted devices for a window)
		// ------------------------------------------------------------------
		{
			feature: "device",
			sql: `CREATE TABLE ${ifne} kavach_trusted_devices (
  id          TEXT NOT NULL PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES kavach_users(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  label       TEXT NOT NULL,
  trusted_at  ${ts} NOT NULL,
  expires_at  ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// kavach_login_history  (last-login method tracking per user)
		// ------------------------------------------------------------------
		{
			feature: "loginHistory",
			sql: `CREATE TABLE ${ifne} kavach_login_history (
  id         TEXT NOT NULL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES kavach_users(id) ON DELETE CASCADE,
  method     TEXT NOT NULL,
  ip         TEXT,
  user_agent TEXT,
  timestamp  ${ts} NOT NULL
)`,
		},
		{
			feature: "loginHistory",
			sql: `CREATE INDEX ${ifne} kavach_login_history_user_ts
  ON kavach_login_history (user_id, timestamp DESC)`,
		},

		// ------------------------------------------------------------------
		// kavach_oidc_clients  (OIDC Provider — registered relying parties)
		// ------------------------------------------------------------------
		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} kavach_oidc_clients (
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

		// ------------------------------------------------------------------
		// kavach_oidc_auth_codes  (OIDC Provider — authorization codes)
		// ------------------------------------------------------------------
		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} kavach_oidc_auth_codes (
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

		// ------------------------------------------------------------------
		// kavach_oidc_refresh_tokens  (OIDC Provider — refresh tokens)
		// ------------------------------------------------------------------
		{
			feature: "oidcProvider",
			sql: `CREATE TABLE ${ifne} kavach_oidc_refresh_tokens (
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

		// ------------------------------------------------------------------
		// kavach_cost_events  (per-agent cost attribution)
		// ------------------------------------------------------------------
		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} kavach_cost_events (
  id                  TEXT    NOT NULL PRIMARY KEY,
  agent_id            TEXT    NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
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
			sql: `CREATE INDEX ${ifne} kavach_cost_events_agent_recorded
  ON kavach_cost_events (agent_id, recorded_at DESC)`,
		},
		{
			feature: "audit",
			sql: `CREATE INDEX ${ifne} kavach_cost_events_chain_id
  ON kavach_cost_events (delegation_chain_id)`,
		},

		// ------------------------------------------------------------------
		// kavach_ephemeral_sessions  (short-lived agent credentials)
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} kavach_ephemeral_sessions (
  id             TEXT    NOT NULL PRIMARY KEY,
  agent_id       TEXT    NOT NULL REFERENCES kavach_agents(id) ON DELETE CASCADE,
  owner_id       TEXT    NOT NULL REFERENCES kavach_users(id),
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
			sql: `CREATE INDEX ${ifne} kavach_ephemeral_sessions_owner_status
  ON kavach_ephemeral_sessions (owner_id, status)`,
		},
		{
			feature: "agent",
			sql: `CREATE INDEX ${ifne} kavach_ephemeral_sessions_expires_at
  ON kavach_ephemeral_sessions (expires_at)`,
		},

		// ------------------------------------------------------------------
		// kavach_jwt_refresh_tokens  (JWT session plugin — general purpose)
		// ------------------------------------------------------------------
		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} kavach_jwt_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  user_id     TEXT    NOT NULL REFERENCES kavach_users(id) ON DELETE CASCADE,
  used        ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  expires_at  ${ts}   NOT NULL,
  created_at  ${ts}   NOT NULL
)`,
		},
		{
			feature: "jwt",
			sql: `CREATE INDEX ${ifne} kavach_jwt_refresh_tokens_user_id
  ON kavach_jwt_refresh_tokens (user_id)`,
		},

		// ------------------------------------------------------------------
		// kavach_stream_events  (persisted SSE events for replay)
		// ------------------------------------------------------------------
		{
			feature: "audit",
			sql: `CREATE TABLE ${ifne} kavach_stream_events (
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
			sql: `CREATE INDEX ${ifne} kavach_stream_events_timestamp
  ON kavach_stream_events (timestamp DESC)`,
		},
		{
			feature: "audit",
			sql: `CREATE INDEX ${ifne} kavach_stream_events_type_timestamp
  ON kavach_stream_events (type, timestamp DESC)`,
		},

		// ------------------------------------------------------------------
		// kavach_rebac_resources  (ReBAC resource hierarchy)
		// ------------------------------------------------------------------
		{
			feature: "rebac",
			sql: `CREATE TABLE ${ifne} kavach_rebac_resources (
  id          TEXT NOT NULL PRIMARY KEY,
  type        TEXT NOT NULL,
  parent_id   TEXT,
  parent_type TEXT,
  created_at  ${ts} NOT NULL
)`,
		},
		{
			feature: "rebac",
			sql: `CREATE INDEX ${ifne} kavach_rebac_resources_parent
  ON kavach_rebac_resources (parent_id, parent_type)`,
		},

		// ------------------------------------------------------------------
		// kavach_rebac_relationships  (Zanzibar-style subject-relation-object tuples)
		// ------------------------------------------------------------------
		{
			feature: "rebac",
			sql: `CREATE TABLE ${ifne} kavach_rebac_relationships (
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
			sql: `CREATE INDEX ${ifne} kavach_rebac_relationships_subject
  ON kavach_rebac_relationships (subject_type, subject_id)`,
		},
		{
			feature: "rebac",
			sql: `CREATE INDEX ${ifne} kavach_rebac_relationships_object
  ON kavach_rebac_relationships (object_type, object_id)`,
		},
		{
			feature: "rebac",
			sql: `CREATE UNIQUE INDEX ${ifne} kavach_rebac_relationships_tuple
  ON kavach_rebac_relationships (subject_type, subject_id, relation, object_type, object_id)`,
		},

		// ------------------------------------------------------------------
		// kavach_federation_instances  (trusted remote KavachOS instances)
		// ------------------------------------------------------------------
		{
			feature: "federation",
			sql: `CREATE TABLE ${ifne} kavach_federation_instances (
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

		// ------------------------------------------------------------------
		// kavach_federation_tokens  (issued/received federation tokens)
		// ------------------------------------------------------------------
		{
			feature: "federation",
			sql: `CREATE TABLE ${ifne} kavach_federation_tokens (
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
			sql: `CREATE INDEX ${ifne} kavach_federation_tokens_agent
  ON kavach_federation_tokens (agent_id)`,
		},
		{
			feature: "federation",
			sql: `CREATE INDEX ${ifne} kavach_federation_tokens_source
  ON kavach_federation_tokens (source_instance_id)`,
		},

		// ------------------------------------------------------------------
		// kavach_refresh_token_families  (token rotation / reuse detection)
		// ------------------------------------------------------------------
		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} kavach_refresh_token_families (
  id                   TEXT    NOT NULL PRIMARY KEY,
  user_id              TEXT    NOT NULL REFERENCES kavach_users(id) ON DELETE CASCADE,
  absolute_expires_at  ${ts}   NOT NULL,
  revoked              ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  created_at           ${ts}   NOT NULL
)`,
		},
		{
			feature: "jwt",
			sql: `CREATE INDEX ${ifne} kavach_refresh_token_families_user_id
  ON kavach_refresh_token_families (user_id)`,
		},

		// ------------------------------------------------------------------
		// kavach_refresh_tokens  (individual one-time-use tokens per family)
		// ------------------------------------------------------------------
		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} kavach_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  family_id   TEXT    NOT NULL REFERENCES kavach_refresh_token_families(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  used        ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  expires_at  ${ts}   NOT NULL,
  created_at  ${ts}   NOT NULL
)`,
		},
		{
			feature: "jwt",
			sql: `CREATE INDEX ${ifne} kavach_refresh_tokens_family_id
  ON kavach_refresh_tokens (family_id)`,
		},
	];
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Create KavachOS tables if they do not already exist.
 *
 * Uses `CREATE TABLE IF NOT EXISTS` so it is safe to call on every startup.
 * Tables are created in dependency order (no forward-reference FK issues).
 *
 * When `config` is provided, only tables required by the configured features
 * are created. When omitted, all tables are created (backward-compatible
 * behaviour for callers that do not pass a config).
 *
 * @param db       Drizzle database instance returned by `createDatabase()`.
 * @param provider The database provider used to build the correct DDL syntax.
 * @param config   Optional KavachConfig used to determine which feature tables
 *                 to create. When absent, all tables are created.
 *
 * @example
 * ```typescript
 * const db = await createDatabase({ provider: 'postgres', url: process.env.DATABASE_URL });
 * await createTables(db, 'postgres');
 * ```
 */
export async function createTables(
	db: Database,
	provider: DatabaseConfig["provider"],
	config?: KavachConfig,
): Promise<void> {
	const allStatements = buildStatements(provider);
	const features = resolveEnabledFeatures(config);

	const statements = allStatements.filter((s) => features[s.feature]).map((s) => s.sql);

	if (provider === "sqlite" || provider === "sqlite-native") {
		// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
		const session = (db as any).session;

		// Path 1: better-sqlite3 (sqlite-native) exposes session.client.exec()
		if (session?.client?.exec) {
			session.client.exec(`${statements.join(";\n")};`);
			return;
		}

		// Path 2: sql.js (default sqlite) exposes session.client.run()
		if (session?.client?.run) {
			for (const sql of statements) {
				session.client.run(sql);
			}
			return;
		}

		// Path 3: Fallback via drizzle run() (works for both sql.js and better-sqlite3)
		// biome-ignore lint/suspicious/noExplicitAny: raw SQL fallback for DDL execution
		const anyDb = db as any;
		for (const sql of statements) {
			await anyDb.run(sql);
		}
		return;
	}

	// Postgres and MySQL: execute each statement via the underlying pool/client.
	// We access the internal session to issue raw DDL since drizzle-orm/node-postgres
	// and drizzle-orm/mysql2 both expose `.session.client` (or `.client`).
	// biome-ignore lint/suspicious/noExplicitAny: raw DDL on pg/mysql adapter boundary
	const anyDb = db as any;

	if (provider === "postgres") {
		// drizzle-orm/node-postgres wraps a `pg` Pool; the pool is at db.session.client
		// or accessible via db.$client depending on drizzle version.
		const client: { query: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"KavachOS createTables: cannot access underlying pg client from Drizzle instance.",
			);
		}
		for (const sql of statements) {
			await client.query(sql);
		}
		return;
	}

	if (provider === "mysql") {
		// drizzle-orm/mysql2 wraps a mysql2 Pool; exposed at db.$client.
		const client: { execute: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"KavachOS createTables: cannot access underlying mysql2 client from Drizzle instance.",
			);
		}
		for (const sql of statements) {
			await client.execute(sql);
		}
		return;
	}

	throw new Error(`createTables: unsupported provider "${provider}"`);
}
