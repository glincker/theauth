import type { TheAuthConfig } from "../types.js";
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
	secondaryStorage: boolean;
	tokenVault: boolean;
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
	secondaryStorage: true,
	tokenVault: true,
};

function resolveEnabledFeatures(config?: TheAuthConfig): EnabledFeatures {
	if (!config) {
		// Backward compat: no config = create everything
		return ALL_FEATURES_ENABLED;
	}

	const hasAgents = !!config.agents || !!config.did; // DID module always requires agent tables
	const hasSession = !!config.auth?.session;
	const hasOAuth = config.plugins?.some((p) => p.id === "theauth-oauth") ?? false;
	const hasOidc = config.plugins?.some((p) => p.id === "theauth-oidc-provider") ?? false;

	// Plugin form (`plugins: [magicLink(...)]`) must create the same tables as
	// the config-key form (`magicLink: {...}`), so look at plugin ids too.
	const hasPlugin = (id: string): boolean => config.plugins?.some((p) => p.id === id) ?? false;
	const hasMagicLink = !!config.magicLink || hasPlugin("theauth-magic-link");
	const hasEmailOtp = !!config.emailOtp || hasPlugin("theauth-email-otp");

	return {
		core: true,
		session: hasSession,
		agent: hasAgents,
		audit: hasAgents,
		oauth: hasOAuth,
		tenant: hasAgents,
		mcp: !!config.mcp,
		org: !!config.org || hasPlugin("theauth-organization"),
		rateLimit: hasAgents,
		budget: hasAgents,
		magicLink: hasMagicLink,
		emailOtp: hasEmailOtp,
		totp: !!config.totp || hasPlugin("theauth-2fa"),
		passkey: !!config.passkey || hasPlugin("theauth-passkey"),
		sso: !!config.sso,
		apiKey: !!config.apiKeys || hasPlugin("theauth-api-key"),
		username: !!config.username,
		phone: !!config.phone,
		device: hasSession,
		oneTimeToken: hasMagicLink || hasEmailOtp || !!config.passwordReset,
		loginHistory: hasSession,
		oidcProvider: hasOidc,
		jwt: hasSession,
		rebac: hasAgents,
		federation: false, // only when explicitly configured (no config key yet)
		// Tiny table, created always so `secondaryStorage: "database"` just works.
		secondaryStorage: true,
		tokenVault: hasPlugin("theauth-token-vault"),
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
 * Returns CREATE TABLE statements for all TheAuth tables, adapted to the
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
	/** Indexed text columns need a bounded type on MySQL. */
	const vc = isMysql ? "VARCHAR(191)" : "TEXT";

	return [
		// ------------------------------------------------------------------
		// theauth_users
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_tenants  (must come before theauth_agents – agents FK to tenants)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_agents
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_permissions
		// ------------------------------------------------------------------
		{
			feature: "agent",
			sql: `CREATE TABLE ${ifne} theauth_permissions (
  id          TEXT  NOT NULL PRIMARY KEY,
  agent_id    TEXT  NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  resource    TEXT  NOT NULL,
  actions     ${json} NOT NULL,
  constraints ${json},
  relation    TEXT,
  created_at  ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// theauth_delegation_chains
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_audit_logs
		// ------------------------------------------------------------------
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
  cache_hit    ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  timestamp    ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// theauth_rate_limits
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_mcp_servers
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_sessions
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oauth_clients
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oauth_access_tokens
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oauth_authorization_codes
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oauth_accounts (provider account linking)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oauth_states (PKCE state for CSRF protection)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_budget_policies
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_agent_cards  (A2A discovery)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_approval_requests  (CIBA async approval flows)
		// ------------------------------------------------------------------
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
  created_at    ${ts} NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// theauth_trust_scores  (graduated autonomy scoring)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_organizations
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_organizations (
  id         TEXT    NOT NULL PRIMARY KEY,
  name       TEXT    NOT NULL,
  slug       TEXT    NOT NULL UNIQUE,
  owner_id   TEXT    NOT NULL REFERENCES theauth_users(id),
  metadata   ${json},
  created_at ${ts}   NOT NULL,
  updated_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// theauth_org_members
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_org_members (
  id        TEXT    NOT NULL PRIMARY KEY,
  org_id    TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  user_id   TEXT    NOT NULL REFERENCES theauth_users(id),
  role      TEXT    NOT NULL DEFAULT 'member',
  joined_at ${ts}   NOT NULL,
  UNIQUE(org_id, user_id)
)`,
		},

		// ------------------------------------------------------------------
		// theauth_org_invitations
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_org_invitations (
  id         TEXT    NOT NULL PRIMARY KEY,
  org_id     TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  email      TEXT    NOT NULL,
  role       TEXT    NOT NULL DEFAULT 'member',
  invited_by TEXT    NOT NULL REFERENCES theauth_users(id),
  status     TEXT    NOT NULL DEFAULT 'pending',
  expires_at ${ts}   NOT NULL,
  created_at ${ts}   NOT NULL
)`,
		},

		// ------------------------------------------------------------------
		// theauth_org_roles
		// ------------------------------------------------------------------
		{
			feature: "org",
			sql: `CREATE TABLE ${ifne} theauth_org_roles (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  permissions ${json} NOT NULL,
  UNIQUE(org_id, name)
)`,
		},

		// ------------------------------------------------------------------
		// theauth_passkey_credentials  (WebAuthn / FIDO2 passkeys)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_passkey_challenges  (short-lived WebAuthn challenges)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_one_time_tokens  (email verify, password reset, invitation)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_secondary_storage  (database adapter for SecondaryStorage)
		// ------------------------------------------------------------------
		{
			feature: "secondaryStorage",
			sql: `CREATE TABLE ${ifne} theauth_secondary_storage (
  storage_key ${isMysql ? "VARCHAR(255)" : "TEXT"} NOT NULL PRIMARY KEY,
  value       TEXT,
  counter     INTEGER,
  expires_at  BIGINT
)`,
		},

		// ------------------------------------------------------------------
		// theauth_agent_registration_tokens  (one-time agent self-registration)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_agent_dids  (W3C Decentralized Identifiers per agent)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_vault_connections / theauth_vault_consents (outbound token vault)
		// ------------------------------------------------------------------
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
  status              VARCHAR(16) NOT NULL DEFAULT 'active',
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

		// ------------------------------------------------------------------
		// theauth_magic_links  (passwordless email login)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_email_otps  (one-time password login)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_totp  (TOTP two-factor authentication)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_sso_connections  (SAML 2.0 / OIDC enterprise SSO)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_api_keys  (static bearer tokens with permission scopes)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_username_accounts  (username + password auth)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_phone_verifications  (SMS OTP)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_trusted_devices  (skip 2FA on trusted devices for a window)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_login_history  (last-login method tracking per user)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oidc_clients  (OIDC Provider — registered relying parties)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oidc_auth_codes  (OIDC Provider — authorization codes)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_oidc_refresh_tokens  (OIDC Provider — refresh tokens)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_cost_events  (per-agent cost attribution)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_ephemeral_sessions  (short-lived agent credentials)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_jwt_refresh_tokens  (JWT session plugin — general purpose)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_stream_events  (persisted SSE events for replay)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_rebac_resources  (ReBAC resource hierarchy)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_rebac_relationships  (Zanzibar-style subject-relation-object tuples)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_federation_instances  (trusted remote TheAuth instances)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_federation_tokens  (issued/received federation tokens)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_refresh_token_families  (token rotation / reuse detection)
		// ------------------------------------------------------------------
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

		// ------------------------------------------------------------------
		// theauth_refresh_tokens  (individual one-time-use tokens per family)
		// ------------------------------------------------------------------
		{
			feature: "jwt",
			sql: `CREATE TABLE ${ifne} theauth_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  family_id   TEXT    NOT NULL REFERENCES theauth_refresh_token_families(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  used        ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
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

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Create TheAuth tables if they do not already exist.
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
 * @param config   Optional TheAuthConfig used to determine which feature tables
 *                 to create. When absent, all tables are created.
 *
 * @example
 * ```typescript
 * const db = await createDatabase({ provider: 'postgres', url: process.env.DATABASE_URL });
 * await createTables(db, 'postgres');
 * ```
 */
/** Prefix used by tables created before the rename to TheAuth. Only used to upgrade existing databases in place. */
const LEGACY_TABLE_PREFIX = "ka" + "vach_";

/**
 * Builds statements that rename pre-existing legacy tables to their current names so
 * upgrading a database keeps its data. Each statement fails harmlessly when the legacy
 * table is absent (fresh database) or the new table already exists, so callers run them
 * tolerantly before the CREATE TABLE statements.
 */
function buildLegacyRenames(provider: DatabaseConfig["provider"], statements: string[]): string[] {
	const names = new Set<string>();
	for (const sql of statements) {
		const m = /CREATE TABLE (?:IF NOT EXISTS )?(theauth_[a-z0-9_]+)/.exec(sql);
		if (m?.[1]) names.add(m[1]);
	}
	return [...names].map((name) => {
		const legacy = name.replace(/^theauth_/, LEGACY_TABLE_PREFIX);
		if (provider === "mysql") return `RENAME TABLE ${legacy} TO ${name}`;
		if (provider === "postgres") return `ALTER TABLE IF EXISTS ${legacy} RENAME TO ${name}`;
		return `ALTER TABLE ${legacy} RENAME TO ${name}`;
	});
}

/** Resolves a function that runs one raw DDL statement against the underlying driver. */
function resolveExecutor(
	db: Database,
	provider: DatabaseConfig["provider"],
): (sql: string) => Promise<void> {
	// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
	const anyDb = db as any;

	if (provider === "sqlite" || provider === "sqlite-native") {
		const session = anyDb.session;
		// better-sqlite3 (sqlite-native) exposes session.client.exec()
		if (session?.client?.exec) {
			return async (sql) => {
				session.client.exec(`${sql};`);
			};
		}
		// sql.js (default sqlite) exposes session.client.run()
		if (session?.client?.run) {
			return async (sql) => {
				session.client.run(sql);
			};
		}
		// Fallback via drizzle run() (works for both sql.js and better-sqlite3)
		return async (sql) => {
			await anyDb.run(sql);
		};
	}

	if (provider === "postgres") {
		// drizzle-orm/node-postgres wraps a `pg` Pool; the pool is at db.$client or db.session.client
		const client: { query: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"TheAuth createTables: cannot access underlying pg client from Drizzle instance.",
			);
		}
		return async (sql) => {
			await client.query(sql);
		};
	}

	if (provider === "mysql") {
		// drizzle-orm/mysql2 wraps a mysql2 Pool; exposed at db.$client.
		const client: { execute: (sql: string) => Promise<unknown> } =
			anyDb.$client ?? anyDb.session?.client;
		if (!client) {
			throw new Error(
				"TheAuth createTables: cannot access underlying mysql2 client from Drizzle instance.",
			);
		}
		return async (sql) => {
			await client.execute(sql);
		};
	}

	throw new Error(`createTables: unsupported provider "${provider}"`);
}

export async function createTables(
	db: Database,
	provider: DatabaseConfig["provider"],
	config?: TheAuthConfig,
): Promise<void> {
	const allStatements = buildStatements(provider);
	const features = resolveEnabledFeatures(config);

	const statements = allStatements.filter((s) => features[s.feature]).map((s) => s.sql);
	const run = resolveExecutor(db, provider);

	// Upgrade path: keep data in tables created under the previous name.
	for (const sql of buildLegacyRenames(
		provider,
		allStatements.map((s) => s.sql),
	)) {
		try {
			await run(sql);
		} catch {
			// Expected on fresh databases or when the new table already exists.
		}
	}

	for (const sql of statements) {
		await run(sql);
	}
}
