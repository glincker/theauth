import type { TheAuthConfig } from "../types.js";
import type { Database, DatabaseConfig } from "./database.js";

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
	sharedSignals: boolean;
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
	sharedSignals: true,
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
		// OAuth plugins hold the native app sign-in codes here.
		oneTimeToken: hasMagicLink || hasEmailOtp || !!config.passwordReset || hasOAuth,
		loginHistory: hasSession,
		oidcProvider: hasOidc,
		jwt: hasSession,
		rebac: hasAgents,
		federation: false, // only when explicitly configured (no config key yet)
		// Tiny table, created always so `secondaryStorage: "database"` just works.
		secondaryStorage: true,
		tokenVault: hasPlugin("theauth-token-vault"),
		sharedSignals: hasPlugin("theauth-shared-signals"),
	};
}

interface TaggedStatement {
	feature: keyof EnabledFeatures;
	sql: string;
}

/** Returns CREATE TABLE statements for all TheAuth tables, adapted to the target SQL dialect, each tagged with its feature. */
function buildStatements(provider: DatabaseConfig["provider"]): TaggedStatement[] {
	const isPostgres = provider === "postgres";
	const isMysql = provider === "mysql";

	const ts = isPostgres ? "TIMESTAMPTZ" : isMysql ? "DATETIME(3)" : "INTEGER";
	const tsNull = ts;
	const json = isPostgres ? "JSONB" : isMysql ? "JSON" : "TEXT";
	const bool = isPostgres ? "BOOLEAN" : isMysql ? "TINYINT(1)" : "INTEGER";
	const ifne = "IF NOT EXISTS";
	/** Indexed text columns need a bounded type on MySQL. */
	const vc = isMysql ? "VARCHAR(191)" : "TEXT";

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
  relation    TEXT,
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
  decision_code TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  cache_hit    ${bool} NOT NULL DEFAULT ${isPostgres ? "FALSE" : "0"},
  timestamp    ${ts}   NOT NULL,
  recorded_at_ms ${isPostgres || isMysql ? "BIGINT" : "INTEGER"},
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
		// MySQL has no CREATE INDEX IF NOT EXISTS, so its index is created by
		// upgradeAuditChainColumns, which tolerates "already exists".
		...(isMysql
			? []
			: [
					{
						feature: "audit" as const,
						sql: `CREATE UNIQUE INDEX ${ifne} theauth_audit_logs_chain
  ON theauth_audit_logs (agent_id, chain_seq)`,
					},
				]),

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
			feature: "secondaryStorage",
			sql: `CREATE TABLE ${ifne} theauth_secondary_storage (
  storage_key ${isMysql ? "VARCHAR(255)" : "TEXT"} NOT NULL PRIMARY KEY,
  value       TEXT,
  counter     INTEGER,
  expires_at  BIGINT
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
  status          VARCHAR(16) NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at ${ts} NOT NULL,
  last_error      TEXT,
  created_at      ${ts} NOT NULL
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

/**
 * Create TheAuth tables if they do not already exist.
 * Uses `CREATE TABLE IF NOT EXISTS` so it is safe to call on every startup. When `config` is provided, only tables required by the configured features are created. When omitted, all tables are created (backward-compatible behaviour for callers that do not pass a config).
 *
 * @example
 * ```typescript
 * const db = await createDatabase({ provider: 'postgres', url: process.env.DATABASE_URL });
 * await createTables(db, 'postgres');
 * ```
 */
/** Prefix used by tables created before the rename to TheAuth. Only used to upgrade existing databases in place. */
const LEGACY_TABLE_PREFIX = "ka" + "vach_";

/** Renames tables created under the legacy prefix so upgrades keep their data. */
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

function resolveExecutor(
	db: Database,
	provider: DatabaseConfig["provider"],
): (sql: string) => Promise<void> {
	// biome-ignore lint/suspicious/noExplicitAny: accessing internal drizzle session for raw DDL
	const anyDb = db as any;

	if (provider === "sqlite" || provider === "sqlite-native") {
		const session = anyDb.session;
		if (session?.client?.exec) {
			return async (sql) => {
				session.client.exec(`${sql};`);
			};
		}
		if (session?.client?.run) {
			return async (sql) => {
				session.client.run(sql);
			};
		}
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

	// A pre-chain audit table needs its new columns before the CREATE INDEX
	// below can reference them. On a fresh database this pass finds no table
	// and is a no-op; the pass after the loop covers MySQL's index.
	if (features.audit) {
		await upgradeAuditChainColumns(run, provider);
	}

	for (const sql of statements) {
		await run(sql);
	}

	if (features.audit) {
		await upgradeAuditChainColumns(run, provider);
	}
	if (features.agent) {
		await upgradeApprovalColumns(run, provider);
	}
}

/** Adds consumed_at to approval tables created before approvals became single use. */
async function upgradeApprovalColumns(
	run: (sql: string) => Promise<void>,
	provider: DatabaseConfig["provider"],
): Promise<void> {
	const ifne = provider === "postgres" ? "IF NOT EXISTS " : "";
	const ts =
		provider === "postgres" ? "TIMESTAMPTZ" : provider === "mysql" ? "DATETIME(3)" : "INTEGER";
	try {
		await run(`ALTER TABLE theauth_approval_requests ADD COLUMN ${ifne}consumed_at ${ts}`);
	} catch {
		// Column already present (fresh install or earlier upgrade).
	}
}

/** Adds the hash chain and accountability columns to audit tables created before them. */
async function upgradeAuditChainColumns(
	run: (sql: string) => Promise<void>,
	provider: DatabaseConfig["provider"],
): Promise<void> {
	const ifne = provider === "postgres" ? "IF NOT EXISTS " : "";
	const jsonType = provider === "postgres" ? "JSONB" : provider === "mysql" ? "JSON" : "TEXT";
	const stmts = [
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}chain_seq INTEGER`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}prev_hash TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}hash TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}hash_version INTEGER`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}subject_id TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}actor_id TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}policy_version TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}approver_id TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}delegation_chain ${jsonType}`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}input_provenance ${jsonType}`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}id_pseudonyms ${jsonType}`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}decision_code TEXT`,
		`ALTER TABLE theauth_audit_logs ADD COLUMN ${ifne}recorded_at_ms ${provider === "postgres" || provider === "mysql" ? "BIGINT" : "INTEGER"}`,
		provider === "mysql"
			? "CREATE UNIQUE INDEX theauth_audit_logs_chain ON theauth_audit_logs (agent_id(191), chain_seq)"
			: "CREATE UNIQUE INDEX IF NOT EXISTS theauth_audit_logs_chain ON theauth_audit_logs (agent_id, chain_seq)",
		provider === "mysql"
			? "CREATE INDEX theauth_audit_logs_code ON theauth_audit_logs (agent_id(191), decision_code(64))"
			: "CREATE INDEX IF NOT EXISTS theauth_audit_logs_code ON theauth_audit_logs (agent_id, decision_code)",
		// Migration 0003: deterministic backfill of the write-order column. Only touches
		// NULL rows, so reruns are no-ops. Ties inside one second are broken at read time
		// by chain_seq then id.
		provider === "postgres"
			? "UPDATE theauth_audit_logs SET recorded_at_ms = CAST(EXTRACT(EPOCH FROM timestamp) * 1000 AS BIGINT) WHERE recorded_at_ms IS NULL"
			: provider === "mysql"
				? "UPDATE theauth_audit_logs SET recorded_at_ms = CAST(UNIX_TIMESTAMP(timestamp) * 1000 AS SIGNED) WHERE recorded_at_ms IS NULL"
				: "UPDATE theauth_audit_logs SET recorded_at_ms = timestamp * 1000 WHERE recorded_at_ms IS NULL",
		provider === "mysql"
			? "CREATE INDEX theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms)"
			: "CREATE INDEX IF NOT EXISTS theauth_audit_logs_order ON theauth_audit_logs (recorded_at_ms)",
	];
	for (const sql of stmts) {
		try {
			await run(sql);
		} catch {
			// Column or index already present (fresh install or earlier upgrade).
		}
	}
}
