/* Migration 0000: baseline */

CREATE TABLE IF NOT EXISTS theauth_schema_migrations (
  id         TEXT NOT NULL PRIMARY KEY,
  name       TEXT      NOT NULL,
  checksum   TEXT      NOT NULL,
  applied_at INTEGER     NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_users (
  id                   TEXT        NOT NULL PRIMARY KEY,
  email                TEXT        NOT NULL UNIQUE,
  username             TEXT        UNIQUE,
  name                 TEXT,
  external_id          TEXT,
  external_provider    TEXT,
  metadata             TEXT,
  banned               INTEGER     NOT NULL DEFAULT 0,
  ban_reason           TEXT,
  ban_expires_at       INTEGER,
  force_password_reset         INTEGER     NOT NULL DEFAULT 0,
  email_verified               INTEGER     NOT NULL DEFAULT 0,
  stripe_customer_id           TEXT        UNIQUE,
  stripe_subscription_id       TEXT,
  stripe_subscription_status   TEXT,
  stripe_price_id              TEXT,
  stripe_current_period_end    INTEGER,
  stripe_cancel_at_period_end  INTEGER     NOT NULL DEFAULT 0,
  polar_customer_id            TEXT        UNIQUE,
  polar_subscription_id        TEXT,
  polar_subscription_status    TEXT,
  polar_product_id             TEXT,
  polar_current_period_end     INTEGER,
  polar_cancel_at_period_end   INTEGER     NOT NULL DEFAULT 0,
  created_at                   INTEGER       NOT NULL,
  updated_at                   INTEGER       NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_tenants (
  id         TEXT NOT NULL PRIMARY KEY,
  name       TEXT NOT NULL,
  slug       TEXT NOT NULL UNIQUE,
  settings   TEXT,
  status     TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_agents (
  id              TEXT  NOT NULL PRIMARY KEY,
  owner_id        TEXT  NOT NULL REFERENCES theauth_users(id),
  tenant_id       TEXT  REFERENCES theauth_tenants(id),
  name            TEXT  NOT NULL,
  type            TEXT  NOT NULL,
  status          TEXT  NOT NULL DEFAULT 'active',
  token_hash      TEXT  NOT NULL,
  token_prefix    TEXT  NOT NULL,
  expires_at      INTEGER,
  last_active_at  INTEGER,
  metadata        TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_permissions (
  id          TEXT  NOT NULL PRIMARY KEY,
  agent_id    TEXT  NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  resource    TEXT  NOT NULL,
  actions     TEXT NOT NULL,
  constraints TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_delegation_chains (
  id            TEXT    NOT NULL PRIMARY KEY,
  from_agent_id TEXT    NOT NULL REFERENCES theauth_agents(id),
  to_agent_id   TEXT    NOT NULL REFERENCES theauth_agents(id),
  permissions   TEXT NOT NULL,
  depth         INTEGER NOT NULL DEFAULT 1,
  max_depth     INTEGER NOT NULL DEFAULT 3,
  status        TEXT    NOT NULL DEFAULT 'active',
  expires_at    INTEGER   NOT NULL,
  created_at    INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_rate_limits (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  resource     TEXT    NOT NULL,
  window_start INTEGER   NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS theauth_mcp_servers (
  id               TEXT    NOT NULL PRIMARY KEY,
  name             TEXT    NOT NULL,
  endpoint         TEXT    NOT NULL UNIQUE,
  tools            TEXT NOT NULL,
  auth_required    INTEGER NOT NULL DEFAULT 1,
  rate_limit_rpm   INTEGER,
  status           TEXT    NOT NULL DEFAULT 'active',
  created_at       INTEGER   NOT NULL,
  updated_at       INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_sessions (
  id         TEXT    NOT NULL PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES theauth_users(id),
  expires_at INTEGER   NOT NULL,
  metadata   TEXT,
  created_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_secondary_storage (
  storage_key TEXT NOT NULL PRIMARY KEY,
  value       TEXT,
  counter     INTEGER,
  expires_at  BIGINT
);

CREATE TABLE IF NOT EXISTS theauth_audit_logs (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES theauth_agents(id),
  user_id      TEXT    NOT NULL REFERENCES theauth_users(id),
  action       TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  parameters   TEXT,
  result       TEXT    NOT NULL,
  reason       TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  timestamp    INTEGER   NOT NULL,
  chain_seq    INTEGER,
  prev_hash    TEXT,
  hash         TEXT,
  hash_version INTEGER,
  subject_id   TEXT,
  actor_id     TEXT,
  policy_version TEXT,
  approver_id  TEXT,
  delegation_chain TEXT,
  input_provenance TEXT,
  id_pseudonyms TEXT
);

CREATE TABLE IF NOT EXISTS theauth_audit_secrets (
  id         TEXT  NOT NULL PRIMARY KEY,
  secret     TEXT  NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_audit_logs_chain
  ON theauth_audit_logs (agent_id, chain_seq);

CREATE TABLE IF NOT EXISTS theauth_cost_events (
  id                  TEXT    NOT NULL PRIMARY KEY,
  agent_id            TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  tool                TEXT    NOT NULL,
  input_tokens        INTEGER,
  output_tokens       INTEGER,
  cost_micros         INTEGER NOT NULL,
  currency            TEXT    NOT NULL DEFAULT 'USD',
  metadata            TEXT,
  delegation_chain_id TEXT,
  recorded_at         INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_cost_events_agent_recorded
  ON theauth_cost_events (agent_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS theauth_cost_events_chain_id
  ON theauth_cost_events (delegation_chain_id);

CREATE TABLE IF NOT EXISTS theauth_stream_events (
  id        TEXT    NOT NULL PRIMARY KEY,
  type      TEXT    NOT NULL,
  timestamp INTEGER   NOT NULL,
  data      TEXT NOT NULL,
  agent_id  TEXT,
  user_id   TEXT
);

CREATE INDEX IF NOT EXISTS theauth_stream_events_timestamp
  ON theauth_stream_events (timestamp DESC);

CREATE INDEX IF NOT EXISTS theauth_stream_events_type_timestamp
  ON theauth_stream_events (type, timestamp DESC);

CREATE TABLE IF NOT EXISTS theauth_budget_policies (
  id            TEXT    NOT NULL PRIMARY KEY,
  agent_id      TEXT    REFERENCES theauth_agents(id) ON DELETE CASCADE,
  user_id       TEXT    REFERENCES theauth_users(id),
  tenant_id     TEXT    REFERENCES theauth_tenants(id),
  limits        TEXT NOT NULL,
  current_usage TEXT NOT NULL,
  action        TEXT    NOT NULL DEFAULT 'warn',
  status        TEXT    NOT NULL DEFAULT 'active',
  created_at    INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_agent_cards (
  id                TEXT    NOT NULL PRIMARY KEY,
  agent_id          TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  name              TEXT    NOT NULL,
  description       TEXT,
  version           TEXT    NOT NULL,
  protocols         TEXT NOT NULL,
  capabilities      TEXT NOT NULL,
  auth_requirements TEXT NOT NULL,
  endpoint          TEXT,
  metadata          TEXT,
  created_at        INTEGER   NOT NULL,
  updated_at        INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_approval_requests (
  id            TEXT NOT NULL PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES theauth_users(id),
  action        TEXT NOT NULL,
  resource      TEXT NOT NULL,
  arguments     TEXT,
  status        TEXT NOT NULL DEFAULT 'pending',
  expires_at    INTEGER NOT NULL,
  responded_at  INTEGER,
  responded_by  TEXT,
  consumed_at   INTEGER,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_trust_scores (
  agent_id    TEXT    NOT NULL PRIMARY KEY REFERENCES theauth_agents(id) ON DELETE CASCADE,
  score       INTEGER NOT NULL,
  level       TEXT    NOT NULL,
  factors     TEXT NOT NULL,
  computed_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_agent_registration_tokens (
  id                TEXT NOT NULL PRIMARY KEY,
  token_hash        TEXT NOT NULL UNIQUE,
  token_prefix      TEXT NOT NULL,
  label             TEXT,
  owner_id          TEXT NOT NULL REFERENCES theauth_users(id),
  tenant_id         TEXT,
  agent_type        TEXT NOT NULL DEFAULT 'autonomous',
  permissions       TEXT NOT NULL,
  name_prefix       TEXT,
  agent_ttl_seconds INTEGER,
  created_by        TEXT,
  expires_at        INTEGER NOT NULL,
  revoked_at        INTEGER,
  used_at           INTEGER,
  claim_nonce       TEXT,
  agent_id          TEXT,
  created_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_agent_dids (
  agent_id       TEXT NOT NULL PRIMARY KEY REFERENCES theauth_agents(id) ON DELETE CASCADE,
  did            TEXT NOT NULL UNIQUE,
  method         TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  did_document   TEXT NOT NULL,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_ephemeral_sessions (
  id             TEXT    NOT NULL PRIMARY KEY,
  agent_id       TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  owner_id       TEXT    NOT NULL REFERENCES theauth_users(id),
  token_hash     TEXT    NOT NULL UNIQUE,
  expires_at     INTEGER   NOT NULL,
  max_actions    INTEGER,
  actions_used   INTEGER NOT NULL DEFAULT 0,
  status         TEXT    NOT NULL DEFAULT 'active',
  audit_group_id TEXT    NOT NULL,
  created_at     INTEGER   NOT NULL,
  updated_at     INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_ephemeral_sessions_owner_status
  ON theauth_ephemeral_sessions (owner_id, status);

CREATE INDEX IF NOT EXISTS theauth_ephemeral_sessions_expires_at
  ON theauth_ephemeral_sessions (expires_at);

CREATE TABLE IF NOT EXISTS theauth_oauth_clients (
  id                          TEXT    NOT NULL PRIMARY KEY,
  client_id                   TEXT    NOT NULL UNIQUE,
  client_secret               TEXT,
  client_name                 TEXT,
  client_uri                  TEXT,
  redirect_uris               TEXT NOT NULL,
  grant_types                 TEXT NOT NULL,
  response_types              TEXT NOT NULL,
  token_endpoint_auth_method  TEXT    NOT NULL DEFAULT 'client_secret_basic',
  type                        TEXT    NOT NULL DEFAULT 'confidential',
  disabled                    INTEGER NOT NULL DEFAULT 0,
  metadata                    TEXT,
  created_at                  INTEGER   NOT NULL,
  updated_at                  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oauth_access_tokens (
  id                        TEXT NOT NULL PRIMARY KEY,
  access_token              TEXT NOT NULL UNIQUE,
  refresh_token             TEXT UNIQUE,
  client_id                 TEXT NOT NULL REFERENCES theauth_oauth_clients(client_id),
  user_id                   TEXT NOT NULL REFERENCES theauth_users(id),
  scopes                    TEXT NOT NULL,
  resource                  TEXT,
  access_token_expires_at   INTEGER NOT NULL,
  refresh_token_expires_at  INTEGER,
  created_at                INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oauth_authorization_codes (
  id                     TEXT NOT NULL PRIMARY KEY,
  code                   TEXT NOT NULL UNIQUE,
  client_id              TEXT NOT NULL REFERENCES theauth_oauth_clients(client_id),
  user_id                TEXT NOT NULL REFERENCES theauth_users(id),
  redirect_uri           TEXT NOT NULL,
  scopes                 TEXT NOT NULL,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  resource               TEXT,
  expires_at             INTEGER NOT NULL,
  created_at             INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oauth_accounts (
  id                   TEXT NOT NULL PRIMARY KEY,
  user_id              TEXT NOT NULL,
  provider             TEXT NOT NULL,
  provider_account_id  TEXT NOT NULL,
  access_token         TEXT NOT NULL,
  refresh_token        TEXT,
  expires_at           INTEGER,
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oauth_states (
  state          TEXT NOT NULL PRIMARY KEY,
  code_verifier  TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  provider       TEXT NOT NULL,
  expires_at     INTEGER NOT NULL,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_passkey_credentials (
  id            TEXT    NOT NULL PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES theauth_users(id),
  credential_id TEXT    NOT NULL UNIQUE,
  public_key    TEXT    NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,
  device_name   TEXT,
  transports    TEXT,
  created_at    INTEGER   NOT NULL,
  last_used_at  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_passkey_challenges (
  id         TEXT NOT NULL PRIMARY KEY,
  challenge  TEXT NOT NULL UNIQUE,
  user_id    TEXT,
  type       TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_one_time_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  purpose     TEXT    NOT NULL,
  identifier  TEXT    NOT NULL,
  metadata    TEXT,
  used        INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER   NOT NULL,
  created_at  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_magic_links (
  id         TEXT    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  token      TEXT    NOT NULL UNIQUE,
  expires_at INTEGER   NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_email_otps (
  id         TEXT    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  code_hash  TEXT    NOT NULL,
  expires_at INTEGER   NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_totp (
  user_id      TEXT    NOT NULL PRIMARY KEY REFERENCES theauth_users(id),
  secret       TEXT    NOT NULL,
  enabled      INTEGER NOT NULL DEFAULT 0,
  backup_codes TEXT NOT NULL,
  created_at   INTEGER   NOT NULL,
  updated_at   INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_sso_connections (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL,
  provider_id TEXT    NOT NULL,
  type        TEXT    NOT NULL,
  domain      TEXT    NOT NULL UNIQUE,
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_api_keys (
  id           TEXT    NOT NULL PRIMARY KEY,
  user_id      TEXT    NOT NULL REFERENCES theauth_users(id),
  name         TEXT    NOT NULL,
  key_hash     TEXT    NOT NULL,
  key_prefix   TEXT    NOT NULL,
  permissions  TEXT NOT NULL,
  expires_at   INTEGER,
  last_used_at INTEGER,
  created_at   INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_username_accounts (
  id            TEXT NOT NULL PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_phone_verifications (
  id           TEXT    NOT NULL PRIMARY KEY,
  phone_number TEXT    NOT NULL,
  code_hash    TEXT    NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  expires_at   INTEGER   NOT NULL,
  created_at   INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_trusted_devices (
  id          TEXT NOT NULL PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  label       TEXT NOT NULL,
  trusted_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_login_history (
  id         TEXT NOT NULL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  method     TEXT NOT NULL,
  ip         TEXT,
  user_agent TEXT,
  timestamp  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_login_history_user_ts
  ON theauth_login_history (user_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS theauth_jwt_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  user_id     TEXT    NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  used        INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER   NOT NULL,
  created_at  INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_jwt_refresh_tokens_user_id
  ON theauth_jwt_refresh_tokens (user_id);

CREATE TABLE IF NOT EXISTS theauth_refresh_token_families (
  id                   TEXT    NOT NULL PRIMARY KEY,
  user_id              TEXT    NOT NULL REFERENCES theauth_users(id) ON DELETE CASCADE,
  absolute_expires_at  INTEGER   NOT NULL,
  revoked              INTEGER NOT NULL DEFAULT 0,
  created_at           INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_refresh_token_families_user_id
  ON theauth_refresh_token_families (user_id);

CREATE TABLE IF NOT EXISTS theauth_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  family_id   TEXT    NOT NULL REFERENCES theauth_refresh_token_families(id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  used        INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER   NOT NULL,
  created_at  INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_refresh_tokens_family_id
  ON theauth_refresh_tokens (family_id);

CREATE TABLE IF NOT EXISTS theauth_organizations (
  id         TEXT    NOT NULL PRIMARY KEY,
  name       TEXT    NOT NULL,
  slug       TEXT    NOT NULL UNIQUE,
  owner_id   TEXT    NOT NULL REFERENCES theauth_users(id),
  metadata   TEXT,
  created_at INTEGER   NOT NULL,
  updated_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_org_members (
  id        TEXT    NOT NULL PRIMARY KEY,
  org_id    TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  user_id   TEXT    NOT NULL REFERENCES theauth_users(id),
  role      TEXT    NOT NULL DEFAULT 'member',
  joined_at INTEGER   NOT NULL,
  UNIQUE(org_id, user_id)
);

CREATE TABLE IF NOT EXISTS theauth_org_invitations (
  id         TEXT    NOT NULL PRIMARY KEY,
  org_id     TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  email      TEXT    NOT NULL,
  role       TEXT    NOT NULL DEFAULT 'member',
  invited_by TEXT    NOT NULL REFERENCES theauth_users(id),
  status     TEXT    NOT NULL DEFAULT 'pending',
  expires_at INTEGER   NOT NULL,
  created_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_org_roles (
  id          TEXT    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  permissions TEXT NOT NULL,
  UNIQUE(org_id, name)
);

CREATE TABLE IF NOT EXISTS theauth_vault_connections (
  id                  TEXT NOT NULL PRIMARY KEY,
  user_id             TEXT NOT NULL,
  tenant_id           TEXT NOT NULL DEFAULT '',
  provider            TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  access_token_enc    TEXT NOT NULL,
  refresh_token_enc   TEXT,
  key_id              TEXT NOT NULL,
  scopes              TEXT NOT NULL,
  status              VARCHAR(16) NOT NULL DEFAULT 'active',
  expires_at          INTEGER,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL,
  UNIQUE (user_id, tenant_id, provider)
);

CREATE TABLE IF NOT EXISTS theauth_vault_consents (
  id                  TEXT NOT NULL PRIMARY KEY,
  user_id             TEXT NOT NULL,
  agent_id            TEXT NOT NULL,
  tenant_id           TEXT NOT NULL DEFAULT '',
  provider            TEXT NOT NULL,
  scopes              TEXT NOT NULL,
  delegation_chain_id TEXT,
  expires_at          INTEGER,
  revoked_at          INTEGER,
  created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_ssf_streams (
  id                        TEXT NOT NULL PRIMARY KEY,
  owner                     TEXT NOT NULL,
  aud                       TEXT NOT NULL,
  events_requested          TEXT NOT NULL,
  events_delivered          TEXT NOT NULL,
  delivery_method           TEXT NOT NULL,
  endpoint_url              TEXT,
  authorization_header      TEXT,
  status                    TEXT NOT NULL DEFAULT 'enabled',
  status_reason             TEXT,
  subject_mode              TEXT NOT NULL DEFAULT 'all',
  description               TEXT,
  min_verification_interval INTEGER,
  last_verified_at          INTEGER,
  created_at                INTEGER NOT NULL,
  updated_at                INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_ssf_subjects (
  id               TEXT NOT NULL PRIMARY KEY,
  stream_id        TEXT NOT NULL,
  subject_key_hash TEXT NOT NULL,
  subject          TEXT NOT NULL,
  verified         INTEGER NOT NULL DEFAULT 1,
  created_at       INTEGER NOT NULL,
  UNIQUE (stream_id, subject_key_hash)
);

CREATE TABLE IF NOT EXISTS theauth_ssf_outbox (
  jti             TEXT NOT NULL PRIMARY KEY,
  stream_id       TEXT NOT NULL,
  jwt             TEXT NOT NULL,
  status          VARCHAR(16) NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_error      TEXT,
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oidc_clients (
  id                          TEXT    NOT NULL PRIMARY KEY,
  client_id                   TEXT    NOT NULL UNIQUE,
  client_secret_hash          TEXT    NOT NULL,
  client_name                 TEXT    NOT NULL,
  redirect_uris               TEXT NOT NULL,
  grant_types                 TEXT NOT NULL,
  response_types              TEXT NOT NULL,
  scopes                      TEXT NOT NULL,
  token_endpoint_auth_method  TEXT    NOT NULL DEFAULT 'client_secret_post',
  created_at                  INTEGER   NOT NULL,
  updated_at                  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oidc_auth_codes (
  id                     TEXT    NOT NULL PRIMARY KEY,
  code_hash              TEXT    NOT NULL UNIQUE,
  client_id              TEXT    NOT NULL,
  user_id                TEXT    NOT NULL,
  redirect_uri           TEXT    NOT NULL,
  scopes                 TEXT    NOT NULL,
  nonce                  TEXT,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  used                   INTEGER NOT NULL DEFAULT 0,
  expires_at             INTEGER   NOT NULL,
  created_at             INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oidc_refresh_tokens (
  id          TEXT    NOT NULL PRIMARY KEY,
  token_hash  TEXT    NOT NULL UNIQUE,
  client_id   TEXT    NOT NULL,
  user_id     TEXT    NOT NULL,
  scopes      TEXT    NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER   NOT NULL,
  created_at  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oidc_logout_clients (
  client_id                   TEXT NOT NULL PRIMARY KEY,
  post_logout_redirect_uris   TEXT NOT NULL,
  backchannel_logout_uri      TEXT,
  updated_at                  INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_oidc_sessions (
  id          TEXT NOT NULL PRIMARY KEY,
  sid         TEXT NOT NULL,
  session_id  TEXT,
  user_id     TEXT NOT NULL,
  client_id   TEXT NOT NULL,
  code_hash   TEXT,
  created_at  INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_oidc_sessions_sid
  ON theauth_oidc_sessions (sid);

CREATE INDEX IF NOT EXISTS theauth_oidc_sessions_session
  ON theauth_oidc_sessions (session_id);

CREATE TABLE IF NOT EXISTS theauth_rebac_resources (
  id          TEXT NOT NULL PRIMARY KEY,
  type        TEXT NOT NULL,
  parent_id   TEXT,
  parent_type TEXT,
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_rebac_resources_parent
  ON theauth_rebac_resources (parent_id, parent_type);

CREATE TABLE IF NOT EXISTS theauth_rebac_relationships (
  id           TEXT NOT NULL PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id   TEXT NOT NULL,
  relation     TEXT NOT NULL,
  object_type  TEXT NOT NULL,
  object_id    TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_rebac_relationships_subject
  ON theauth_rebac_relationships (subject_type, subject_id);

CREATE INDEX IF NOT EXISTS theauth_rebac_relationships_object
  ON theauth_rebac_relationships (object_type, object_id);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_rebac_relationships_tuple
  ON theauth_rebac_relationships (subject_type, subject_id, relation, object_type, object_id);

CREATE TABLE IF NOT EXISTS theauth_federation_instances (
  id            TEXT NOT NULL PRIMARY KEY,
  instance_id   TEXT NOT NULL UNIQUE,
  instance_url  TEXT NOT NULL,
  public_key_jwk TEXT,
  trust_level   TEXT NOT NULL DEFAULT 'verify-only',
  discovered_at INTEGER,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_federation_tokens (
  id                  TEXT    NOT NULL PRIMARY KEY,
  token_jti           TEXT    NOT NULL UNIQUE,
  agent_id            TEXT    NOT NULL,
  source_instance_id  TEXT    NOT NULL,
  target_instance_id  TEXT,
  direction           TEXT    NOT NULL,
  permissions         TEXT NOT NULL,
  trust_score         INTEGER,
  expires_at          INTEGER   NOT NULL,
  created_at          INTEGER   NOT NULL
);

CREATE INDEX IF NOT EXISTS theauth_federation_tokens_agent
  ON theauth_federation_tokens (agent_id);

CREATE INDEX IF NOT EXISTS theauth_federation_tokens_source
  ON theauth_federation_tokens (source_instance_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0000', 'baseline', 'cbaa56f7beec0656e897fe34ed0ff9697baf717ca74a27700faf3ab866c4f252', CAST(strftime('%s', 'now') AS INTEGER));
