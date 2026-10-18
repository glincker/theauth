/* Migration 0000: baseline */

CREATE TABLE IF NOT EXISTS theauth_schema_migrations (
  id         VARCHAR(191) NOT NULL PRIMARY KEY,
  name       TEXT      NOT NULL,
  checksum   TEXT      NOT NULL,
  applied_at DATETIME(3)     NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_users (
  id                   VARCHAR(191)        NOT NULL PRIMARY KEY,
  email                VARCHAR(191)        NOT NULL UNIQUE,
  username             VARCHAR(191)        UNIQUE,
  name                 TEXT,
  external_id          TEXT,
  external_provider    TEXT,
  metadata             JSON,
  banned               TINYINT(1)     NOT NULL DEFAULT 0,
  ban_reason           TEXT,
  ban_expires_at       BIGINT,
  force_password_reset         TINYINT(1)     NOT NULL DEFAULT 0,
  email_verified               TINYINT(1)     NOT NULL DEFAULT 0,
  stripe_customer_id           VARCHAR(191)        UNIQUE,
  stripe_subscription_id       TEXT,
  stripe_subscription_status   TEXT,
  stripe_price_id              TEXT,
  stripe_current_period_end    BIGINT,
  stripe_cancel_at_period_end  TINYINT(1)     NOT NULL DEFAULT 0,
  polar_customer_id            VARCHAR(191)        UNIQUE,
  polar_subscription_id        TEXT,
  polar_subscription_status    TEXT,
  polar_product_id             TEXT,
  polar_current_period_end     BIGINT,
  polar_cancel_at_period_end   TINYINT(1)     NOT NULL DEFAULT 0,
  created_at                   BIGINT       NOT NULL,
  updated_at                   BIGINT       NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_tenants (
  id         VARCHAR(191) NOT NULL PRIMARY KEY,
  name       TEXT NOT NULL,
  slug       VARCHAR(191) NOT NULL UNIQUE,
  settings   JSON,
  status     VARCHAR(191) NOT NULL DEFAULT 'active',
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_agents (
  id              VARCHAR(191)  NOT NULL PRIMARY KEY,
  owner_id        VARCHAR(191)  NOT NULL,
  tenant_id       VARCHAR(191),
  name            TEXT  NOT NULL,
  type            TEXT  NOT NULL,
  status          VARCHAR(191)  NOT NULL DEFAULT 'active',
  token_hash      TEXT  NOT NULL,
  token_prefix    TEXT  NOT NULL,
  expires_at      BIGINT,
  last_active_at  BIGINT,
  metadata        JSON,
  created_at      BIGINT NOT NULL,
  updated_at      BIGINT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES theauth_users(id),
  FOREIGN KEY (tenant_id) REFERENCES theauth_tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_permissions (
  id          VARCHAR(191)  NOT NULL PRIMARY KEY,
  agent_id    VARCHAR(191)  NOT NULL,
  resource    TEXT  NOT NULL,
  actions     JSON NOT NULL,
  constraints JSON,
  created_at  BIGINT NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_delegation_chains (
  id            VARCHAR(191)    NOT NULL PRIMARY KEY,
  from_agent_id VARCHAR(191)    NOT NULL,
  to_agent_id   VARCHAR(191)    NOT NULL,
  permissions   JSON NOT NULL,
  depth         INTEGER NOT NULL DEFAULT 1,
  max_depth     INTEGER NOT NULL DEFAULT 3,
  status        VARCHAR(191)    NOT NULL DEFAULT 'active',
  expires_at    BIGINT   NOT NULL,
  created_at    BIGINT   NOT NULL,
  FOREIGN KEY (from_agent_id) REFERENCES theauth_agents(id),
  FOREIGN KEY (to_agent_id) REFERENCES theauth_agents(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_rate_limits (
  id           VARCHAR(191)    NOT NULL PRIMARY KEY,
  agent_id     VARCHAR(191)    NOT NULL,
  resource     TEXT    NOT NULL,
  window_start BIGINT   NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_mcp_servers (
  id               VARCHAR(191)    NOT NULL PRIMARY KEY,
  name             TEXT    NOT NULL,
  endpoint         VARCHAR(191)    NOT NULL UNIQUE,
  tools            JSON NOT NULL,
  auth_required    TINYINT(1) NOT NULL DEFAULT 1,
  rate_limit_rpm   INTEGER,
  status           VARCHAR(191)    NOT NULL DEFAULT 'active',
  created_at       BIGINT   NOT NULL,
  updated_at       BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_sessions (
  id         VARCHAR(191)    NOT NULL PRIMARY KEY,
  user_id    VARCHAR(191)    NOT NULL,
  expires_at BIGINT   NOT NULL,
  metadata   JSON,
  created_at BIGINT   NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_secondary_storage (
  storage_key VARCHAR(255) NOT NULL PRIMARY KEY,
  value       TEXT,
  counter     INTEGER,
  expires_at  BIGINT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_audit_logs (
  id           VARCHAR(191)    NOT NULL PRIMARY KEY,
  agent_id     VARCHAR(191)    NOT NULL,
  user_id      VARCHAR(191)    NOT NULL,
  action       TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  parameters   JSON,
  result       TEXT    NOT NULL,
  reason       TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  timestamp    BIGINT   NOT NULL,
  chain_seq    INTEGER,
  prev_hash    TEXT,
  hash         TEXT,
  hash_version INTEGER,
  subject_id   TEXT,
  actor_id     TEXT,
  policy_version TEXT,
  approver_id  TEXT,
  delegation_chain JSON,
  input_provenance JSON,
  id_pseudonyms JSON,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id),
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_audit_secrets (
  id         VARCHAR(191)  NOT NULL PRIMARY KEY,
  secret     TEXT  NOT NULL,
  created_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE UNIQUE INDEX theauth_audit_logs_chain
  ON theauth_audit_logs (agent_id, chain_seq);

CREATE TABLE IF NOT EXISTS theauth_cost_events (
  id                  VARCHAR(191)    NOT NULL PRIMARY KEY,
  agent_id            VARCHAR(191)    NOT NULL,
  tool                TEXT    NOT NULL,
  input_tokens        INTEGER,
  output_tokens       INTEGER,
  cost_micros         BIGINT NOT NULL,
  currency            VARCHAR(191)    NOT NULL DEFAULT 'USD',
  metadata            JSON,
  delegation_chain_id VARCHAR(191),
  recorded_at         BIGINT   NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_cost_events_agent_recorded
  ON theauth_cost_events (agent_id, recorded_at DESC);

CREATE INDEX theauth_cost_events_chain_id
  ON theauth_cost_events (delegation_chain_id);

CREATE TABLE IF NOT EXISTS theauth_stream_events (
  id        VARCHAR(191)    NOT NULL PRIMARY KEY,
  type      VARCHAR(191)    NOT NULL,
  timestamp BIGINT   NOT NULL,
  data      JSON NOT NULL,
  agent_id  TEXT,
  user_id   TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_stream_events_timestamp
  ON theauth_stream_events (timestamp DESC);

CREATE INDEX theauth_stream_events_type_timestamp
  ON theauth_stream_events (type, timestamp DESC);

CREATE TABLE IF NOT EXISTS theauth_budget_policies (
  id            VARCHAR(191)    NOT NULL PRIMARY KEY,
  agent_id      VARCHAR(191),
  user_id       VARCHAR(191),
  tenant_id     VARCHAR(191),
  limits        JSON NOT NULL,
  current_usage JSON NOT NULL,
  action        VARCHAR(191)    NOT NULL DEFAULT 'warn',
  status        VARCHAR(191)    NOT NULL DEFAULT 'active',
  created_at    BIGINT   NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id),
  FOREIGN KEY (tenant_id) REFERENCES theauth_tenants(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_agent_cards (
  id                VARCHAR(191)    NOT NULL PRIMARY KEY,
  agent_id          VARCHAR(191)    NOT NULL,
  name              TEXT    NOT NULL,
  description       TEXT,
  version           TEXT    NOT NULL,
  protocols         JSON NOT NULL,
  capabilities      JSON NOT NULL,
  auth_requirements JSON NOT NULL,
  endpoint          TEXT,
  metadata          JSON,
  created_at        BIGINT   NOT NULL,
  updated_at        BIGINT   NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_approval_requests (
  id            VARCHAR(191) NOT NULL PRIMARY KEY,
  agent_id      VARCHAR(191) NOT NULL,
  user_id       VARCHAR(191) NOT NULL,
  action        TEXT NOT NULL,
  resource      TEXT NOT NULL,
  arguments     JSON,
  status        VARCHAR(191) NOT NULL DEFAULT 'pending',
  expires_at    BIGINT NOT NULL,
  responded_at  BIGINT,
  responded_by  TEXT,
  consumed_at   BIGINT,
  created_at    BIGINT NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_trust_scores (
  agent_id    VARCHAR(191)    NOT NULL PRIMARY KEY,
  score       INTEGER NOT NULL,
  level       TEXT    NOT NULL,
  factors     JSON NOT NULL,
  computed_at BIGINT   NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_agent_registration_tokens (
  id                VARCHAR(191) NOT NULL PRIMARY KEY,
  token_hash        VARCHAR(191) NOT NULL UNIQUE,
  token_prefix      TEXT NOT NULL,
  label             TEXT,
  owner_id          VARCHAR(191) NOT NULL,
  tenant_id         TEXT,
  agent_type        VARCHAR(191) NOT NULL DEFAULT 'autonomous',
  permissions       JSON NOT NULL,
  name_prefix       TEXT,
  agent_ttl_seconds INTEGER,
  created_by        TEXT,
  expires_at        BIGINT NOT NULL,
  revoked_at        BIGINT,
  used_at           BIGINT,
  claim_nonce       TEXT,
  agent_id          TEXT,
  created_at        BIGINT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_agent_dids (
  agent_id       VARCHAR(191) NOT NULL PRIMARY KEY,
  did            VARCHAR(191) NOT NULL UNIQUE,
  method         TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  did_document   TEXT NOT NULL,
  created_at     BIGINT NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_ephemeral_sessions (
  id             VARCHAR(191)    NOT NULL PRIMARY KEY,
  agent_id       VARCHAR(191)    NOT NULL,
  owner_id       VARCHAR(191)    NOT NULL,
  token_hash     VARCHAR(191)    NOT NULL UNIQUE,
  expires_at     BIGINT   NOT NULL,
  max_actions    INTEGER,
  actions_used   INTEGER NOT NULL DEFAULT 0,
  status         VARCHAR(191)    NOT NULL DEFAULT 'active',
  audit_group_id TEXT    NOT NULL,
  created_at     BIGINT   NOT NULL,
  updated_at     BIGINT   NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES theauth_agents(id) ON DELETE CASCADE,
  FOREIGN KEY (owner_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_ephemeral_sessions_owner_status
  ON theauth_ephemeral_sessions (owner_id, status);

CREATE INDEX theauth_ephemeral_sessions_expires_at
  ON theauth_ephemeral_sessions (expires_at);

CREATE TABLE IF NOT EXISTS theauth_oauth_clients (
  id                          VARCHAR(191)    NOT NULL PRIMARY KEY,
  client_id                   VARCHAR(191)    NOT NULL UNIQUE,
  client_secret               TEXT,
  client_name                 TEXT,
  client_uri                  TEXT,
  redirect_uris               JSON NOT NULL,
  grant_types                 JSON NOT NULL,
  response_types              JSON NOT NULL,
  token_endpoint_auth_method  VARCHAR(191)    NOT NULL DEFAULT 'client_secret_basic',
  type                        VARCHAR(191)    NOT NULL DEFAULT 'confidential',
  disabled                    TINYINT(1) NOT NULL DEFAULT 0,
  metadata                    JSON,
  created_at                  BIGINT   NOT NULL,
  updated_at                  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oauth_access_tokens (
  id                        VARCHAR(191) NOT NULL PRIMARY KEY,
  access_token              VARCHAR(191) NOT NULL UNIQUE,
  refresh_token             VARCHAR(191) UNIQUE,
  client_id                 VARCHAR(191) NOT NULL,
  user_id                   VARCHAR(191) NOT NULL,
  scopes                    TEXT NOT NULL,
  resource                  TEXT,
  access_token_expires_at   BIGINT NOT NULL,
  refresh_token_expires_at  BIGINT,
  created_at                BIGINT NOT NULL,
  FOREIGN KEY (client_id) REFERENCES theauth_oauth_clients(client_id),
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oauth_authorization_codes (
  id                     VARCHAR(191) NOT NULL PRIMARY KEY,
  code                   VARCHAR(191) NOT NULL UNIQUE,
  client_id              VARCHAR(191) NOT NULL,
  user_id                VARCHAR(191) NOT NULL,
  redirect_uri           TEXT NOT NULL,
  scopes                 TEXT NOT NULL,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  resource               TEXT,
  expires_at             BIGINT NOT NULL,
  created_at             BIGINT NOT NULL,
  FOREIGN KEY (client_id) REFERENCES theauth_oauth_clients(client_id),
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oauth_accounts (
  id                   VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id              TEXT NOT NULL,
  provider             TEXT NOT NULL,
  provider_account_id  TEXT NOT NULL,
  access_token         TEXT NOT NULL,
  refresh_token        TEXT,
  expires_at           BIGINT,
  created_at           BIGINT NOT NULL,
  updated_at           BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oauth_states (
  state          VARCHAR(191) NOT NULL PRIMARY KEY,
  code_verifier  TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  provider       TEXT NOT NULL,
  expires_at     BIGINT NOT NULL,
  created_at     BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_passkey_credentials (
  id            VARCHAR(191)    NOT NULL PRIMARY KEY,
  user_id       VARCHAR(191)    NOT NULL,
  credential_id VARCHAR(191)    NOT NULL UNIQUE,
  public_key    TEXT    NOT NULL,
  counter       INTEGER NOT NULL DEFAULT 0,
  device_name   TEXT,
  transports    TEXT,
  created_at    BIGINT   NOT NULL,
  last_used_at  BIGINT   NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_passkey_challenges (
  id         VARCHAR(191) NOT NULL PRIMARY KEY,
  challenge  VARCHAR(191) NOT NULL UNIQUE,
  user_id    TEXT,
  type       TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_one_time_tokens (
  id          VARCHAR(191)    NOT NULL PRIMARY KEY,
  token_hash  VARCHAR(191)    NOT NULL UNIQUE,
  purpose     TEXT    NOT NULL,
  identifier  TEXT    NOT NULL,
  metadata    JSON,
  used        TINYINT(1) NOT NULL DEFAULT 0,
  expires_at  BIGINT   NOT NULL,
  created_at  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_magic_links (
  id         VARCHAR(191)    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  token      VARCHAR(191)    NOT NULL UNIQUE,
  expires_at BIGINT   NOT NULL,
  used       TINYINT(1) NOT NULL DEFAULT 0,
  created_at BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_email_otps (
  id         VARCHAR(191)    NOT NULL PRIMARY KEY,
  email      TEXT    NOT NULL,
  code_hash  TEXT    NOT NULL,
  expires_at BIGINT   NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_totp (
  user_id      VARCHAR(191)    NOT NULL PRIMARY KEY,
  secret       TEXT    NOT NULL,
  enabled      TINYINT(1) NOT NULL DEFAULT 0,
  backup_codes JSON NOT NULL,
  created_at   BIGINT   NOT NULL,
  updated_at   BIGINT   NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_sso_connections (
  id          VARCHAR(191)    NOT NULL PRIMARY KEY,
  org_id      TEXT    NOT NULL,
  provider_id TEXT    NOT NULL,
  type        TEXT    NOT NULL,
  domain      VARCHAR(191)    NOT NULL UNIQUE,
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_api_keys (
  id           VARCHAR(191)    NOT NULL PRIMARY KEY,
  user_id      VARCHAR(191)    NOT NULL,
  name         TEXT    NOT NULL,
  key_hash     TEXT    NOT NULL,
  key_prefix   TEXT    NOT NULL,
  permissions  JSON NOT NULL,
  expires_at   BIGINT,
  last_used_at BIGINT,
  created_at   BIGINT   NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_username_accounts (
  id            VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id       VARCHAR(191) NOT NULL,
  username      VARCHAR(191) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_phone_verifications (
  id           VARCHAR(191)    NOT NULL PRIMARY KEY,
  phone_number TEXT    NOT NULL,
  code_hash    TEXT    NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  expires_at   BIGINT   NOT NULL,
  created_at   BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_trusted_devices (
  id          VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id     VARCHAR(191) NOT NULL,
  fingerprint TEXT NOT NULL,
  label       TEXT NOT NULL,
  trusted_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_login_history (
  id         VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id    VARCHAR(191) NOT NULL,
  method     TEXT NOT NULL,
  ip         TEXT,
  user_agent TEXT,
  timestamp  BIGINT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_login_history_user_ts
  ON theauth_login_history (user_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS theauth_jwt_refresh_tokens (
  id          VARCHAR(191)    NOT NULL PRIMARY KEY,
  token_hash  VARCHAR(191)    NOT NULL UNIQUE,
  user_id     VARCHAR(191)    NOT NULL,
  used        TINYINT(1) NOT NULL DEFAULT 0,
  expires_at  BIGINT   NOT NULL,
  created_at  BIGINT   NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_jwt_refresh_tokens_user_id
  ON theauth_jwt_refresh_tokens (user_id);

CREATE TABLE IF NOT EXISTS theauth_refresh_token_families (
  id                   VARCHAR(191)    NOT NULL PRIMARY KEY,
  user_id              VARCHAR(191)    NOT NULL,
  absolute_expires_at  BIGINT   NOT NULL,
  revoked              TINYINT(1) NOT NULL DEFAULT 0,
  created_at           BIGINT   NOT NULL,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_refresh_token_families_user_id
  ON theauth_refresh_token_families (user_id);

CREATE TABLE IF NOT EXISTS theauth_refresh_tokens (
  id          VARCHAR(191)    NOT NULL PRIMARY KEY,
  family_id   VARCHAR(191)    NOT NULL,
  token_hash  VARCHAR(191)    NOT NULL UNIQUE,
  used        BIGINT NOT NULL DEFAULT 0,
  expires_at  BIGINT   NOT NULL,
  created_at  BIGINT   NOT NULL,
  FOREIGN KEY (family_id) REFERENCES theauth_refresh_token_families(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_refresh_tokens_family_id
  ON theauth_refresh_tokens (family_id);

CREATE TABLE IF NOT EXISTS theauth_organizations (
  id         VARCHAR(191)    NOT NULL PRIMARY KEY,
  name       TEXT    NOT NULL,
  slug       VARCHAR(191)    NOT NULL UNIQUE,
  owner_id   VARCHAR(191)    NOT NULL,
  metadata   JSON,
  created_at BIGINT   NOT NULL,
  updated_at BIGINT   NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_org_members (
  id        VARCHAR(191)    NOT NULL PRIMARY KEY,
  org_id    VARCHAR(191)    NOT NULL,
  user_id   VARCHAR(191)    NOT NULL,
  role      VARCHAR(191)    NOT NULL DEFAULT 'member',
  joined_at BIGINT   NOT NULL,
  UNIQUE(org_id, user_id),
  FOREIGN KEY (org_id) REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_org_invitations (
  id         VARCHAR(191)    NOT NULL PRIMARY KEY,
  org_id     VARCHAR(191)    NOT NULL,
  email      TEXT    NOT NULL,
  role       VARCHAR(191)    NOT NULL DEFAULT 'member',
  invited_by VARCHAR(191)    NOT NULL,
  status     VARCHAR(191)    NOT NULL DEFAULT 'pending',
  expires_at BIGINT   NOT NULL,
  created_at BIGINT   NOT NULL,
  FOREIGN KEY (org_id) REFERENCES theauth_organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (invited_by) REFERENCES theauth_users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_org_roles (
  id          VARCHAR(191)    NOT NULL PRIMARY KEY,
  org_id      VARCHAR(191)    NOT NULL,
  name        VARCHAR(191)    NOT NULL,
  permissions JSON NOT NULL,
  UNIQUE(org_id, name),
  FOREIGN KEY (org_id) REFERENCES theauth_organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_vault_connections (
  id                  VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id             VARCHAR(191) NOT NULL,
  tenant_id           VARCHAR(191) NOT NULL DEFAULT '',
  provider            VARCHAR(191) NOT NULL,
  provider_account_id TEXT NOT NULL,
  access_token_enc    TEXT NOT NULL,
  refresh_token_enc   TEXT,
  key_id              TEXT NOT NULL,
  scopes              JSON NOT NULL,
  status              VARCHAR(191) NOT NULL DEFAULT 'active',
  expires_at          BIGINT,
  created_at          BIGINT NOT NULL,
  updated_at          BIGINT NOT NULL,
  UNIQUE (user_id, tenant_id, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_vault_consents (
  id                  VARCHAR(191) NOT NULL PRIMARY KEY,
  user_id             TEXT NOT NULL,
  agent_id            TEXT NOT NULL,
  tenant_id           VARCHAR(191) NOT NULL DEFAULT '',
  provider            TEXT NOT NULL,
  scopes              JSON NOT NULL,
  delegation_chain_id TEXT,
  expires_at          BIGINT,
  revoked_at          BIGINT,
  created_at          BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_ssf_streams (
  id                        VARCHAR(191) NOT NULL PRIMARY KEY,
  owner                     TEXT NOT NULL,
  aud                       JSON NOT NULL,
  events_requested          JSON NOT NULL,
  events_delivered          JSON NOT NULL,
  delivery_method           TEXT NOT NULL,
  endpoint_url              TEXT,
  authorization_header      TEXT,
  status                    VARCHAR(191) NOT NULL DEFAULT 'enabled',
  status_reason             TEXT,
  subject_mode              VARCHAR(191) NOT NULL DEFAULT 'all',
  description               TEXT,
  min_verification_interval INTEGER,
  last_verified_at          BIGINT,
  created_at                BIGINT NOT NULL,
  updated_at                BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_ssf_subjects (
  id               VARCHAR(191) NOT NULL PRIMARY KEY,
  stream_id        VARCHAR(191) NOT NULL,
  subject_key_hash VARCHAR(191) NOT NULL,
  subject          JSON NOT NULL,
  verified         INTEGER NOT NULL DEFAULT 1,
  created_at       BIGINT NOT NULL,
  UNIQUE (stream_id, subject_key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_ssf_outbox (
  jti             VARCHAR(191) NOT NULL PRIMARY KEY,
  stream_id       VARCHAR(191) NOT NULL,
  jwt             TEXT NOT NULL,
  status          VARCHAR(191) NOT NULL DEFAULT 'pending',
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at BIGINT NOT NULL,
  last_error      TEXT,
  created_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oidc_clients (
  id                          VARCHAR(191)    NOT NULL PRIMARY KEY,
  client_id                   VARCHAR(191)    NOT NULL UNIQUE,
  client_secret_hash          TEXT    NOT NULL,
  client_name                 TEXT    NOT NULL,
  redirect_uris               JSON NOT NULL,
  grant_types                 JSON NOT NULL,
  response_types              JSON NOT NULL,
  scopes                      JSON NOT NULL,
  token_endpoint_auth_method  VARCHAR(191)    NOT NULL DEFAULT 'client_secret_post',
  created_at                  BIGINT   NOT NULL,
  updated_at                  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oidc_auth_codes (
  id                     VARCHAR(191)    NOT NULL PRIMARY KEY,
  code_hash              VARCHAR(191)    NOT NULL UNIQUE,
  client_id              TEXT    NOT NULL,
  user_id                TEXT    NOT NULL,
  redirect_uri           TEXT    NOT NULL,
  scopes                 TEXT    NOT NULL,
  nonce                  TEXT,
  code_challenge         TEXT,
  code_challenge_method  TEXT,
  used                   TINYINT(1) NOT NULL DEFAULT 0,
  expires_at             BIGINT   NOT NULL,
  created_at             BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oidc_refresh_tokens (
  id          VARCHAR(191)    NOT NULL PRIMARY KEY,
  token_hash  VARCHAR(191)    NOT NULL UNIQUE,
  client_id   TEXT    NOT NULL,
  user_id     TEXT    NOT NULL,
  scopes      TEXT    NOT NULL,
  revoked     TINYINT(1) NOT NULL DEFAULT 0,
  expires_at  BIGINT   NOT NULL,
  created_at  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oidc_logout_clients (
  client_id                   VARCHAR(191) NOT NULL PRIMARY KEY,
  post_logout_redirect_uris   JSON NOT NULL,
  backchannel_logout_uri      TEXT,
  updated_at                  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_oidc_sessions (
  id          VARCHAR(191) NOT NULL PRIMARY KEY,
  sid         VARCHAR(191) NOT NULL,
  session_id  VARCHAR(191),
  user_id     VARCHAR(191) NOT NULL,
  client_id   VARCHAR(191) NOT NULL,
  code_hash   VARCHAR(191),
  created_at  BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_oidc_sessions_sid
  ON theauth_oidc_sessions (sid);

CREATE INDEX theauth_oidc_sessions_session
  ON theauth_oidc_sessions (session_id);

CREATE TABLE IF NOT EXISTS theauth_rebac_resources (
  id          VARCHAR(191) NOT NULL PRIMARY KEY,
  type        TEXT NOT NULL,
  parent_id   VARCHAR(191),
  parent_type VARCHAR(191),
  created_at  BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_rebac_resources_parent
  ON theauth_rebac_resources (parent_id, parent_type);

CREATE TABLE IF NOT EXISTS theauth_rebac_relationships (
  id           VARCHAR(191) NOT NULL PRIMARY KEY,
  subject_type VARCHAR(128) NOT NULL,
  subject_id   VARCHAR(191) NOT NULL,
  relation     VARCHAR(128) NOT NULL,
  object_type  VARCHAR(128) NOT NULL,
  object_id    VARCHAR(191) NOT NULL,
  created_at   BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_rebac_relationships_subject
  ON theauth_rebac_relationships (subject_type, subject_id);

CREATE INDEX theauth_rebac_relationships_object
  ON theauth_rebac_relationships (object_type, object_id);

CREATE UNIQUE INDEX theauth_rebac_relationships_tuple
  ON theauth_rebac_relationships (subject_type, subject_id, relation, object_type, object_id);

CREATE TABLE IF NOT EXISTS theauth_federation_instances (
  id            VARCHAR(191) NOT NULL PRIMARY KEY,
  instance_id   VARCHAR(191) NOT NULL UNIQUE,
  instance_url  TEXT NOT NULL,
  public_key_jwk TEXT,
  trust_level   VARCHAR(191) NOT NULL DEFAULT 'verify-only',
  discovered_at BIGINT,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS theauth_federation_tokens (
  id                  VARCHAR(191)    NOT NULL PRIMARY KEY,
  token_jti           VARCHAR(191)    NOT NULL UNIQUE,
  agent_id            VARCHAR(191)    NOT NULL,
  source_instance_id  VARCHAR(191)    NOT NULL,
  target_instance_id  TEXT,
  direction           TEXT    NOT NULL,
  permissions         JSON NOT NULL,
  trust_score         INTEGER,
  expires_at          BIGINT   NOT NULL,
  created_at          BIGINT   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_federation_tokens_agent
  ON theauth_federation_tokens (agent_id);

CREATE INDEX theauth_federation_tokens_source
  ON theauth_federation_tokens (source_instance_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0000', 'baseline', '4ddbc1eb2fcce97315facf194c54bf061e6fcf3590c1466b8509b8131c713038', UTC_TIMESTAMP(3));
