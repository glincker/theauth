-- TheAuth demo worker schema. Generated from createTables() for the sqlite dialect
-- with the agents and audit features enabled (see tests/migration.test.ts, which
-- fails when this file drifts from the SDK).

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
  relation    TEXT,
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
  cache_hit    INTEGER NOT NULL DEFAULT 0,
  timestamp    INTEGER   NOT NULL,
  chain_seq    INTEGER,
  prev_hash    TEXT,
  hash         TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS theauth_audit_logs_chain
  ON theauth_audit_logs (agent_id, chain_seq);

CREATE TABLE IF NOT EXISTS theauth_rate_limits (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES theauth_agents(id) ON DELETE CASCADE,
  resource     TEXT    NOT NULL,
  window_start INTEGER   NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0
);

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
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_trust_scores (
  agent_id    TEXT    NOT NULL PRIMARY KEY REFERENCES theauth_agents(id) ON DELETE CASCADE,
  score       INTEGER NOT NULL,
  level       TEXT    NOT NULL,
  factors     TEXT NOT NULL,
  computed_at INTEGER   NOT NULL
);

CREATE TABLE IF NOT EXISTS theauth_secondary_storage (
  storage_key TEXT NOT NULL PRIMARY KEY,
  value       TEXT,
  counter     INTEGER,
  expires_at  BIGINT
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

CREATE UNIQUE INDEX IF NOT EXISTS theauth_audit_logs_chain ON theauth_audit_logs (agent_id, chain_seq);
