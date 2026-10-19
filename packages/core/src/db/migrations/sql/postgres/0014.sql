/* Migration 0014: hot-path-indexes */

CREATE INDEX IF NOT EXISTS theauth_agents_token_hash ON theauth_agents (token_hash);

CREATE INDEX IF NOT EXISTS theauth_agents_owner_status ON theauth_agents (owner_id, status);

CREATE INDEX IF NOT EXISTS theauth_delegation_chains_to ON theauth_delegation_chains (to_agent_id, status);

CREATE INDEX IF NOT EXISTS theauth_delegation_chains_from ON theauth_delegation_chains (from_agent_id, status);

CREATE INDEX IF NOT EXISTS theauth_rate_limits_lookup ON theauth_rate_limits (agent_id, resource, window_start);

CREATE INDEX IF NOT EXISTS theauth_approval_requests_status ON theauth_approval_requests (status, created_at);

CREATE INDEX IF NOT EXISTS theauth_permissions_agent ON theauth_permissions (agent_id);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0014', 'hot-path-indexes', '8f376a5761e217cd55715058caaf0adfd4685e5c5b5ffebe6251c040178376c5', NOW());
