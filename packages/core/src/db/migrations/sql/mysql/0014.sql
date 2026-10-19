/* Migration 0014: hot-path-indexes */

CREATE INDEX theauth_agents_token_hash ON theauth_agents (token_hash(191));

CREATE INDEX theauth_agents_owner_status ON theauth_agents (owner_id, status);

CREATE INDEX theauth_delegation_chains_to ON theauth_delegation_chains (to_agent_id(191), status(16));

CREATE INDEX theauth_delegation_chains_from ON theauth_delegation_chains (from_agent_id(191), status(16));

CREATE INDEX theauth_rate_limits_lookup ON theauth_rate_limits (agent_id, resource(191), window_start);

CREATE INDEX theauth_approval_requests_status ON theauth_approval_requests (status, created_at);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0014', 'hot-path-indexes', 'a70c746e3dc8f79a3dcbbbea4dec1c2350fd2230691823a8c93c81b63b0cc346', UTC_TIMESTAMP(3));
