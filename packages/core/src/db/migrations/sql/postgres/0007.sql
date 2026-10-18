/* Migration 0007: mcp-revocation */

CREATE TABLE IF NOT EXISTS theauth_mcp_revocations (
  kind          TEXT NOT NULL,
  id            TEXT NOT NULL,
  revoked_at_ms BIGINT NOT NULL,
  expires_at    BIGINT NOT NULL,
  reason        TEXT NOT NULL,
  source_id     TEXT,
  PRIMARY KEY (kind, id)
);

CREATE INDEX IF NOT EXISTS theauth_mcp_revocations_exp ON theauth_mcp_revocations (expires_at);

CREATE INDEX IF NOT EXISTS theauth_mcp_revocations_ms ON theauth_mcp_revocations (revoked_at_ms);

CREATE INDEX IF NOT EXISTS theauth_delegation_chains_to ON theauth_delegation_chains (to_agent_id, status);

CREATE INDEX IF NOT EXISTS theauth_delegation_chains_from ON theauth_delegation_chains (from_agent_id, status);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0007', 'mcp-revocation', 'cb6616a6700b744d725737aa52752dcfebda204a6787d4b52e0c47488d65a059', NOW());
