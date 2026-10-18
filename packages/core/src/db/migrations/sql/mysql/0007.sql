/* Migration 0007: mcp-revocation */

CREATE TABLE IF NOT EXISTS theauth_mcp_revocations (
  kind          VARCHAR(16) NOT NULL,
  id            VARCHAR(191) NOT NULL,
  revoked_at_ms BIGINT NOT NULL,
  expires_at    BIGINT NOT NULL,
  reason        TEXT NOT NULL,
  source_id     TEXT,
  PRIMARY KEY (kind, id)
);

CREATE INDEX theauth_mcp_revocations_exp ON theauth_mcp_revocations (expires_at);

CREATE INDEX theauth_mcp_revocations_ms ON theauth_mcp_revocations (revoked_at_ms);

CREATE INDEX theauth_delegation_chains_to ON theauth_delegation_chains (to_agent_id(191), status(16));

CREATE INDEX theauth_delegation_chains_from ON theauth_delegation_chains (from_agent_id(191), status(16));

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0007', 'mcp-revocation', '6acc02d1601c4168c35ccf9c3d23960ef3fc87a1da53c55a7b76c17987d3e584', NOW(3));
