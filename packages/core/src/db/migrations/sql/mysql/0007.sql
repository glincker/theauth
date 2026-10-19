/* Migration 0007: mcp-revocation */

CREATE TABLE IF NOT EXISTS theauth_mcp_revocations (
  kind          VARCHAR(16) NOT NULL,
  id            VARCHAR(191) NOT NULL,
  revoked_at_ms BIGINT NOT NULL,
  expires_at    BIGINT NOT NULL,
  reason        TEXT NOT NULL,
  source_id     TEXT,
  PRIMARY KEY (kind, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE INDEX theauth_mcp_revocations_exp ON theauth_mcp_revocations (expires_at);

CREATE INDEX theauth_mcp_revocations_ms ON theauth_mcp_revocations (revoked_at_ms);

CREATE INDEX theauth_delegation_chains_to ON theauth_delegation_chains (to_agent_id(191), status(16));

CREATE INDEX theauth_delegation_chains_from ON theauth_delegation_chains (from_agent_id(191), status(16));

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0007', 'mcp-revocation', 'a027b3fd5f6be498d798b72c32ec31cfaa07a26f6451eca73bbbea0b30b9f194', UTC_TIMESTAMP(3));
