/* Migration 0013: approval-quorum */

ALTER TABLE theauth_approval_requests ADD COLUMN required_approvals INTEGER;

CREATE TABLE IF NOT EXISTS theauth_approval_votes (
  approval_id  VARCHAR(191) NOT NULL,
  approver_id  VARCHAR(191) NOT NULL,
  decided_at   BIGINT NOT NULL,
  approver_acr TEXT,
  PRIMARY KEY (approval_id, approver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0013', 'approval-quorum', '48885e532a33c1ace5cda0fcc4e46bb225010ad257b384767221fbc8e8ed60f7', UTC_TIMESTAMP(3));
