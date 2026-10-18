/* Migration 0013: approval-quorum */

ALTER TABLE theauth_approval_requests ADD COLUMN IF NOT EXISTS required_approvals INTEGER;

CREATE TABLE IF NOT EXISTS theauth_approval_votes (
  approval_id  TEXT NOT NULL,
  approver_id  TEXT NOT NULL,
  decided_at   BIGINT NOT NULL,
  approver_acr TEXT,
  PRIMARY KEY (approval_id, approver_id)
);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0013', 'approval-quorum', '0354a664fc46019e6efb140bf812aacbbc7f58547f2a681c1af05b7cfc6f0968', NOW());
