/* Migration 0013: approval-quorum */

ALTER TABLE theauth_approval_requests ADD COLUMN required_approvals INTEGER;

CREATE TABLE IF NOT EXISTS theauth_approval_votes (
  approval_id  TEXT NOT NULL,
  approver_id  TEXT NOT NULL,
  decided_at   INTEGER NOT NULL,
  approver_acr TEXT,
  PRIMARY KEY (approval_id, approver_id)
);

INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0013', 'approval-quorum', '6a3e08a4157d75a25db84347db50dba0194a77bfde16393f9d9113e24798ad2d', CAST(strftime('%s', 'now') AS INTEGER));
