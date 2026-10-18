import type { Migration } from "../migrate/types.js";

/**
 * The machine-readable DecisionCode of an authorization outcome (for example allowed, no_permission, hook_denied, hook_timeout). Nullable, so rows written before this migration stay valid and read back with no code.
 *
 * The column is NOT part of the audit hash payload (hash version stays 2), so existing chains and the Go verifier keep verifying. `reason` remains the hashed text.
 */
export const auditDecisionCode: Migration = {
	id: "0002",
	name: "audit-decision-code",
	requires: ["audit"],
	up: {
		sqlite: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN decision_code TEXT",
			"CREATE INDEX IF NOT EXISTS theauth_audit_logs_code ON theauth_audit_logs (agent_id, decision_code)",
		],
		postgres: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS decision_code TEXT",
			"CREATE INDEX IF NOT EXISTS theauth_audit_logs_code ON theauth_audit_logs (agent_id, decision_code)",
		],
		mysql: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN decision_code TEXT",
			"CREATE INDEX theauth_audit_logs_code ON theauth_audit_logs (agent_id(191), decision_code(64))",
		],
	},
};
