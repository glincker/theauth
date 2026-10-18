import type { Migration } from "../migrate/types.js";

/**
 * A single event vocabulary for audit rows. `event` says what happened (authorize, policy.evaluate, delegation.create, ...), `action` keeps the domain verb (read, write, the tool name). Nullable, so rows from unknown writers read back with no event.
 *
 * The column is NOT part of the audit hash payload (hash version stays 2), so existing chains keep verifying. Rows already written keep their `action` text, because it is hashed.
 *
 * Backfill, only for rows with no event (reruns are no-ops):
 * 1. rows whose action is itself an event name get event = action;
 * 2. policy engine rows (they carry input provenance) get policy.evaluate;
 * 3. remaining rows with a decision code are authorization rows and get authorize;
 * 4. anything else stays NULL rather than guessing.
 */
const KNOWN_ACTIONS =
	"('delegation.create', 'delegation.revoke', 'agent.cascade.revoked', 'approval.request', 'approval.approve', 'approval.deny', 'vault.read', 'audit.checkpoint', 'audit.write_failed', 'audit.erasure')";

const BACKFILL = [
	`UPDATE theauth_audit_logs SET event = action WHERE event IS NULL AND action IN ${KNOWN_ACTIONS}`,
	"UPDATE theauth_audit_logs SET event = 'policy.evaluate' WHERE event IS NULL AND input_provenance IS NOT NULL AND decision_code IS NOT NULL",
	"UPDATE theauth_audit_logs SET event = 'authorize' WHERE event IS NULL AND decision_code IS NOT NULL",
];

export const auditEvent: Migration = {
	id: "0005",
	name: "audit-event",
	requires: ["audit"],
	up: {
		sqlite: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN event TEXT",
			...BACKFILL,
			"CREATE INDEX IF NOT EXISTS theauth_audit_logs_event ON theauth_audit_logs (agent_id, event, recorded_at_ms)",
		],
		postgres: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN IF NOT EXISTS event TEXT",
			...BACKFILL,
			"CREATE INDEX IF NOT EXISTS theauth_audit_logs_event ON theauth_audit_logs (agent_id, event, recorded_at_ms)",
		],
		mysql: [
			"ALTER TABLE theauth_audit_logs ADD COLUMN event TEXT",
			...BACKFILL,
			"CREATE INDEX theauth_audit_logs_event ON theauth_audit_logs (agent_id(191), event(64), recorded_at_ms)",
		],
	},
};
