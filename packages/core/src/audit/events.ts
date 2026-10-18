import type { AuditEvent } from "../types.js";

/**
 * Actions that are themselves event names. Writers that predate the `event` column (approval,
 * vault, cascade revoke, checkpoint, erasure) keep their `action` text, which is hashed, and get
 * the same string as `event` here. Anything else gets no derived event: the writer sets it or it
 * stays NULL rather than guessing.
 */
const ACTION_IS_EVENT: ReadonlySet<string> = new Set([
	"agent.cascade.revoked",
	"approval.request",
	"approval.approve",
	"approval.deny",
	"vault.read",
	"audit.checkpoint",
	"audit.write_failed",
	"audit.erasure",
]);

/** The event to store when a writer did not pass one. */
export function eventForAction(action: string): AuditEvent | null {
	return ACTION_IS_EVENT.has(action) ? action : null;
}
