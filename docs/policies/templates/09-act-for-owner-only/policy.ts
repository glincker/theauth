/**
 * Template 09, Agent acts only for its owner, within delegated scope
 *
 * The owner's agent holds the broad permission. A worker agent receives a
 * narrow, short-lived subset through theauth.delegate() and holds no
 * permissions of its own. Two engine checks keep the worker on the owner's
 * side:
 *
 *   1. subject.ownerId on evaluate(): denied with POLICY_OWNER_MISMATCH unless
 *      it equals the agent's ownerId.
 *   2. Delegation constraints: stored on the chain, narrowed against the
 *      parent, and enforced by evaluate().
 *
 * Seeding:
 *   1. Create ownerAgent with ownerAgentPermissions (ownerId = the user).
 *   2. Create workerAgent with permissions: [] and type "delegated"
 *      (ownerId = the same user).
 *   3. Call theauth.delegate({ fromAgent: ownerAgent.id, toAgent: workerAgent.id,
 *        permissions: workerDelegation, expiresAt, maxDepth: 1 }).
 *   4. Call theauth.policy.evaluate({ subject: { agentId, ownerId }, ... })
 *      with the owner id taken from the authenticated request.
 */

import type { Permission } from "../../../../packages/core/src/index.js";

export const OWNER_ID = "user-123";

/** Held by the owner's own agent. */
export const ownerAgentPermissions: Permission[] = [
	{
		resource: `files:${OWNER_ID}:*`,
		actions: ["read", "write"],
		constraints: { maxCallsPerHour: 200 },
	},
];

/**
 * Delegated to the worker: read only, one project, a lower call cap. The cap
 * is min(parent, child), so asking for more than 200 still yields 200.
 */
export const workerDelegation: Permission[] = [
	{
		resource: `files:${OWNER_ID}:project-a`,
		actions: ["read"],
		constraints: { maxCallsPerHour: 30 },
	},
];
