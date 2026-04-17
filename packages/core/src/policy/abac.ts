/**
 * ABAC primitives: resource/action matching, IP allowlist, time windows,
 * rate limits, argument pattern validation. Extracted from the legacy
 * permission/engine.ts so both the legacy authorize() and the new unified
 * policy engine can share one implementation.
 */

import { and, eq, gte } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { rateLimits } from "../db/schema.js";
import type { PermissionConstraints } from "../types.js";

export interface ConstraintEvaluationInput {
	subjectId: string; // agent id used for rate-limit row keying; "" if subject has no agent
	resource: string;
	arguments?: Record<string, unknown>;
	ip?: string;
}

export interface ConstraintResult {
	allowed: boolean;
	reason?: string;
}

/**
 * Match a resource pattern against a requested resource.
 * Supports wildcards: "mcp:github:*", "tool:*", "*".
 */
export function matchResource(pattern: string, resource: string): boolean {
	if (pattern === "*") return true;

	const patternParts = pattern.split(":");
	const resourceParts = resource.split(":");

	for (let i = 0; i < patternParts.length; i++) {
		const part = patternParts[i];
		if (part === "*") return true;
		if (part !== resourceParts[i]) return false;
	}

	return patternParts.length === resourceParts.length;
}

/**
 * Check if an action is allowed by a permission's actions list.
 */
export function matchAction(allowedActions: string[], requestedAction: string): boolean {
	return allowedActions.includes(requestedAction) || allowedActions.includes("*");
}

function parseIPv4(ip: string): number | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	let result = 0;
	for (const part of parts) {
		const num = parseInt(part, 10);
		if (Number.isNaN(num) || num < 0 || num > 255) return null;
		result = (result << 8) | num;
	}
	return result >>> 0;
}

function matchesIPEntry(entry: string, ip: string): boolean {
	const slashIndex = entry.indexOf("/");
	if (slashIndex === -1) {
		return entry === ip;
	}

	const cidrIp = entry.slice(0, slashIndex);
	const prefixLen = parseInt(entry.slice(slashIndex + 1), 10);
	if (Number.isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return false;

	const entryNum = parseIPv4(cidrIp);
	const ipNum = parseIPv4(ip);
	if (entryNum === null || ipNum === null) return false;

	const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
	return (entryNum & mask) === (ipNum & mask);
}

/**
 * Check whether an IP is in the allowlist (exact IPs or CIDR ranges).
 * Exported for the legacy permission engine.
 */
export function isIPAllowed(allowlist: string[], ip: string): boolean {
	return allowlist.some((entry) => matchesIPEntry(entry, ip));
}

/**
 * Validate request arguments against allowed regex patterns. All string-typed
 * argument values must match every pattern, otherwise the request is denied.
 */
export function validateArgPatterns(
	patterns: string[],
	args: Record<string, unknown>,
): { valid: boolean; reason?: string } {
	for (const pattern of patterns) {
		const regex = new RegExp(pattern);
		for (const [key, value] of Object.entries(args)) {
			if (typeof value === "string" && !regex.test(value)) {
				return {
					valid: false,
					reason: `Argument "${key}" value "${value}" does not match pattern "${pattern}"`,
				};
			}
		}
	}
	return { valid: true };
}

/**
 * Sliding-window rate limit check. Increments the per-agent counter as a
 * side effect when the request is allowed. Skipped entirely when subjectId
 * is empty (RBAC-only requests for human users do not consume agent quota).
 */
export async function checkRateLimit(
	db: Database,
	agentId: string,
	resource: string,
	maxCallsPerHour: number,
): Promise<ConstraintResult> {
	if (!agentId) {
		return { allowed: true };
	}

	const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

	const rows = await db
		.select()
		.from(rateLimits)
		.where(
			and(
				eq(rateLimits.agentId, agentId),
				eq(rateLimits.resource, resource),
				gte(rateLimits.windowStart, oneHourAgo),
			),
		);

	const totalCalls = rows.reduce((sum, r) => sum + r.count, 0);

	if (totalCalls >= maxCallsPerHour) {
		return {
			allowed: false,
			reason: `Rate limit exceeded: ${totalCalls}/${maxCallsPerHour} calls per hour for resource "${resource}"`,
		};
	}

	const currentWindow = new Date(Math.floor(Date.now() / (5 * 60 * 1000)) * (5 * 60 * 1000));
	const existing = rows.find((r) => r.windowStart.getTime() === currentWindow.getTime());

	if (existing) {
		await db
			.update(rateLimits)
			.set({ count: existing.count + 1 })
			.where(eq(rateLimits.id, existing.id));
	} else {
		await db.insert(rateLimits).values({
			id: generateId(),
			agentId,
			resource,
			windowStart: currentWindow,
			count: 1,
		});
	}

	return { allowed: true };
}

/**
 * Evaluate every constraint on a permission. Returns the first failure, or
 * { allowed: true } if all pass. Constraint order: rate limit, arg patterns,
 * approval, time window, IP allowlist.
 */
export async function evaluateConstraints(
	db: Database,
	input: ConstraintEvaluationInput,
	constraints: PermissionConstraints,
): Promise<ConstraintResult> {
	if (constraints.maxCallsPerHour) {
		const rateResult = await checkRateLimit(
			db,
			input.subjectId,
			input.resource,
			constraints.maxCallsPerHour,
		);
		if (!rateResult.allowed) {
			return rateResult;
		}
	}

	if (constraints.allowedArgPatterns && input.arguments) {
		const patternResult = validateArgPatterns(constraints.allowedArgPatterns, input.arguments);
		if (!patternResult.valid) {
			return { allowed: false, reason: patternResult.reason };
		}
	}

	if (constraints.requireApproval) {
		return {
			allowed: false,
			reason: "This action requires human approval before execution",
		};
	}

	if (constraints.timeWindow) {
		const now = new Date();
		const hours = now.getHours();
		const minutes = now.getMinutes();
		const currentTime = `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;

		if (currentTime < constraints.timeWindow.start || currentTime > constraints.timeWindow.end) {
			return {
				allowed: false,
				reason: `Action is only allowed between ${constraints.timeWindow.start} and ${constraints.timeWindow.end}`,
			};
		}
	}

	if (constraints.ipAllowlist && constraints.ipAllowlist.length > 0) {
		if (!input.ip) {
			return {
				allowed: false,
				reason: "IP_NOT_ALLOWED: No IP address provided; resource requires an IP allowlist match",
			};
		}
		if (!isIPAllowed(constraints.ipAllowlist, input.ip)) {
			return {
				allowed: false,
				reason: `IP_NOT_ALLOWED: IP "${input.ip}" is not in the allowlist for this resource`,
			};
		}
	}

	return { allowed: true };
}

/**
 * Returns true when the constraint result depends on per-call state or input,
 * so the decision must NOT be cached:
 *  - maxCallsPerHour: counter changes every call
 *  - timeWindow: result flips at window boundaries
 *  - allowedArgPatterns: result depends on context.arguments, which are not
 *    part of the cache key. Caching could otherwise let safe-args permits
 *    serve unsafe-args requests.
 */
export function isCacheUnsafe(constraints?: PermissionConstraints): boolean {
	if (!constraints) return false;
	return (
		Boolean(constraints.maxCallsPerHour) ||
		Boolean(constraints.timeWindow) ||
		(Array.isArray(constraints.allowedArgPatterns) && constraints.allowedArgPatterns.length > 0)
	);
}
