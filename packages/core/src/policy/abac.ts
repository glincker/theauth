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
import type { Permission, PermissionConstraints } from "../types.js";

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
			reason: rateLimitReason(totalCalls, maxCallsPerHour, resource),
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

/** Message used when an hourly call budget is spent. Shared by the real and simulated paths. */
export function rateLimitReason(totalCalls: number, max: number, resource: string): string {
	return `Rate limit exceeded: ${totalCalls}/${max} calls per hour for resource "${resource}"`;
}

/**
 * Find the first permission that grants `action` on `resource`. Shared by the
 * real authorize path and the simulator so both pick the same rule.
 */
export function findMatchingPermission(
	permissions: Permission[],
	action: string,
	resource: string,
): { permission: Permission; index: number } | null {
	const index = permissions.findIndex(
		(p) => matchResource(p.resource, resource) && matchAction(p.actions, action),
	);
	const permission = index === -1 ? undefined : permissions[index];
	return permission ? { permission, index } : null;
}

/**
 * Read the calls recorded in the last hour for an agent and resource.
 * Read-only: unlike checkRateLimit it never increments the counter.
 */
export async function readRateUsage(
	db: Database,
	agentId: string,
	resource: string,
	now: Date = new Date(),
): Promise<number> {
	if (!agentId) return 0;
	const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
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
	return rows.reduce((sum, r) => sum + r.count, 0);
}

export type ConstraintName =
	| "maxCallsPerHour"
	| "allowedArgPatterns"
	| "requireApproval"
	| "timeWindow"
	| "ipAllowlist";

export interface ConstraintStep {
	constraint: ConstraintName;
	/** pass, fail, or approval (the constraint holds the call for a human) */
	outcome: "pass" | "fail" | "approval";
	detail: string;
	/** The value the constraint was evaluated against, when there is one. */
	observed?: unknown;
	/** The configured limit or rule. */
	configured?: unknown;
}

export interface ConstraintInspection {
	allowed: boolean;
	needsApproval: boolean;
	reason?: string;
	steps: ConstraintStep[];
}

export interface InspectOptions {
	now: Date;
	/**
	 * Calls already recorded this hour. Leave undefined to skip the rate step,
	 * which evaluateConstraints runs itself because it must also count the call.
	 */
	rateUsage?: number;
}

/**
 * Evaluate every constraint without touching storage. Constraint order is
 * rate limit, arg patterns, approval, time window, IP allowlist, and the walk
 * stops at the first failure, exactly like evaluateConstraints.
 */
export function inspectConstraints(
	input: ConstraintEvaluationInput,
	constraints: PermissionConstraints,
	options: InspectOptions,
): ConstraintInspection {
	const steps: ConstraintStep[] = [];
	const stop = (
		step: ConstraintStep,
		reason: string | undefined,
		needsApproval = false,
	): ConstraintInspection => {
		steps.push(step);
		return { allowed: false, needsApproval, reason, steps };
	};

	if (constraints.maxCallsPerHour && options.rateUsage !== undefined) {
		const max = constraints.maxCallsPerHour;
		const used = options.rateUsage;
		if (used >= max) {
			const reason = rateLimitReason(used, max, input.resource);
			return stop(
				{
					constraint: "maxCallsPerHour",
					outcome: "fail",
					detail: reason,
					observed: used,
					configured: max,
				},
				reason,
			);
		}
		steps.push({
			constraint: "maxCallsPerHour",
			outcome: "pass",
			detail: `${used}/${max} calls used this hour`,
			observed: used,
			configured: max,
		});
	}

	if (constraints.allowedArgPatterns && input.arguments) {
		const patternResult = validateArgPatterns(constraints.allowedArgPatterns, input.arguments);
		if (!patternResult.valid) {
			return stop(
				{
					constraint: "allowedArgPatterns",
					outcome: "fail",
					detail: patternResult.reason ?? "Argument pattern mismatch",
					observed: input.arguments,
					configured: constraints.allowedArgPatterns,
				},
				patternResult.reason,
			);
		}
		steps.push({
			constraint: "allowedArgPatterns",
			outcome: "pass",
			detail: "All string arguments match the allowed patterns",
			observed: input.arguments,
			configured: constraints.allowedArgPatterns,
		});
	}

	if (constraints.requireApproval) {
		const reason = "This action requires human approval before execution";
		return stop(
			{ constraint: "requireApproval", outcome: "approval", detail: reason, configured: true },
			reason,
			true,
		);
	}

	if (constraints.timeWindow) {
		const hours = options.now.getHours();
		const minutes = options.now.getMinutes();
		const currentTime = `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
		const { start, end } = constraints.timeWindow;
		if (currentTime < start || currentTime > end) {
			const reason = `Action is only allowed between ${start} and ${end}`;
			return stop(
				{
					constraint: "timeWindow",
					outcome: "fail",
					detail: reason,
					observed: currentTime,
					configured: constraints.timeWindow,
				},
				reason,
			);
		}
		steps.push({
			constraint: "timeWindow",
			outcome: "pass",
			detail: `${currentTime} is inside ${start} to ${end}`,
			observed: currentTime,
			configured: constraints.timeWindow,
		});
	}

	if (constraints.ipAllowlist && constraints.ipAllowlist.length > 0) {
		if (!input.ip) {
			const reason =
				"IP_NOT_ALLOWED: No IP address provided; resource requires an IP allowlist match";
			return stop(
				{
					constraint: "ipAllowlist",
					outcome: "fail",
					detail: reason,
					configured: constraints.ipAllowlist,
				},
				reason,
			);
		}
		if (!isIPAllowed(constraints.ipAllowlist, input.ip)) {
			const reason = `IP_NOT_ALLOWED: IP "${input.ip}" is not in the allowlist for this resource`;
			return stop(
				{
					constraint: "ipAllowlist",
					outcome: "fail",
					detail: reason,
					observed: input.ip,
					configured: constraints.ipAllowlist,
				},
				reason,
			);
		}
		steps.push({
			constraint: "ipAllowlist",
			outcome: "pass",
			detail: `IP "${input.ip}" is in the allowlist`,
			observed: input.ip,
			configured: constraints.ipAllowlist,
		});
	}

	return { allowed: true, needsApproval: false, steps };
}

/**
 * Evaluate every constraint on a permission. Returns the first failure, or
 * { allowed: true } if all pass. Constraint order: rate limit, arg patterns,
 * approval, time window, IP allowlist.
 *
 * The rate limit step records the call; everything after it is delegated to
 * inspectConstraints so the simulator evaluates the same rules.
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

	const inspection = inspectConstraints(input, constraints, { now: new Date() });
	return inspection.allowed ? { allowed: true } : { allowed: false, reason: inspection.reason };
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
