import { randomUUID } from "node:crypto";
import { and, eq, gte } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs, rateLimits } from "../db/schema.js";
import type {
	AgentIdentity,
	AuthorizeRequest,
	AuthorizeResult,
	PermissionConstraints,
} from "../types.js";

interface PermissionEngineConfig {
	db: Database;
	auditAll: boolean;
}

/**
 * Match a resource pattern against a requested resource.
 *
 * Supports wildcards:
 * - "mcp:github:*" matches "mcp:github:create_issue"
 * - "tool:*" matches "tool:file_read"
 * - "*" matches everything
 */
function matchResource(pattern: string, resource: string): boolean {
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
function matchAction(allowedActions: string[], requestedAction: string): boolean {
	return allowedActions.includes(requestedAction) || allowedActions.includes("*");
}

/**
 * Parse an IPv4 address into a 32-bit integer.
 */
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

/**
 * Check whether an IP matches a CIDR range or exact IP entry.
 * Supports both "10.0.0.1" and "10.0.0.0/8" notation (IPv4 only).
 */
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
 */
function isIPAllowed(allowlist: string[], ip: string): boolean {
	return allowlist.some((entry) => matchesIPEntry(entry, ip));
}

/**
 * Validate argument patterns against the request arguments.
 */
function validateArgPatterns(
	patterns: string[],
	args: Record<string, unknown>,
): { valid: boolean; reason?: string } {
	for (const pattern of patterns) {
		const regex = new RegExp(pattern);
		// Check all string arguments against the pattern
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
 * Check rate limits for an agent on a specific resource.
 */
async function checkRateLimit(
	db: Database,
	agentId: string,
	resource: string,
	maxCallsPerHour: number,
): Promise<{ allowed: boolean; reason?: string }> {
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

	// Increment counter
	const currentWindow = new Date(Math.floor(Date.now() / (5 * 60 * 1000)) * (5 * 60 * 1000)); // 5-min windows
	const existing = rows.find((r) => r.windowStart.getTime() === currentWindow.getTime());

	if (existing) {
		await db
			.update(rateLimits)
			.set({ count: existing.count + 1 })
			.where(eq(rateLimits.id, existing.id));
	} else {
		await db.insert(rateLimits).values({
			id: randomUUID(),
			agentId,
			resource,
			windowStart: currentWindow,
			count: 1,
		});
	}

	return { allowed: true };
}

/**
 * Create the permission/authorization engine.
 */
export function createPermissionEngine(config: PermissionEngineConfig) {
	const { db, auditAll } = config;

	/**
	 * Check if an agent is authorized to perform an action.
	 * This is the core authorization function.
	 *
	 * @param tokensCost - Optional token cost to record in the audit log.
	 */
	async function authorize(
		agent: AgentIdentity,
		request: AuthorizeRequest,
		tokensCost?: number,
	): Promise<AuthorizeResult> {
		const startTime = performance.now();
		const auditId = randomUUID();

		// Find matching permission
		const matchingPermission = agent.permissions.find(
			(p) => matchResource(p.resource, request.resource) && matchAction(p.actions, request.action),
		);

		if (!matchingPermission) {
			const result: AuthorizeResult = {
				allowed: false,
				reason: `No permission grants agent "${agent.name}" access to "${request.action}" on "${request.resource}"`,
				auditId,
			};
			if (auditAll) {
				await writeAuditLog(db, agent, request, result, startTime, auditId, tokensCost);
			}
			return result;
		}

		// Check constraints
		if (matchingPermission.constraints) {
			const constraintResult = await evaluateConstraints(
				db,
				agent,
				request,
				matchingPermission.constraints,
			);
			if (!constraintResult.allowed) {
				const result: AuthorizeResult = {
					allowed: false,
					reason: constraintResult.reason,
					auditId,
				};
				if (auditAll) {
					await writeAuditLog(db, agent, request, result, startTime, auditId, tokensCost);
				}
				return result;
			}
		}

		const result: AuthorizeResult = { allowed: true, auditId };
		if (auditAll) {
			await writeAuditLog(db, agent, request, result, startTime, auditId, tokensCost);
		}
		return result;
	}

	return { authorize };
}

async function evaluateConstraints(
	db: Database,
	agent: AgentIdentity,
	request: AuthorizeRequest,
	constraints: PermissionConstraints,
): Promise<{ allowed: boolean; reason?: string }> {
	// Rate limit check
	if (constraints.maxCallsPerHour) {
		const rateResult = await checkRateLimit(
			db,
			agent.id,
			request.resource,
			constraints.maxCallsPerHour,
		);
		if (!rateResult.allowed) {
			return rateResult;
		}
	}

	// Argument pattern check
	if (constraints.allowedArgPatterns && request.arguments) {
		const patternResult = validateArgPatterns(constraints.allowedArgPatterns, request.arguments);
		if (!patternResult.valid) {
			return { allowed: false, reason: patternResult.reason };
		}
	}

	// Human-in-the-loop check
	if (constraints.requireApproval) {
		return {
			allowed: false,
			reason: "This action requires human approval before execution",
		};
	}

	// Time window check
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

	// IP allowlist check
	if (constraints.ipAllowlist && constraints.ipAllowlist.length > 0) {
		if (!request.ip) {
			return {
				allowed: false,
				reason: "IP_NOT_ALLOWED: No IP address provided; resource requires an IP allowlist match",
			};
		}
		if (!isIPAllowed(constraints.ipAllowlist, request.ip)) {
			return {
				allowed: false,
				reason: `IP_NOT_ALLOWED: IP "${request.ip}" is not in the allowlist for this resource`,
			};
		}
	}

	return { allowed: true };
}

async function writeAuditLog(
	db: Database,
	agent: AgentIdentity,
	request: AuthorizeRequest,
	result: AuthorizeResult,
	startTime: number,
	auditId: string,
	tokensCost?: number,
): Promise<void> {
	const durationMs = Math.round(performance.now() - startTime);

	await db.insert(auditLogs).values({
		id: auditId,
		agentId: agent.id,
		userId: agent.ownerId,
		action: request.action,
		resource: request.resource,
		parameters: request.arguments ?? {},
		result: result.allowed ? "allowed" : "denied",
		reason: result.reason ?? null,
		durationMs,
		tokensCost: tokensCost ?? null,
		timestamp: new Date(),
		ip: request.context?.ip ?? null,
		userAgent: request.context?.userAgent ?? null,
	});
}
