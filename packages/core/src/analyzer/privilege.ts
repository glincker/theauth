import { and, eq, gte } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, auditLogs, permissions } from "../db/schema.js";
import type { Permission } from "../types.js";

export interface PrivilegeFinding {
	type:
		| "wildcard_permission"
		| "unused_permission"
		| "overly_broad"
		| "no_constraints"
		| "no_expiry";
	severity: "info" | "warning" | "critical";
	description: string;
	permission?: { resource: string; actions: string[] };
}

export interface PrivilegeAnalysis {
	agentId: string;
	agentName: string;
	score: "minimal" | "appropriate" | "over-permissioned" | "wildcard-heavy";
	findings: PrivilegeFinding[];
	recommendations: string[];
}

export interface PrivilegeSummary {
	total: number;
	byScore: Record<string, number>;
	criticalFindings: number;
}

const DEFAULT_LOOKBACK_DAYS = 30;

function isWildcard(value: string): boolean {
	return value === "*" || value.endsWith(":*") || value.endsWith("/*");
}

function deriveScore(findings: PrivilegeFinding[]): PrivilegeAnalysis["score"] {
	const hasCritical = findings.some((f) => f.severity === "critical");
	const wildcardCount = findings.filter((f) => f.type === "wildcard_permission").length;
	const warningCount = findings.filter((f) => f.severity === "warning").length;

	if (hasCritical || wildcardCount >= 2) return "wildcard-heavy";
	if (wildcardCount === 1 || warningCount >= 2) return "over-permissioned";
	if (findings.length === 0) return "minimal";
	return "appropriate";
}

function buildRecommendations(findings: PrivilegeFinding[], usedResources: Set<string>): string[] {
	const recs: string[] = [];

	for (const finding of findings) {
		if (finding.type === "wildcard_permission" && finding.permission) {
			const { resource, actions } = finding.permission;
			// Strip the trailing wildcard to get the namespace prefix.
			// "mcp:*" → "mcp", "*" → "" (match everything), "mcp:github:*" → "mcp:github"
			const wildcardBase = resource.replace(/:?\*$/, "");
			const relevantUsed = [...usedResources].filter((r) =>
				wildcardBase ? r.startsWith(wildcardBase) : true,
			);

			if (relevantUsed.length > 0) {
				recs.push(`Narrow \`${resource}\` to \`${relevantUsed.join(", ")}\``);
			} else {
				recs.push(`Remove unused wildcard permission \`${resource}\``);
			}

			if (actions.includes("*")) {
				const usedActions = ["read"]; // conservative fallback
				recs.push(
					`Replace wildcard actions on \`${resource}\` with explicit actions: ${usedActions.join(", ")}`,
				);
			}
		}

		if (finding.type === "unused_permission" && finding.permission) {
			recs.push(
				`Remove unused permission \`${finding.permission.resource}\` (no activity in last ${DEFAULT_LOOKBACK_DAYS} days)`,
			);
		}

		if (finding.type === "overly_broad" && finding.permission) {
			const { resource } = finding.permission;
			const relevantUsed = [...usedResources].filter((r) => {
				const prefix = resource.replace(/:?\*$/, "");
				return r.startsWith(prefix);
			});
			if (relevantUsed.length > 0) {
				recs.push(
					`Narrow \`${resource}\` to the specific resources used: \`${relevantUsed.join(", ")}\``,
				);
			}
		}

		if (finding.type === "no_constraints") {
			recs.push("Add rate limits or approval gates to sensitive permissions");
		}

		if (finding.type === "no_expiry") {
			recs.push("Set an expiry date on this agent to enforce periodic credential rotation");
		}
	}

	return [...new Set(recs)];
}

/**
 * Create the least-privilege analyzer.
 *
 * @example
 * ```typescript
 * const analyzer = createPrivilegeAnalyzer(db);
 * const report = await analyzer.analyzeAgent('agent-123');
 * console.log(report.score, report.recommendations);
 * ```
 */
export function createPrivilegeAnalyzer(db: Database) {
	async function analyzeAgent(
		agentId: string,
		options?: { since?: Date },
	): Promise<PrivilegeAnalysis> {
		const agentRows = await db
			.select({ id: agents.id, name: agents.name, expiresAt: agents.expiresAt })
			.from(agents)
			.where(eq(agents.id, agentId))
			.limit(1);

		const agent = agentRows[0];
		if (!agent) {
			return {
				agentId,
				agentName: "unknown",
				score: "appropriate",
				findings: [],
				recommendations: [],
			};
		}

		const permRows = await db
			.select({
				resource: permissions.resource,
				actions: permissions.actions,
				constraints: permissions.constraints,
			})
			.from(permissions)
			.where(eq(permissions.agentId, agentId));

		const agentPermissions: Array<Permission & { constraints: Permission["constraints"] }> =
			permRows.map((r) => ({
				resource: r.resource,
				actions: r.actions,
				constraints: (r.constraints as Permission["constraints"]) ?? undefined,
			}));

		const since =
			options?.since ?? new Date(Date.now() - DEFAULT_LOOKBACK_DAYS * 24 * 60 * 60 * 1000);

		const auditRows = await db
			.select({ resource: auditLogs.resource, action: auditLogs.action })
			.from(auditLogs)
			.where(and(eq(auditLogs.agentId, agentId), gte(auditLogs.timestamp, since)));

		const usedResources = new Set(auditRows.map((r) => r.resource));

		const findings: PrivilegeFinding[] = [];

		for (const perm of agentPermissions) {
			// wildcard_permission: resource or action is a wildcard
			const hasWildcardResource = isWildcard(perm.resource);
			const hasWildcardAction = perm.actions.includes("*");

			if (hasWildcardResource || hasWildcardAction) {
				findings.push({
					type: "wildcard_permission",
					severity: "critical",
					description: hasWildcardResource
						? `Permission resource \`${perm.resource}\` uses a wildcard`
						: `Permission \`${perm.resource}\` has wildcard action \`*\``,
					permission: { resource: perm.resource, actions: perm.actions },
				});
				continue; // skip further checks for this permission — wildcard covers all
			}

			// unused_permission: resource never appears in audit logs
			const wasUsed = [...usedResources].some((used) => {
				if (perm.resource === used) return true;
				// permission covers a namespace, check if any used resource falls under it
				const permBase = perm.resource.replace(/:?\*$/, "");
				return used.startsWith(permBase);
			});

			if (!wasUsed) {
				findings.push({
					type: "unused_permission",
					severity: "warning",
					description: `Permission \`${perm.resource}\` has not been used in the last ${DEFAULT_LOOKBACK_DAYS} days`,
					permission: { resource: perm.resource, actions: perm.actions },
				});
			}

			// overly_broad: permission matches a broad prefix but only specific sub-resources are used
			// e.g. permission is "mcp:*" but only "mcp:github:repos" is used
			if (perm.resource.includes(":")) {
				const permBase = perm.resource.replace(/:?\*$/, "");
				const coveredUsed = [...usedResources].filter((r) => r.startsWith(permBase));

				if (coveredUsed.length > 0 && coveredUsed.length < 3) {
					// Only a few specific resources used, we can be more precise
					const segments = perm.resource.split(":");
					if (
						segments.length <= 2 &&
						coveredUsed.every((r) => r.split(":").length > segments.length)
					) {
						findings.push({
							type: "overly_broad",
							severity: "warning",
							description: `Permission \`${perm.resource}\` is broader than necessary; only \`${coveredUsed.join(", ")}\` was actually used`,
							permission: { resource: perm.resource, actions: perm.actions },
						});
					}
				}
			}

			// no_constraints: permission has no rate limits, time windows, or approval gates
			const hasConstraints =
				perm.constraints &&
				(perm.constraints.maxCallsPerHour !== undefined ||
					perm.constraints.timeWindow !== undefined ||
					perm.constraints.requireApproval === true ||
					(perm.constraints.ipAllowlist && perm.constraints.ipAllowlist.length > 0));

			if (!hasConstraints) {
				findings.push({
					type: "no_constraints",
					severity: "info",
					description: `Permission \`${perm.resource}\` has no rate limits, time windows, or approval gates`,
					permission: { resource: perm.resource, actions: perm.actions },
				});
			}
		}

		// no_expiry: agent has no expiresAt
		if (!agent.expiresAt) {
			findings.push({
				type: "no_expiry",
				severity: "info",
				description: "Agent has no expiry date set",
			});
		}

		const score = deriveScore(findings);
		const recommendations = buildRecommendations(findings, usedResources);

		return {
			agentId,
			agentName: agent.name,
			score,
			findings,
			recommendations,
		};
	}

	async function analyzeAll(options?: { since?: Date }): Promise<PrivilegeAnalysis[]> {
		const activeAgents = await db
			.select({ id: agents.id })
			.from(agents)
			.where(eq(agents.status, "active"));

		const results = await Promise.all(activeAgents.map((a) => analyzeAgent(a.id, options)));

		return results;
	}

	async function getSummary(): Promise<PrivilegeSummary> {
		const analyses = await analyzeAll();

		const byScore: Record<string, number> = {};
		let criticalFindings = 0;

		for (const analysis of analyses) {
			byScore[analysis.score] = (byScore[analysis.score] ?? 0) + 1;
			criticalFindings += analysis.findings.filter((f) => f.severity === "critical").length;
		}

		return {
			total: analyses.length,
			byScore,
			criticalFindings,
		};
	}

	return { analyzeAgent, analyzeAll, getSummary };
}

export type PrivilegeAnalyzer = ReturnType<typeof createPrivilegeAnalyzer>;
