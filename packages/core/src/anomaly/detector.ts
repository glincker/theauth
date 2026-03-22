import { and, eq, gte, lte } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { auditLogs } from "../db/schema.js";

export interface AnomalyConfig {
	/** Max calls per agent per hour before flagging (default: 500) */
	highFrequencyThreshold?: number;
	/** Denial rate % that triggers alert (default: 50) */
	highDenialRateThreshold?: number;
	/** Flag access outside these hours as anomalous (optional) */
	expectedHours?: { start: number; end: number };
}

export interface Anomaly {
	type:
		| "high_frequency"
		| "high_denial_rate"
		| "off_hours_access"
		| "new_resource_pattern"
		| "privilege_escalation_attempt";
	agentId: string;
	severity: "low" | "medium" | "high" | "critical";
	description: string;
	detectedAt: string;
	metadata: Record<string, unknown>;
}

export interface AnomalySummary {
	total: number;
	bySeverity: Record<string, number>;
	byType: Record<string, number>;
	topAgents: Array<{ agentId: string; anomalyCount: number }>;
}

interface AuditRow {
	agentId: string;
	action: string;
	resource: string;
	result: string;
	reason: string | null;
	timestamp: Date;
}

const SEVERITY_MAP: Record<Anomaly["type"], Anomaly["severity"]> = {
	high_frequency: "medium",
	high_denial_rate: "high",
	off_hours_access: "low",
	new_resource_pattern: "low",
	privilege_escalation_attempt: "critical",
};

function groupByAgent(rows: AuditRow[]): Map<string, AuditRow[]> {
	const map = new Map<string, AuditRow[]>();
	for (const row of rows) {
		const existing = map.get(row.agentId);
		if (existing) {
			existing.push(row);
		} else {
			map.set(row.agentId, [row]);
		}
	}
	return map;
}

function detectHighFrequency(
	byAgent: Map<string, AuditRow[]>,
	threshold: number,
	now: Date,
): Anomaly[] {
	const anomalies: Anomaly[] = [];
	const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);

	for (const [agentId, rows] of byAgent) {
		const recentRows = rows.filter((r) => r.timestamp >= hourAgo);
		if (recentRows.length > threshold) {
			anomalies.push({
				type: "high_frequency",
				agentId,
				severity: SEVERITY_MAP.high_frequency,
				description: `Agent made ${recentRows.length} calls in the last hour (threshold: ${threshold})`,
				detectedAt: now.toISOString(),
				metadata: {
					callCount: recentRows.length,
					threshold,
					windowStart: hourAgo.toISOString(),
					windowEnd: now.toISOString(),
				},
			});
		}
	}

	return anomalies;
}

function detectHighDenialRate(
	byAgent: Map<string, AuditRow[]>,
	thresholdPercent: number,
	now: Date,
): Anomaly[] {
	const anomalies: Anomaly[] = [];

	for (const [agentId, rows] of byAgent) {
		const allowed = rows.filter((r) => r.result === "allowed").length;
		const denied = rows.filter((r) => r.result === "denied").length;
		const total = allowed + denied;

		if (total === 0) continue;

		const denialRate = (denied / total) * 100;
		if (denialRate >= thresholdPercent) {
			anomalies.push({
				type: "high_denial_rate",
				agentId,
				severity: SEVERITY_MAP.high_denial_rate,
				description: `Agent has a ${denialRate.toFixed(1)}% denial rate (${denied}/${total} requests denied, threshold: ${thresholdPercent}%)`,
				detectedAt: now.toISOString(),
				metadata: {
					denialRate: Math.round(denialRate * 10) / 10,
					deniedCount: denied,
					allowedCount: allowed,
					totalCount: total,
					thresholdPercent,
				},
			});
		}
	}

	return anomalies;
}

function detectOffHoursAccess(
	byAgent: Map<string, AuditRow[]>,
	expectedHours: { start: number; end: number },
	now: Date,
): Anomaly[] {
	const anomalies: Anomaly[] = [];

	for (const [agentId, rows] of byAgent) {
		const offHourRows = rows.filter((r) => {
			const hour = r.timestamp.getUTCHours();
			if (expectedHours.start <= expectedHours.end) {
				return hour < expectedHours.start || hour >= expectedHours.end;
			}
			// Overnight window (e.g. 22-6)
			return hour < expectedHours.start && hour >= expectedHours.end;
		});

		if (offHourRows.length > 0) {
			const hours = offHourRows.map((r) => r.timestamp.getUTCHours());
			const uniqueHours = [...new Set(hours)].sort((a, b) => a - b);
			anomalies.push({
				type: "off_hours_access",
				agentId,
				severity: SEVERITY_MAP.off_hours_access,
				description: `Agent accessed resources outside expected hours (${expectedHours.start}:00-${expectedHours.end}:00 UTC) — ${offHourRows.length} event(s) detected`,
				detectedAt: now.toISOString(),
				metadata: {
					offHoursEventCount: offHourRows.length,
					accessedAtHours: uniqueHours,
					expectedStart: expectedHours.start,
					expectedEnd: expectedHours.end,
					firstOffHoursAccess: offHourRows[0]?.timestamp.toISOString(),
				},
			});
		}
	}

	return anomalies;
}

async function detectNewResourcePatterns(
	db: Database,
	byAgent: Map<string, AuditRow[]>,
	since: Date,
	now: Date,
): Promise<Anomaly[]> {
	const anomalies: Anomaly[] = [];

	// Prior window: 7 days before since
	const priorStart = new Date(since.getTime() - 7 * 24 * 60 * 60 * 1000);

	for (const [agentId, currentRows] of byAgent) {
		const currentResources = new Set(currentRows.map((r) => r.resource));

		const priorRows = await db
			.select({ resource: auditLogs.resource })
			.from(auditLogs)
			.where(
				and(
					eq(auditLogs.agentId, agentId),
					gte(auditLogs.timestamp, priorStart),
					lte(auditLogs.timestamp, since),
				),
			);

		const priorResources = new Set(priorRows.map((r) => r.resource));

		const newResources = [...currentResources].filter((r) => !priorResources.has(r));

		if (newResources.length > 0) {
			anomalies.push({
				type: "new_resource_pattern",
				agentId,
				severity: SEVERITY_MAP.new_resource_pattern,
				description: `Agent accessed ${newResources.length} resource(s) not seen in the prior 7 days`,
				detectedAt: now.toISOString(),
				metadata: {
					newResources,
					newResourceCount: newResources.length,
					priorWindowStart: priorStart.toISOString(),
					priorWindowEnd: since.toISOString(),
				},
			});
		}
	}

	return anomalies;
}

function detectPrivilegeEscalationAttempts(byAgent: Map<string, AuditRow[]>, now: Date): Anomaly[] {
	const anomalies: Anomaly[] = [];

	for (const [agentId, rows] of byAgent) {
		const escalationRows = rows.filter((r) => {
			if (r.result !== "denied") return false;
			const reason = r.reason ?? "";
			return (
				reason.includes("INSUFFICIENT_PERMISSIONS") ||
				reason.toLowerCase().includes("delegation") ||
				reason.toLowerCase().includes("insufficient_permissions")
			);
		});

		if (escalationRows.length > 0) {
			const resources = [...new Set(escalationRows.map((r) => r.resource))];
			anomalies.push({
				type: "privilege_escalation_attempt",
				agentId,
				severity: SEVERITY_MAP.privilege_escalation_attempt,
				description: `Agent made ${escalationRows.length} denied request(s) with INSUFFICIENT_PERMISSIONS — possible privilege escalation attempt`,
				detectedAt: now.toISOString(),
				metadata: {
					attemptCount: escalationRows.length,
					targetResources: resources,
					firstAttempt: escalationRows[0]?.timestamp.toISOString(),
					lastAttempt: escalationRows[escalationRows.length - 1]?.timestamp.toISOString(),
				},
			});
		}
	}

	return anomalies;
}

/**
 * Create a behavioural anomaly detector backed by the KavachOS audit log.
 *
 * @example
 * ```typescript
 * const detector = createAnomalyDetector({ highFrequencyThreshold: 200 }, db);
 * const anomalies = await detector.scan({ since: new Date(Date.now() - 3600_000) });
 * ```
 */
export function createAnomalyDetector(config: AnomalyConfig, db: Database) {
	const highFrequencyThreshold = config.highFrequencyThreshold ?? 500;
	const highDenialRateThreshold = config.highDenialRateThreshold ?? 50;

	async function scan(options?: { since?: Date; agentId?: string }): Promise<Anomaly[]> {
		const now = new Date();
		const since = options?.since ?? new Date(now.getTime() - 24 * 60 * 60 * 1000);

		const conditions = [gte(auditLogs.timestamp, since), lte(auditLogs.timestamp, now)];
		if (options?.agentId) {
			conditions.push(eq(auditLogs.agentId, options.agentId));
		}

		const rows = await db
			.select({
				agentId: auditLogs.agentId,
				action: auditLogs.action,
				resource: auditLogs.resource,
				result: auditLogs.result,
				reason: auditLogs.reason,
				timestamp: auditLogs.timestamp,
			})
			.from(auditLogs)
			.where(and(...conditions));

		const byAgent = groupByAgent(rows);

		const [newResourceAnomalies] = await Promise.all([
			detectNewResourcePatterns(db, byAgent, since, now),
		]);

		const anomalies: Anomaly[] = [
			...detectHighFrequency(byAgent, highFrequencyThreshold, now),
			...detectHighDenialRate(byAgent, highDenialRateThreshold, now),
			...(config.expectedHours ? detectOffHoursAccess(byAgent, config.expectedHours, now) : []),
			...newResourceAnomalies,
			...detectPrivilegeEscalationAttempts(byAgent, now),
		];

		return anomalies;
	}

	async function getSummary(since?: Date): Promise<AnomalySummary> {
		const anomalies = await scan({ since });

		const bySeverity: Record<string, number> = {};
		const byType: Record<string, number> = {};
		const agentCounts = new Map<string, number>();

		for (const anomaly of anomalies) {
			bySeverity[anomaly.severity] = (bySeverity[anomaly.severity] ?? 0) + 1;
			byType[anomaly.type] = (byType[anomaly.type] ?? 0) + 1;
			agentCounts.set(anomaly.agentId, (agentCounts.get(anomaly.agentId) ?? 0) + 1);
		}

		const topAgents = [...agentCounts.entries()]
			.sort((a, b) => b[1] - a[1])
			.slice(0, 10)
			.map(([agentId, anomalyCount]) => ({ agentId, anomalyCount }));

		return {
			total: anomalies.length,
			bySeverity,
			byType,
			topAgents,
		};
	}

	return { scan, getSummary };
}

export type AnomalyDetector = ReturnType<typeof createAnomalyDetector>;
