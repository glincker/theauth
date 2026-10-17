import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { agents, auditLogs, trustScores } from "../db/schema.js";

export interface TrustScore {
	agentId: string;
	score: number;
	level: "untrusted" | "limited" | "standard" | "trusted" | "elevated";
	factors: {
		successRate: number;
		denialRate: number;
		ageInDays: number;
		totalCalls: number;
		anomalyCount: number;
		lastViolation?: string;
	};
	computedAt: string;
}

export interface TrustConfig {
	/** Score thresholds for levels */
	thresholds?: {
		untrusted: number;
		limited: number;
		standard: number;
		trusted: number;
		elevated: number;
	};
}

const DEFAULT_THRESHOLDS = {
	untrusted: 20,
	limited: 40,
	standard: 60,
	trusted: 80,
	elevated: 95,
};

function scoreToLevel(score: number, thresholds: typeof DEFAULT_THRESHOLDS): TrustScore["level"] {
	if (score >= thresholds.elevated) return "elevated";
	if (score >= thresholds.trusted) return "trusted";
	if (score >= thresholds.standard) return "standard";
	if (score >= thresholds.limited) return "limited";
	return "untrusted";
}

function clamp(value: number, min: number, max: number): number {
	return Math.max(min, Math.min(max, value));
}

function rowToScore(row: typeof trustScores.$inferSelect): TrustScore {
	const factors = row.factors as TrustScore["factors"];
	return {
		agentId: row.agentId,
		score: row.score,
		level: row.level as TrustScore["level"],
		factors,
		computedAt: row.computedAt.toISOString(),
	};
}

/**
 * Create the graduated autonomy trust scoring module.
 *
 * @example
 * ```typescript
 * const trust = createTrustModule({}, db);
 * const score = await trust.computeScore(agentId);
 * console.log(score.level); // 'standard'
 * ```
 */
export function createTrustModule(config: TrustConfig, db: Database) {
	const thresholds = { ...DEFAULT_THRESHOLDS, ...config.thresholds };

	async function computeScore(agentId: string): Promise<TrustScore> {
		const now = new Date();

		// Fetch agent creation date for age calculation
		const agentRows = await db
			.select({ createdAt: agents.createdAt })
			.from(agents)
			.where(eq(agents.id, agentId))
			.limit(1);

		const agentRow = agentRows[0];
		const ageInDays = agentRow
			? (now.getTime() - agentRow.createdAt.getTime()) / (1000 * 60 * 60 * 24)
			: 0;

		// Aggregate audit stats for this agent
		const allLogs = await db
			.select({
				result: auditLogs.result,
				reason: auditLogs.reason,
				timestamp: auditLogs.timestamp,
			})
			.from(auditLogs)
			.where(eq(auditLogs.agentId, agentId));

		const totalCalls = allLogs.length;
		const allowed = allLogs.filter((r) => r.result === "allowed").length;
		const denied = allLogs.filter((r) => r.result === "denied").length;

		const successRate = totalCalls > 0 ? (allowed / totalCalls) * 100 : 100;
		const denialRate = totalCalls > 0 ? (denied / totalCalls) * 100 : 0;

		// Detect anomaly count: privilege escalation attempts in audit logs
		const anomalyCount = allLogs.filter((r) => {
			if (r.result !== "denied") return false;
			const reason = r.reason ?? "";
			return (
				reason.includes("INSUFFICIENT_PERMISSIONS") ||
				reason.toLowerCase().includes("privilege") ||
				reason.toLowerCase().includes("escalation")
			);
		}).length;

		const violationLogs = allLogs
			.filter((r) => r.result === "denied")
			.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
		const lastViolation = violationLogs[0]?.timestamp.toISOString();

		let score = 50;
		score += Math.min(25, Math.floor(allowed / 100)); // +1 per 100 successful calls, max +25
		score -= denied * 5; // -5 per denial
		score -= anomalyCount * 10; // -10 per anomaly
		if (ageInDays > 30) score += 10;
		else if (ageInDays > 7) score += 5;

		score = clamp(Math.round(score), 0, 100);
		const level = scoreToLevel(score, thresholds);

		const factors: TrustScore["factors"] = {
			successRate: Math.round(successRate * 10) / 10,
			denialRate: Math.round(denialRate * 10) / 10,
			ageInDays: Math.round(ageInDays * 10) / 10,
			totalCalls,
			anomalyCount,
			lastViolation,
		};

		const existingRows = await db
			.select({ agentId: trustScores.agentId })
			.from(trustScores)
			.where(eq(trustScores.agentId, agentId))
			.limit(1);

		if (existingRows.length > 0) {
			await db
				.update(trustScores)
				.set({ score, level, factors, computedAt: now })
				.where(eq(trustScores.agentId, agentId));
		} else {
			await db.insert(trustScores).values({
				agentId,
				score,
				level,
				factors,
				computedAt: now,
			});
		}

		return {
			agentId,
			score,
			level,
			factors,
			computedAt: now.toISOString(),
		};
	}

	async function getScore(agentId: string): Promise<TrustScore | null> {
		const rows = await db
			.select()
			.from(trustScores)
			.where(eq(trustScores.agentId, agentId))
			.limit(1);

		const row = rows[0];
		if (!row) return null;
		return rowToScore(row);
	}

	async function computeAll(): Promise<TrustScore[]> {
		const activeAgents = await db
			.select({ id: agents.id })
			.from(agents)
			.where(eq(agents.status, "active"));

		const results: TrustScore[] = [];
		for (const agent of activeAgents) {
			const score = await computeScore(agent.id);
			results.push(score);
		}
		return results;
	}

	async function getScores(filters?: { level?: string; minScore?: number }): Promise<TrustScore[]> {
		const rows = await db.select().from(trustScores);
		let scores = rows.map(rowToScore);

		if (filters?.level) {
			scores = scores.filter((s) => s.level === filters.level);
		}
		if (filters?.minScore !== undefined) {
			const min = filters.minScore;
			scores = scores.filter((s) => s.score >= min);
		}

		return scores;
	}

	return {
		computeScore,
		getScore,
		computeAll,
		getScores,
	};
}

export type TrustModule = ReturnType<typeof createTrustModule>;
