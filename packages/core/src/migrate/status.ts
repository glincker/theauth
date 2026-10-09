import type { MigrationRecord, MigrationStore } from "./types.js";

export interface MigrationStatusReport {
	generatedAt: string;
	total: number;
	migrated: number;
	pending: number;
	failed: number;
	percentMigrated: number;
	bySource: Record<string, { migrated: number; pending: number; failed: number }>;
	byCohort: Record<string, number>;
	failuresByCode: Record<string, number>;
}

/**
 * Counts only. The ledger holds ids, source names and cohort labels, and this report
 * drops even the ids, so it can be pasted into a status update.
 */
export async function getMigrationStatus(
	store: Pick<MigrationStore, "listMigrations">,
	now: Date = new Date(),
): Promise<MigrationStatusReport> {
	const all = await store.listMigrations();
	// Latest record wins per user. Failures without a user are each their own entry.
	const latest = new Map<string, MigrationRecord>();
	all.forEach((r, i) => {
		const key = r.userId ?? `anon:${i}`;
		const prev = latest.get(key);
		if (!prev || r.at.getTime() >= prev.at.getTime()) latest.set(key, r);
	});
	const report: MigrationStatusReport = {
		generatedAt: now.toISOString(),
		total: latest.size,
		migrated: 0,
		pending: 0,
		failed: 0,
		percentMigrated: 0,
		bySource: {},
		byCohort: {},
		failuresByCode: {},
	};
	for (const r of latest.values()) {
		report[r.status]++;
		const src = report.bySource[r.source] ?? { migrated: 0, pending: 0, failed: 0 };
		report.bySource[r.source] = src;
		src[r.status]++;
		if (r.status === "migrated" && r.cohort) {
			report.byCohort[r.cohort] = (report.byCohort[r.cohort] ?? 0) + 1;
		}
		if (r.status === "failed") {
			const code = r.errorCode ?? "UNKNOWN";
			report.failuresByCode[code] = (report.failuresByCode[code] ?? 0) + 1;
		}
	}
	report.percentMigrated =
		report.total === 0 ? 0 : Math.round((report.migrated / report.total) * 1000) / 10;
	return report;
}

export function formatStatus(r: MigrationStatusReport): string {
	const lines = [
		`Migration status (${r.generatedAt})`,
		`  total ${r.total}, migrated ${r.migrated} (${r.percentMigrated}%), pending ${r.pending}, failed ${r.failed}`,
	];
	for (const [src, c] of Object.entries(r.bySource)) {
		lines.push(`  ${src}: migrated ${c.migrated}, pending ${c.pending}, failed ${c.failed}`);
	}
	for (const [cohort, n] of Object.entries(r.byCohort)) lines.push(`  cohort ${cohort}: ${n}`);
	for (const [code, n] of Object.entries(r.failuresByCode)) lines.push(`  failure ${code}: ${n}`);
	return `${lines.join("\n")}\n`;
}
