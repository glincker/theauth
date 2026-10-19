/**
 * The audit repository on a store kernel. `appendAt` is one insert whose unique index on
 * (agent_id, chain_seq) rejects a forked chain, `readHead` is an indexed descending read. The
 * per agent write queue lives here, on the stores object, instead of in a WeakMap keyed by the
 * Drizzle handle, so a second backend gets the same serialization without knowing about it.
 */
import type { AuditHead, AuditInsertRow, AuditLogRepo, StoreKernel } from "./types.js";

/** Runs jobs for the same key one after the other. A failing job does not block the next one. */
export function createKeyedQueue(): <T>(key: string, run: () => Promise<T>) => Promise<T> {
	const tails = new Map<string, Promise<unknown>>();
	return async function exclusive<T>(key: string, run: () => Promise<T>): Promise<T> {
		const previous = tails.get(key) ?? Promise.resolve();
		const job = previous.then(run);
		const tail = job.catch(() => undefined);
		tails.set(key, tail);
		try {
			return await job;
		} finally {
			if (tails.get(key) === tail) tails.delete(key);
		}
	};
}

export function createAuditLogRepo(kernel: StoreKernel): AuditLogRepo {
	const exclusive = createKeyedQueue();
	return {
		async readHead(agentId: string): Promise<AuditHead | null> {
			const rows = await kernel.findMany("auditLogs", {
				where: [
					{ field: "agentId", op: "eq", value: agentId },
					{ field: "chainSeq", op: "notNull" },
				],
				columns: ["chainSeq", "hash", "recordedAtMs"],
				orderBy: [{ field: "chainSeq", dir: "desc" }],
				limit: 1,
			});
			const head = rows[0];
			if (!head || typeof head.chainSeq !== "number" || typeof head.hash !== "string") return null;
			return {
				seq: head.chainSeq,
				hash: head.hash,
				recordedAtMs: typeof head.recordedAtMs === "number" ? head.recordedAtMs : 0,
			};
		},
		async appendAt(row: AuditInsertRow): Promise<void> {
			if (typeof row.chainSeq !== "number" || typeof row.hash !== "string") {
				throw new Error("audit appendAt needs chainSeq and hash on the row");
			}
			await kernel.insert("auditLogs", row);
		},
		insertUnchained: (row: AuditInsertRow) => kernel.insert("auditLogs", row),
		exclusive,
	};
}
