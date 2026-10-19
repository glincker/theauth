/**
 * Runs a write-only group of operations. Where the backend has an atomic batch the group is all or nothing. Where it does not (`atomicBatch` false) the group runs in order, one statement at a time, so every caller must build groups that are safe to rerun from the start (deletes and updates by key, inserts that tolerate a conflict). Design: docs-local/design/db-adapter-abstraction.md section 2.
 */
import type { Database } from "../database.js";
import { createDrizzleKernel } from "./drizzle-kernel.js";
import type { WriteOp } from "./types.js";

export async function applyWriteOps(db: Database, ops: readonly WriteOp[]): Promise<void> {
	if (ops.length === 0) return;
	const kernel = createDrizzleKernel(db);
	if (kernel.capabilities.atomicBatch) {
		await kernel.batch(ops);
		return;
	}
	for (const op of ops) {
		if (op.op === "insert") await kernel.insert(op.model, op.row);
		else if (op.op === "update") await kernel.updateMany(op.model, op.where, op.set);
		else await kernel.deleteMany(op.model, op.where);
	}
}
