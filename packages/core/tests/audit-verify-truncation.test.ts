/** Regressions for prefix truncation: deleting the oldest rows of a chain must not verify as ok. */

import { and, eq, lte } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createAuditModule } from "../src/audit/audit.js";
import { CHECKPOINT_ACTION } from "../src/audit/chain.js";
import { enableAuditChain, insertAuditRow, verifyAuditChain } from "../src/audit/index.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const KEY = "secret-hmac-key";
const T0 = new Date("2026-10-01T00:00:00Z");
const OLD = new Date("2020-01-01T00:00:00Z");

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	await db
		.insert(users)
		.values({ id: "u1", email: "u@x.io", name: "U", createdAt: T0, updatedAt: T0 });
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		status: "active",
		tokenHash: "h",
		tokenPrefix: "ta_x",
		metadata: {},
		createdAt: T0,
		updatedAt: T0,
	});
	enableAuditChain(db, { hmacKey: KEY });
	return db;
}

function row(id: string, timestamp: Date) {
	return {
		id,
		agentId: "a1",
		userId: "u1",
		action: "execute",
		resource: "db:prod",
		parameters: { id },
		result: "allowed" as const,
		durationMs: 1,
		timestamp,
	};
}

async function verify(db: Database, opts: Parameters<typeof verifyAuditChain>[1] = {}) {
	const r = await verifyAuditChain(db, opts, KEY);
	if (!r.success) throw new Error(r.error.message);
	return r.data;
}

async function dropThrough(db: Database, seq: number) {
	await db.delete(auditLogs).where(and(eq(auditLogs.agentId, "a1"), lte(auditLogs.chainSeq, seq)));
}

describe("prefix truncation", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
		for (let i = 1; i <= 5; i++)
			await insertAuditRow(db, row(`r${i}`, new Date(T0.getTime() + i * 1000)));
	});

	it("deleting the oldest rows is reported as truncated_prefix", async () => {
		await dropThrough(db, 3);
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.firstBreak).toMatchObject({ reason: "truncated_prefix", rowId: "r4", seq: 4 });
	});

	it("allowUnanchoredPrefix keeps the old lenient behavior when asked for", async () => {
		await dropThrough(db, 3);
		expect((await verify(db, { allowUnanchoredPrefix: true })).ok).toBe(true);
	});

	it("checkpoint() anchors the current start, and deleting past it is caught", async () => {
		await dropThrough(db, 2);
		const mod = createAuditModule({ db, hmacKey: KEY });
		const cp = await mod.checkpoint();
		if (!cp.success) throw new Error(cp.error.message);
		expect(cp.data.anchors).toEqual([expect.objectContaining({ agentId: "a1", seq: 3, id: "r3" })]);
		expect(cp.data.heads[0]).toMatchObject({ agentId: "a1", seq: 6 });
		const anchorRow = await db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.action, CHECKPOINT_ACTION));
		expect(anchorRow).toHaveLength(1);
		expect((await verify(db)).ok).toBe(true);

		await dropThrough(db, 3);
		expect((await verify(db)).firstBreak).toMatchObject({ reason: "truncated_prefix", seq: 4 });
	});

	it("a forged anchor row without a valid MAC is not accepted", async () => {
		await dropThrough(db, 2);
		const [first] = await db.select().from(auditLogs).where(eq(auditLogs.id, "r3"));
		await insertAuditRow(db, {
			...row("chk_forged", new Date()),
			action: CHECKPOINT_ACTION,
			parameters: {
				kind: "anchor",
				firstSeq: 3,
				firstId: "r3",
				firstHash: first?.hash,
				mac: "0".repeat(64),
			},
		});
		expect((await verify(db)).firstBreak).toMatchObject({ reason: "truncated_prefix", seq: 3 });
	});

	it("externally pinned anchors catch a deleted or rewritten start", async () => {
		const mod = createAuditModule({ db, hmacKey: KEY });
		const cp = await mod.checkpoint();
		if (!cp.success) throw new Error(cp.error.message);
		const anchors = cp.data.anchors;
		expect((await verify(db, { anchors, expectedHeads: cp.data.heads })).ok).toBe(true);

		const wrong = anchors.map((a) => ({ ...a, hash: "f".repeat(64) }));
		expect((await verify(db, { anchors: wrong })).firstBreak?.reason).toBe("anchor_mismatch");

		await dropThrough(db, 1);
		expect((await verify(db, { anchors, allowUnanchoredPrefix: true })).firstBreak).toMatchObject({
			reason: "truncated_prefix",
			seq: 1,
		});
	});
});

describe("retention cleanup is still an accepted cut", () => {
	it("verifies after cleanup, signs the checkpoint, and catches one more deleted row", async () => {
		const db = await setup();
		for (let i = 1; i <= 3; i++)
			await insertAuditRow(db, row(`o${i}`, new Date(OLD.getTime() + i * 1000)));
		for (let i = 1; i <= 3; i++) await insertAuditRow(db, row(`n${i}`, new Date()));
		const mod = createAuditModule({ db, hmacKey: KEY });
		expect(await mod.cleanup({ retentionDays: 30 })).toMatchObject({ deleted: 3, checkpoints: 1 });
		const [cp] = await db.select().from(auditLogs).where(eq(auditLogs.action, CHECKPOINT_ACTION));
		expect((cp?.parameters as { mac?: unknown } | null)?.mac).toEqual(expect.any(String));
		expect((await verify(db)).ok).toBe(true);

		await db.delete(auditLogs).where(eq(auditLogs.id, "n1"));
		expect((await verify(db)).firstBreak).toMatchObject({
			reason: "truncated_prefix",
			rowId: "n2",
		});
	});
});
