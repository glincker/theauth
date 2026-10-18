/** Erasure (GDPR deleteUser) against the audit hash chain. */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { computeRowHash, ERASURE_ACTION } from "../src/audit/chain.js";
import { enableAuditChain, insertAuditRow, verifyAuditChain } from "../src/audit/index.js";
import { createGdprModule } from "../src/auth/gdpr.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, auditSecrets, users } from "../src/db/schema.js";

const KEY = "erasure-test-key";
const T0 = new Date("2026-10-01T00:00:00Z");

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	for (const id of ["u1", "u2"]) {
		await db.insert(users).values({
			id,
			email: `${id}@example.com`,
			name: id,
			username: id,
			createdAt: T0,
			updatedAt: T0,
		});
	}
	for (const [id, owner] of [
		["a1", "u1"],
		["a2", "u2"],
	] as const) {
		await db.insert(agents).values({
			id,
			ownerId: owner,
			name: id,
			type: "autonomous",
			status: "active",
			tokenHash: `h-${id}`,
			tokenPrefix: "kv_x",
			metadata: {},
			createdAt: T0,
			updatedAt: T0,
		});
	}
	return db;
}

function row(id: string, agentId: string, userId: string, secs: number, extra = {}) {
	return {
		id,
		agentId,
		userId,
		action: "execute",
		resource: `mcp:test:${id}`,
		parameters: {},
		result: "allowed" as const,
		durationMs: 1,
		timestamp: new Date(T0.getTime() + secs * 1000),
		...extra,
	};
}

describe("audit chain and erasure", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	for (const [label, hmacKey] of [
		["with hmacKey", KEY],
		["with the per-installation secret", undefined],
	] as const) {
		it(`keeps version 2 rows verifiable after anonymizing the user (${label})`, async () => {
			enableAuditChain(db, { hmacKey });
			await insertAuditRow(db, row("r1", "a1", "u1", 1, { subjectId: "u1", approverId: "u2" }));
			await insertAuditRow(db, row("r2", "a1", "u1", 2, { actorId: "a1", subjectId: "u1" }));
			await insertAuditRow(db, row("r3", "a1", "u1", 3));
			const before = await db.select().from(auditLogs).where(eq(auditLogs.agentId, "a1"));
			const hashes = before.map((r) => [r.id, r.hash]).sort();

			await createGdprModule(db).deleteUser("u1", { keepAuditLogs: true });

			const after = await db.select().from(auditLogs).where(eq(auditLogs.action, "execute"));
			expect(after.map((r) => [r.id, r.hash]).sort()).toEqual(hashes);
			for (const r of after) {
				expect(r.userId).toMatch(/^\[deleted-/);
				expect(r.agentId).toMatch(/^\[deleted-/);
				expect(r.subjectId).toBeNull();
				expect(r.actorId).toBeNull();
			}
			// approverId pointed at u2, who was not erased
			expect(after.find((r) => r.id === "r1")?.approverId).toBe("u2");

			const result = await verifyAuditChain(db, {}, hmacKey);
			expect(result.success && result.data.ok).toBe(true);
			expect(result.success && result.data.checked).toBe(3);
			expect(result.success && result.data.erased).toBe(3);
			// the per-installation secret is only created when no hmacKey is set
			const secrets = await db.select().from(auditSecrets);
			expect(secrets).toHaveLength(hmacKey ? 0 : 1);
		});
	}

	it("still detects tamper of a version 2 row after erasure", async () => {
		enableAuditChain(db, { hmacKey: KEY });
		await insertAuditRow(db, row("r1", "a1", "u1", 1, { subjectId: "u1" }));
		await insertAuditRow(db, row("r2", "a1", "u1", 2));
		await createGdprModule(db).deleteUser("u1", { keepAuditLogs: true });
		await db.update(auditLogs).set({ resource: "mcp:evil" }).where(eq(auditLogs.id, "r2"));
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.firstBreak?.reason).toBe("hash_mismatch");
	});

	it("reports an edited raw id as pseudonym_mismatch", async () => {
		enableAuditChain(db, { hmacKey: KEY });
		await insertAuditRow(db, row("r1", "a1", "u1", 1, { subjectId: "u1" }));
		await db.update(auditLogs).set({ subjectId: "u2" }).where(eq(auditLogs.id, "r1"));
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.firstBreak?.reason).toBe("pseudonym_mismatch");
	});

	async function insertV1(id: string, seq: number, prevHash: string | null): Promise<string> {
		const base = row(id, "a1", "u1", seq);
		const hash = await computeRowHash({ ...base, hashVersion: null }, seq, prevHash, KEY);
		await db.insert(auditLogs).values({ ...base, chainSeq: seq, prevHash, hash });
		return hash;
	}

	it("reports erased version 1 rows as erased, not as tamper", async () => {
		const h1 = await insertV1("v1", 1, null);
		const h2 = await insertV1("v2", 2, h1);
		await insertV1("v3", 3, h2);
		const pre = await verifyAuditChain(db, {}, KEY);
		expect(pre.success && pre.data.ok).toBe(true);

		// Erasure appends its signed record to the chain, so the chain is on as in production.
		enableAuditChain(db, { hmacKey: KEY });
		await createGdprModule(db).deleteUser("u1", { keepAuditLogs: true });

		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.ok).toBe(true);
		expect(result.success && result.data.erased).toBe(3);
		// the erasure record is a chained row, not an unchained one
		expect(result.success && result.data.unchained).toBe(0);
		const records = await db.select().from(auditLogs).where(eq(auditLogs.action, ERASURE_ACTION));
		expect(records).toHaveLength(1);
	});

	it("still flags a version 1 row that was edited, not erased", async () => {
		const h1 = await insertV1("v1", 1, null);
		await insertV1("v2", 2, h1);
		await db.update(auditLogs).set({ resource: "mcp:evil" }).where(eq(auditLogs.id, "v2"));
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.firstBreak?.reason).toBe("hash_mismatch");
	});

	it("does not let an erasure record excuse a changed version 1 row", async () => {
		const h1 = await insertV1("v1", 1, null);
		await insertV1("v2", 2, h1);
		enableAuditChain(db, { hmacKey: KEY });
		await createGdprModule(db).deleteUser("u1", { keepAuditLogs: true });
		// tamper with a row after it was erased: the stored hash no longer matches the record
		await db
			.update(auditLogs)
			.set({ hash: "f".repeat(64) })
			.where(eq(auditLogs.id, "v1"));
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.ok).toBe(false);
	});

	it("bridges rows removed by a hard delete and still catches other gaps", async () => {
		enableAuditChain(db, { hmacKey: KEY });
		// u2 acts on a1's chain between two of u1's rows.
		await insertAuditRow(db, row("r1", "a1", "u1", 1));
		await insertAuditRow(db, row("r2", "a1", "u2", 2));
		await insertAuditRow(db, row("r3", "a1", "u1", 3));

		await createGdprModule(db).deleteUser("u2", { keepAuditLogs: false });

		expect(await db.select().from(auditLogs).where(eq(auditLogs.id, "r2"))).toHaveLength(0);
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.ok).toBe(true);
		expect(result.success && result.data.erased).toBe(1);
	});

	it("still reports a row removed without an erasure record as a gap", async () => {
		enableAuditChain(db, { hmacKey: KEY });
		await insertAuditRow(db, row("r1", "a1", "u1", 1));
		await insertAuditRow(db, row("r2", "a1", "u1", 2));
		await insertAuditRow(db, row("r3", "a1", "u1", 3));
		await db.delete(auditLogs).where(eq(auditLogs.id, "r2"));
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.firstBreak?.reason).toBe("seq_gap");
	});
});
