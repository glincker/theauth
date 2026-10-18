/**
 * Regressions for the forged `audit.erasure` finding: someone with database write access but not the audit key must not be able to excuse an edit or a deletion with an erasure record they wrote themselves.
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { computeRowHash, ERASURE_ACTION } from "../src/audit/chain.js";
import { enableAuditChain, insertAuditRow, verifyAuditChain } from "../src/audit/index.js";
import { createGdprModule } from "../src/auth/gdpr.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const KEY = "secret-hmac-key";
const T0 = new Date("2026-10-01T00:00:00Z");

async function baseDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	for (const id of ["u1", "u2"]) {
		await db
			.insert(users)
			.values({ id, email: `${id}@x.io`, name: id, createdAt: T0, updatedAt: T0 });
	}
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
	return db;
}

function row(id: string, userId: string, i: number) {
	return {
		id,
		agentId: "a1",
		userId,
		action: "execute",
		resource: "db:prod",
		parameters: { i },
		result: i === 3 ? ("denied" as const) : ("allowed" as const),
		durationMs: 1,
		timestamp: new Date(T0.getTime() + i * 1000),
	};
}

async function chained(): Promise<Database> {
	const db = await baseDb();
	enableAuditChain(db, { hmacKey: KEY });
	for (let i = 1; i <= 5; i++) await insertAuditRow(db, row(`r${i}`, "u1", i));
	return db;
}

async function verify(db: Database) {
	const r = await verifyAuditChain(db, {}, KEY);
	if (!r.success) throw new Error(r.error.message);
	return r.data;
}

/** The record an attacker writes by hand: unchained, no MAC, values copied from the table. */
async function forgeUnchained(db: Database, rowId: string, id = "era_forged") {
	const [orig] = await db.select().from(auditLogs).where(eq(auditLogs.id, rowId));
	if (!orig) throw new Error("missing row");
	await db.insert(auditLogs).values({
		id,
		agentId: "a1",
		userId: "u1",
		action: ERASURE_ACTION,
		resource: "audit:a1",
		parameters: {
			rows: [
				{
					id: orig.id,
					agentId: "a1",
					seq: orig.chainSeq,
					hash: orig.hash,
					prevHash: orig.prevHash,
				},
			],
		},
		result: "allowed",
		reason: "erasure",
		durationMs: 0,
		timestamp: new Date(),
	});
	return orig;
}

describe("forged erasure records", () => {
	let db: Database;
	beforeEach(async () => {
		db = await chained();
	});

	it("deleting a middle row plus a forged unchained erasure record is reported", async () => {
		await forgeUnchained(db, "r3");
		await db.delete(auditLogs).where(eq(auditLogs.id, "r3"));
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.erased).toBe(0);
		expect(v.firstBreak).toMatchObject({ reason: "erasure_unchained", rowId: "era_forged" });
	});

	it("a chained erasure record whose entries carry no valid MAC is reported as forged", async () => {
		const [orig] = await db.select().from(auditLogs).where(eq(auditLogs.id, "r3"));
		if (!orig) throw new Error("missing row");
		// Even appended through the real writer (so its chain hash is valid), an entry without the erasure MAC excuses nothing.
		await insertAuditRow(db, {
			id: "era_chained",
			agentId: "a1",
			userId: "u1",
			action: ERASURE_ACTION,
			resource: "audit:a1",
			parameters: {
				rows: [
					{
						id: orig.id,
						agentId: "a1",
						seq: orig.chainSeq,
						hash: orig.hash,
						prevHash: orig.prevHash,
						hashVersion: 2,
						reason: "deleted",
						erasedHash: null,
						mac: "0".repeat(64),
					},
				],
			},
			result: "allowed",
			reason: "erasure",
			durationMs: 0,
			timestamp: new Date(),
		});
		await db.delete(auditLogs).where(eq(auditLogs.id, "r3"));
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.firstBreak).toMatchObject({ reason: "erasure_forged", rowId: "era_chained" });
	});

	it("a version 2 row rewritten to hash_version NULL is a version_downgrade", async () => {
		await db
			.update(auditLogs)
			.set({ hashVersion: null, result: "allowed", resource: "db:harmless" })
			.where(eq(auditLogs.id, "r3"));
		const v = await verify(db);
		expect(v.firstBreak).toMatchObject({ reason: "version_downgrade", rowId: "r3" });
	});

	it("a downgrade plus a forged erasure record is still reported", async () => {
		await forgeUnchained(db, "r3");
		await db
			.update(auditLogs)
			.set({ hashVersion: null, parameters: { forged: true } })
			.where(eq(auditLogs.id, "r3"));
		const v = await verify(db);
		expect(v.ok).toBe(false);
	});

	it("tampering with a genuine erasure record breaks its chain hash", async () => {
		await insertAuditRow(db, row("x1", "u2", 6));
		await insertAuditRow(db, row("r7", "u1", 7));
		await createGdprModule(db).deleteUser("u2", { keepAuditLogs: false });
		expect((await verify(db)).ok).toBe(true);
		const [rec] = await db.select().from(auditLogs).where(eq(auditLogs.action, ERASURE_ACTION));
		if (!rec) throw new Error("no erasure record");
		await db
			.update(auditLogs)
			.set({ parameters: { rows: [] } })
			.where(eq(auditLogs.id, rec.id));
		const v = await verify(db);
		expect(v.ok).toBe(false);
	});
});

describe("genuine erasure keeps verifying", () => {
	async function insertV1(db: Database, id: string, seq: number, prev: string | null) {
		const base = { ...row(id, "u1", seq), hashVersion: null };
		const hash = await computeRowHash(base, seq, prev, KEY);
		await db.insert(auditLogs).values({ ...base, chainSeq: seq, prevHash: prev, hash });
		return hash;
	}

	it("anonymized version 1 rows verify as erased, and a later edit of one is caught", async () => {
		const db = await baseDb();
		const h1 = await insertV1(db, "v1", 1, null);
		const h2 = await insertV1(db, "v2", 2, h1);
		await insertV1(db, "v3", 3, h2);
		enableAuditChain(db, { hmacKey: KEY });
		await createGdprModule(db).deleteUser("u1", { keepAuditLogs: true });

		const ok = await verify(db);
		expect(ok).toMatchObject({ ok: true, erased: 3, unchained: 0 });
		const [rec] = await db.select().from(auditLogs).where(eq(auditLogs.action, ERASURE_ACTION));
		expect(rec?.hash).not.toBeNull();
		expect(rec?.chainSeq).toBe(4);

		// The entry pins the row as erasure left it, so editing it afterwards is tamper.
		await db.update(auditLogs).set({ resource: "db:edited" }).where(eq(auditLogs.id, "v2"));
		const bad = await verify(db);
		expect(bad.firstBreak).toMatchObject({ reason: "hash_mismatch", rowId: "v2" });
	});

	it("an edited version 1 row is not excused by a forged record", async () => {
		const db = await baseDb();
		const h1 = await insertV1(db, "v1", 1, null);
		await insertV1(db, "v2", 2, h1);
		await db
			.update(auditLogs)
			.set({ result: "allowed", reason: "edited" })
			.where(eq(auditLogs.id, "v2"));
		await forgeUnchained(db, "v2");
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.erased).toBe(0);
	});

	it("a hard deleted middle row is bridged by the signed, chained record", async () => {
		const db = await baseDb();
		enableAuditChain(db, { hmacKey: KEY });
		await insertAuditRow(db, row("r1", "u1", 1));
		await insertAuditRow(db, row("r2", "u2", 2));
		await insertAuditRow(db, row("r3", "u1", 3));
		await createGdprModule(db).deleteUser("u2", { keepAuditLogs: false });
		const v = await verify(db);
		expect(v).toMatchObject({ ok: true, erased: 1, checked: 3 });
	});

	it("a verifier with the wrong key rejects the erasure entries", async () => {
		const db = await baseDb();
		enableAuditChain(db, { hmacKey: KEY });
		await insertAuditRow(db, row("r1", "u1", 1));
		await insertAuditRow(db, row("r2", "u2", 2));
		await createGdprModule(db).deleteUser("u2", { keepAuditLogs: false });
		const r = await verifyAuditChain(db, {}, "other-key");
		expect(r.success && r.data.firstBreak?.reason).toBe("erasure_forged");
	});
});
