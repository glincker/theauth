/** Audit rows written in the same second keep their write order, and the order column is not hashed. */
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createAuditModule } from "../src/audit/audit.js";
import { nextRecordedAtMs } from "../src/audit/chain.js";
import { enableAuditChain, insertAuditRow, verifyAuditChain } from "../src/audit/index.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const T0 = new Date("2026-10-01T00:00:00Z");

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	await db.insert(users).values({
		id: "u1",
		email: "u1@example.com",
		name: "U1",
		username: "u1",
		createdAt: T0,
		updatedAt: T0,
	});
	for (const id of ["a1", "a2"]) {
		await db.insert(agents).values({
			id,
			ownerId: "u1",
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

function row(id: string, agentId: string, ts: Date = T0) {
	return {
		id,
		agentId,
		userId: "u1",
		action: "execute",
		resource: `mcp:test:${id}`,
		parameters: {},
		result: "allowed" as const,
		durationMs: 1,
		timestamp: ts,
	};
}

describe("audit write ordering", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	it("stamps strictly increasing milliseconds even when the clock stalls", () => {
		const a = nextRecordedAtMs();
		const b = nextRecordedAtMs();
		const c = nextRecordedAtMs(b + 5000);
		expect(b).toBeGreaterThan(a);
		expect(c).toBeGreaterThan(b + 5000);
	});

	for (const chained of [true, false]) {
		it(`returns same-second rows newest first (${chained ? "chained" : "unchained"})`, async () => {
			if (chained) enableAuditChain(db);
			// Identical timestamp for every row: only the write order tells them apart.
			for (let i = 1; i <= 8; i++) await insertAuditRow(db, row(`r${i}`, "a1"));
			const audit = createAuditModule({ db });
			const entries = await audit.query({ agentId: "a1" });
			expect(entries.map((e) => e.id)).toEqual(["r8", "r7", "r6", "r5", "r4", "r3", "r2", "r1"]);
		});
	}

	it("orders across agents by write order, not by agent", async () => {
		enableAuditChain(db);
		await insertAuditRow(db, row("x1", "a1"));
		await insertAuditRow(db, row("y1", "a2"));
		await insertAuditRow(db, row("x2", "a1"));
		const entries = await createAuditModule({ db }).query({});
		expect(entries.map((e) => e.id)).toEqual(["x2", "y1", "x1"]);
	});

	it("never lets a chain's order go backwards when an earlier writer stamped ahead", async () => {
		enableAuditChain(db);
		await insertAuditRow(db, row("first", "a1"));
		const ahead = Date.now() + 60_000;
		await db.update(auditLogs).set({ recordedAtMs: ahead }).where(eq(auditLogs.id, "first"));
		await insertAuditRow(db, row("second", "a1"));
		const [second] = await db.select().from(auditLogs).where(eq(auditLogs.id, "second"));
		expect(second?.recordedAtMs).toBeGreaterThan(ahead);
	});

	it("breaks ties on backfilled rows by chain_seq then id", async () => {
		enableAuditChain(db);
		for (let i = 1; i <= 3; i++) await insertAuditRow(db, row(`b${i}`, "a1"));
		// Simulate migration 0003 backfill: every same-second row gets the same value.
		await db.update(auditLogs).set({ recordedAtMs: T0.getTime() });
		const entries = await createAuditModule({ db }).query({ agentId: "a1" });
		expect(entries.map((e) => e.id)).toEqual(["b3", "b2", "b1"]);
	});

	it("keeps recorded_at_ms out of the hash: an old-style chain with no value still verifies", async () => {
		enableAuditChain(db, { hmacKey: "k" });
		for (let i = 1; i <= 3; i++)
			await insertAuditRow(db, row(`c${i}`, "a1", new Date(T0.getTime() + i * 1000)));
		// Make the rows look like they predate the column.
		await db.update(auditLogs).set({ recordedAtMs: null });
		const r = await verifyAuditChain(db, { agentId: "a1" }, "k");
		expect(r.success && r.data).toMatchObject({ ok: true, checked: 3 });
		// Any value in the order column leaves the hashes untouched.
		await db.update(auditLogs).set({ recordedAtMs: 12345 });
		const again = await verifyAuditChain(db, { agentId: "a1" }, "k");
		expect(again.success && again.data).toMatchObject({ ok: true, checked: 3 });
	});
});
