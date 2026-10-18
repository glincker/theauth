/** Audit query v2: order, cursor paging, event and resource filters, event column and migration 0005. */
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createAuditModule } from "../src/audit/audit.js";
import { computeRowHash } from "../src/audit/chain.js";
import {
	decodeAuditCursor,
	enableAuditChain,
	encodeAuditCursor,
	insertAuditRow,
	isInvalidAuditCursor,
	verifyAuditChain,
} from "../src/audit/index.js";
import { recordAuditEvent } from "../src/audit/record.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { runMigrations } from "../src/db/migrate/index.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";
import { columnsOf, indexNames, memoryDbV120 } from "./helpers-schema-db.js";

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

function row(id: string, agentId: string, extra: Partial<typeof auditLogs.$inferInsert> = {}) {
	return {
		id,
		agentId,
		userId: "u1",
		action: "read",
		resource: `mcp:github:${id}`,
		parameters: {},
		result: "allowed" as const,
		durationMs: 1,
		timestamp: T0,
		...extra,
	};
}

async function drain(
	audit: ReturnType<typeof createAuditModule>,
	order: "asc" | "desc",
	limit: number,
): Promise<{ ids: string[]; pages: number }> {
	const ids: string[] = [];
	let cursor: string | undefined;
	let pages = 0;
	for (;;) {
		const page = await audit.page({ order, limit, ...(cursor ? { cursor } : {}) });
		pages++;
		ids.push(...page.entries.map((e) => e.id));
		if (!page.nextCursor) return { ids, pages };
		cursor = page.nextCursor;
	}
}

describe("audit query v2", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	it("defaults to newest first and supports order asc", async () => {
		for (let i = 1; i <= 4; i++) await insertAuditRow(db, row(`r${i}`, "a1"));
		const audit = createAuditModule({ db });
		expect((await audit.query({})).map((e) => e.id)).toEqual(["r4", "r3", "r2", "r1"]);
		expect((await audit.query({ order: "desc" })).map((e) => e.id)).toEqual([
			"r4",
			"r3",
			"r2",
			"r1",
		]);
		expect((await audit.query({ order: "asc" })).map((e) => e.id)).toEqual([
			"r1",
			"r2",
			"r3",
			"r4",
		]);
	});

	for (const order of ["asc", "desc"] as const) {
		it(`pages ${order} with a cursor, no gaps or repeats, including same millisecond rows`, async () => {
			enableAuditChain(db);
			// Ten rows share one recorded_at_ms: only the id breaks the tie.
			for (let i = 1; i <= 10; i++) {
				await insertAuditRow(db, row(`m${String(i).padStart(2, "0")}`, i % 2 ? "a1" : "a2"));
			}
			await db.update(auditLogs).set({ recordedAtMs: 1_790_000_000_000 });
			const audit = createAuditModule({ db });
			const all = (await audit.query({ order })).map((e) => e.id);
			expect(new Set(all).size).toBe(10);
			const { ids, pages } = await drain(audit, order, 3);
			expect(ids).toEqual(all);
			expect(pages).toBe(4);
		});
	}

	it("returns a null cursor on the last page and when there is no limit", async () => {
		for (let i = 1; i <= 3; i++) await insertAuditRow(db, row(`r${i}`, "a1"));
		const audit = createAuditModule({ db });
		expect((await audit.page({ limit: 3 })).nextCursor).toBeNull();
		expect((await audit.page({})).nextCursor).toBeNull();
		expect((await audit.page({ limit: 2 })).nextCursor).not.toBeNull();
	});

	it("stays stable when rows are written between pages", async () => {
		for (let i = 1; i <= 6; i++) await insertAuditRow(db, row(`r${i}`, "a1"));
		const audit = createAuditModule({ db });
		const first = await audit.page({ order: "desc", limit: 3 });
		await insertAuditRow(db, row("late", "a1"));
		const second = await audit.page({ order: "desc", limit: 3, cursor: first.nextCursor ?? "" });
		expect(first.entries.map((e) => e.id)).toEqual(["r6", "r5", "r4"]);
		expect(second.entries.map((e) => e.id)).toEqual(["r3", "r2", "r1"]);
	});

	it("rejects a cursor it did not issue", async () => {
		const audit = createAuditModule({ db });
		for (const bad of ["nope", "c1.@@@", `c1.${btoa("[1]")}`]) {
			await expect(audit.page({ cursor: bad })).rejects.toSatisfy(isInvalidAuditCursor);
		}
		expect(decodeAuditCursor(encodeAuditCursor({ ms: 5, id: "é-1" }))).toEqual({
			ms: 5,
			id: "é-1",
		});
	});

	it("filters by events, actions and resource prefix in SQL", async () => {
		await insertAuditRow(
			db,
			row("a", "a1", { event: "authorize", resource: "mcp:github:create_issue" }),
		);
		await insertAuditRow(
			db,
			row("b", "a1", { event: "policy.evaluate", resource: "mcp:github:list" }),
		);
		await insertAuditRow(
			db,
			row("c", "a1", { event: "authorize", action: "write", resource: "mcp:slack:post" }),
		);
		await insertAuditRow(db, row("d", "a1", { event: "authorize", resource: "mcp:git_hub%:x" }));
		const audit = createAuditModule({ db });
		const ids = async (f: Parameters<typeof audit.query>[0]) =>
			(await audit.query({ ...f, order: "asc" })).map((e) => e.id);
		expect(await ids({ events: ["authorize"] })).toEqual(["a", "c", "d"]);
		expect(await ids({ events: ["authorize", "policy.evaluate"], actions: ["write"] })).toEqual([
			"c",
		]);
		expect(await ids({ resource: "mcp:github:*" })).toEqual(["a", "b"]);
		expect(await ids({ resource: "mcp:slack:post" })).toEqual(["c"]);
		// LIKE wildcards in the prefix are literal.
		expect(await ids({ resource: "mcp:git_hub%*" })).toEqual(["d"]);
		expect(await ids({ resource: "mcp:gi_hub*" })).toEqual([]);
	});

	it("applies the actions filter before the limit", async () => {
		await insertAuditRow(db, row("w1", "a1", { action: "write" }));
		for (let i = 1; i <= 5; i++) await insertAuditRow(db, row(`r${i}`, "a1"));
		const entries = await createAuditModule({ db }).query({ actions: ["write"], limit: 2 });
		expect(entries.map((e) => e.id)).toEqual(["w1"]);
	});

	it("exposes event on entries and derives it for known action names", async () => {
		await insertAuditRow(db, row("e1", "a1", { event: "authorize" }));
		await insertAuditRow(db, row("e2", "a1", { action: "vault.read" }));
		await insertAuditRow(db, row("e3", "a1"));
		await recordAuditEvent(db, {
			agentId: "a1",
			action: "delegate",
			event: "delegation.create",
			resource: "delegation:d1",
			result: "allowed",
		});
		const byId = new Map((await createAuditModule({ db }).query({})).map((e) => [e.id, e]));
		expect(byId.get("e1")?.event).toBe("authorize");
		expect(byId.get("e2")?.event).toBe("vault.read");
		expect(byId.get("e3")?.event).toBeNull();
		const delegated = (await createAuditModule({ db }).query({ events: ["delegation.create"] }))[0];
		expect(delegated?.action).toBe("delegate");
	});

	it("keeps event out of the hash: old-style chains verify with or without it", async () => {
		enableAuditChain(db, { hmacKey: "k" });
		await insertAuditRow(db, row("h1", "a1", { event: "authorize" }));
		await insertAuditRow(db, row("h2", "a1", { event: "policy.evaluate" }));
		await insertAuditRow(db, row("h3", "a1"));
		const verified = async () => {
			const r = await verifyAuditChain(db, { agentId: "a1" }, "k");
			return r.success && r.data;
		};
		expect(await verified()).toMatchObject({ ok: true, checked: 3 });
		// Rows from before the column exist read back with no event: still valid.
		await db.update(auditLogs).set({ event: null });
		expect(await verified()).toMatchObject({ ok: true, checked: 3 });
		await db.update(auditLogs).set({ event: "anything.else" });
		expect(await verified()).toMatchObject({ ok: true, checked: 3 });
		const [stored] = await db.select().from(auditLogs).where(eq(auditLogs.id, "h1"));
		if (!stored) throw new Error("row missing");
		const same = await computeRowHash({ ...stored, event: "x" }, 1, null, "k");
		const other = await computeRowHash({ ...stored, event: null }, 1, null, "k");
		expect(same).toBe(other);
		expect(same).toBe(stored.hash);
	});
});

describe("migration 0005 audit-event", () => {
	it("adds the column and index, and backfills only rows it can classify", async () => {
		const { db, exec } = await memoryDbV120({ withData: true });
		await runMigrations(db, "sqlite", { to: "0004" });
		const ins = (id: string, action: string, code: string | null, prov: string | null) =>
			exec.run(
				`INSERT INTO theauth_audit_logs (id, agent_id, user_id, action, resource, result, duration_ms, timestamp, decision_code, input_provenance) VALUES ('${id}', 'a1', 'u1', '${action}', 'r', 'allowed', 1, 1700000300, ${code ? `'${code}'` : "NULL"}, ${prov ? `'${prov}'` : "NULL"})`,
			);
		await ins("d1", "delegation.create", null, null);
		await ins("d2", "approval.request", null, null);
		await ins("p1", "read", "allowed", '{"x":1}');
		await ins("z1", "read", "no_permission", null);
		await ins("u1x", "register", null, null);
		expect(await columnsOf(exec, "theauth_audit_logs")).not.toContain("event");

		await runMigrations(db, "sqlite");
		expect(await columnsOf(exec, "theauth_audit_logs")).toContain("event");
		expect(await indexNames(exec, "theauth_audit_logs")).toContain("theauth_audit_logs_event");
		const rows = await exec.all(
			"SELECT id AS id, event AS event FROM theauth_audit_logs ORDER BY id",
		);
		const events = Object.fromEntries(rows.map((r) => [String(r.id), r.event]));
		expect(events).toMatchObject({
			d1: "delegation.create",
			d2: "approval.request",
			p1: "policy.evaluate",
			z1: "authorize",
			u1x: null,
			r1: null,
			r2: null,
		});
		const again = await runMigrations(db, "sqlite");
		expect(again.applied).toEqual([]);
	});
});
