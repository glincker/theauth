/**
 * Tamper-evident audit chain: append, verify, replay, export.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { and, eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import {
	enableAuditChain,
	exportAudit,
	insertAuditRow,
	replayAgent,
	verifyAuditChain,
	verifyAuditExport,
} from "../src/audit/index.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	approvalRequests,
	auditLogs,
	costEvents,
	delegationChains,
	users,
} from "../src/db/schema.js";

const KEY = "test-hmac-key";
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

function row(
	id: string,
	agentId: string,
	secondsAfter: number,
	extra: Partial<typeof auditLogs.$inferInsert> = {},
) {
	return {
		id,
		agentId,
		userId: "u1",
		action: "execute",
		resource: `mcp:github:${id}`,
		parameters: { b: 2, a: { z: 1, y: [1, 2] } },
		result: "allowed" as const,
		reason: null,
		durationMs: 5,
		timestamp: new Date(T0.getTime() + secondsAfter * 1000),
		...extra,
	};
}

async function appendN(db: Database, agentId: string, n: number, prefix = agentId) {
	for (let i = 1; i <= n; i++) await insertAuditRow(db, row(`${prefix}-${i}`, agentId, i));
}

async function verify(
	db: Database,
	opts: Parameters<typeof verifyAuditChain>[1] = {},
	key?: string,
) {
	const r = await verifyAuditChain(db, opts, key);
	if (!r.success) throw new Error(r.error.message);
	return r.data;
}

describe("audit hash chain", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	it("leaves rows unchained when the chain is not enabled", async () => {
		await appendN(db, "a1", 2);
		const rows = await db.select().from(auditLogs);
		expect(rows.every((r) => r.hash === null && r.chainSeq === null)).toBe(true);
		const v = await verify(db);
		expect(v).toMatchObject({ ok: true, checked: 0, unchained: 2 });
	});

	it("keeps old rows untouched and starts the chain at seq 1 after opt-in", async () => {
		await appendN(db, "a1", 2, "old");
		enableAuditChain(db);
		await appendN(db, "a1", 3, "new");
		const rows = await db.select().from(auditLogs).where(eq(auditLogs.agentId, "a1"));
		const old = rows.filter((r) => r.id.startsWith("old"));
		expect(old.every((r) => r.hash === null && r.prevHash === null)).toBe(true);
		const chained = rows
			.filter((r) => r.hash !== null)
			.sort((a, b) => (a.chainSeq ?? 0) - (b.chainSeq ?? 0));
		expect(chained.map((r) => r.chainSeq)).toEqual([1, 2, 3]);
		expect(chained[0]?.prevHash).toBeNull();
		expect(chained[1]?.prevHash).toBe(chained[0]?.hash);
		expect(await verify(db)).toMatchObject({ ok: true, checked: 3, unchained: 2 });
	});

	it("keeps a separate chain per agent", async () => {
		enableAuditChain(db);
		await appendN(db, "a1", 2);
		await appendN(db, "a2", 2);
		const v = await verify(db);
		expect(v.ok).toBe(true);
		expect(v.heads.map((h) => [h.agentId, h.seq])).toEqual([
			["a1", 2],
			["a2", 2],
		]);
	});

	it("detects a mutated row", async () => {
		enableAuditChain(db);
		await appendN(db, "a1", 4);
		await db.update(auditLogs).set({ result: "denied" }).where(eq(auditLogs.id, "a1-3"));
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.firstBreak).toMatchObject({
			agentId: "a1",
			rowId: "a1-3",
			seq: 3,
			reason: "hash_mismatch",
		});
	});

	it("detects a deleted row", async () => {
		enableAuditChain(db);
		await appendN(db, "a1", 4);
		await db.delete(auditLogs).where(eq(auditLogs.id, "a1-2"));
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.firstBreak).toMatchObject({ rowId: "a1-3", reason: "seq_gap" });
		expect(v.firstBreak?.rowIds).toEqual(["a1-1", "a1-3"]);
	});

	it("detects reordered rows", async () => {
		enableAuditChain(db);
		await appendN(db, "a1", 3);
		await db.update(auditLogs).set({ chainSeq: 99 }).where(eq(auditLogs.id, "a1-2"));
		await db.update(auditLogs).set({ chainSeq: 2 }).where(eq(auditLogs.id, "a1-3"));
		await db.update(auditLogs).set({ chainSeq: 3 }).where(eq(auditLogs.id, "a1-2"));
		const v = await verify(db);
		expect(v.ok).toBe(false);
		expect(v.firstBreak?.seq).toBe(2);
	});

	it("detects truncation only against a saved head", async () => {
		enableAuditChain(db);
		await appendN(db, "a1", 3);
		const before = await verify(db);
		await db.delete(auditLogs).where(and(eq(auditLogs.agentId, "a1"), eq(auditLogs.chainSeq, 3)));
		expect((await verify(db)).ok).toBe(true);
		const v = await verify(db, { expectedHeads: before.heads });
		expect(v.firstBreak).toMatchObject({ reason: "truncated", seq: 3 });
	});

	it("checks a time range, including the link to the row before it", async () => {
		enableAuditChain(db);
		await appendN(db, "a1", 5);
		const from = new Date(T0.getTime() + 3000);
		expect(await verify(db, { from })).toMatchObject({ ok: true, checked: 3 });
		await db.update(auditLogs).set({ prevHash: "x" }).where(eq(auditLogs.id, "a1-3"));
		const v = await verify(db, { from });
		expect(v.firstBreak).toMatchObject({ rowId: "a1-3", reason: "prev_hash_mismatch" });
	});

	it("uses HMAC when a key is set, so recomputing without the key fails", async () => {
		enableAuditChain(db, { hmacKey: KEY });
		await appendN(db, "a1", 2);
		expect((await verify(db, {}, KEY)).ok).toBe(true);
		expect((await verify(db, {}, "wrong-key")).firstBreak?.reason).toBe("hash_mismatch");
		expect((await verify(db)).ok).toBe(false);
	});

	it("does not fork under concurrent writers", async () => {
		enableAuditChain(db, { hmacKey: KEY });
		await Promise.all(
			Array.from({ length: 25 }, (_, i) => insertAuditRow(db, row(`c-${i}`, "a1", i))),
		);
		const rows = await db.select().from(auditLogs).where(eq(auditLogs.agentId, "a1"));
		expect(rows).toHaveLength(25);
		expect(rows.map((r) => r.chainSeq).sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual(
			Array.from({ length: 25 }, (_, i) => i + 1),
		);
		expect(await verify(db, {}, KEY)).toMatchObject({ ok: true, checked: 25 });
	});
});

describe("audit hash chain across connections", () => {
	it("two connections to one file never fork a chain", async () => {
		const dir = mkdtempSync(join(tmpdir(), "audit-chain-"));
		const url = join(dir, "audit.db");
		try {
			const first = await createDatabase({ provider: "sqlite-native", url });
			await createTables(first, "sqlite-native");
			await first.insert(users).values({
				id: "u1",
				email: "u1@example.com",
				name: "U1",
				username: "u1",
				createdAt: T0,
				updatedAt: T0,
			});
			await first.insert(agents).values({
				id: "a1",
				ownerId: "u1",
				name: "a1",
				type: "autonomous",
				status: "active",
				tokenHash: "h",
				tokenPrefix: "kv_x",
				metadata: {},
				createdAt: T0,
				updatedAt: T0,
			});
			const second = await createDatabase({ provider: "sqlite-native", url });
			enableAuditChain(first);
			enableAuditChain(second);
			await Promise.all(
				Array.from({ length: 20 }, (_, i) =>
					insertAuditRow(i % 2 === 0 ? first : second, row(`x-${i}`, "a1", i)),
				),
			);
			const rows = await first.select().from(auditLogs);
			expect(rows.map((r) => r.chainSeq).sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual(
				Array.from({ length: 20 }, (_, i) => i + 1),
			);
			expect(await verify(first)).toMatchObject({ ok: true, checked: 20 });
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("replayAgent", () => {
	it("merges actions, decisions, delegations, approvals and token events in order", async () => {
		const db = await setup();
		enableAuditChain(db);
		const at = (s: number) => new Date(T0.getTime() + s * 1000);
		await insertAuditRow(db, row("r1", "a1", 10));
		await insertAuditRow(db, row("r2", "a1", 30, { result: "denied", reason: "no scope" }));
		await insertAuditRow(db, row("other", "a2", 15));
		await db.insert(delegationChains).values({
			id: "d1",
			fromAgentId: "a1",
			toAgentId: "a2",
			permissions: [{ resource: "mcp:*", actions: ["read"] }],
			expiresAt: at(9999),
			createdAt: at(5),
		});
		await db.insert(approvalRequests).values({
			id: "ap1",
			agentId: "a1",
			userId: "u1",
			action: "write",
			resource: "db:prod",
			status: "approved",
			expiresAt: at(9999),
			respondedAt: at(25),
			respondedBy: "u1",
			createdAt: at(20),
		});
		await db.insert(costEvents).values({
			id: "c1",
			agentId: "a1",
			tool: "openai:gpt-4o",
			inputTokens: 10,
			outputTokens: 20,
			costMicros: 300,
			recordedAt: at(12),
		});

		const r = await replayAgent(db, "a1", { since: at(0), until: at(100), userId: "u1" });
		if (!r.success) throw new Error(r.error.message);
		expect(r.data.events.map((e) => `${e.kind}:${e.id}`)).toEqual([
			"delegation:d1",
			"action:r1",
			"token:c1",
			"approval:ap1:requested",
			"approval:ap1:approved",
			"decision:r2",
		]);
		expect(r.data.verification).toMatchObject({ status: "verified", checked: 2 });

		await db.update(auditLogs).set({ action: "delete" }).where(eq(auditLogs.id, "r1"));
		const broken = await replayAgent(db, "a1", {});
		if (!broken.success) throw new Error(broken.error.message);
		expect(broken.data.verification.status).toBe("broken");
		expect(broken.data.verification.firstBreak?.rowId).toBe("r1");
	});
});

describe("exportAudit", () => {
	it("writes JSONL with a signed manifest that verifies offline", async () => {
		const db = await setup();
		enableAuditChain(db, { hmacKey: KEY });
		await appendN(db, "a1", 3);
		const r = await exportAudit(db, { agentId: "a1" }, KEY);
		if (!r.success) throw new Error(r.error.message);
		expect(r.data.jsonl.trimEnd().split("\n")).toHaveLength(3);
		expect(r.data.manifest).toMatchObject({ rowCount: 3, chainVerified: true });
		expect(r.data.manifest.heads).toEqual([expect.objectContaining({ agentId: "a1", seq: 3 })]);
		expect((await verifyAuditExport(r.data, KEY)).ok).toBe(true);

		const edited = { ...r.data, jsonl: r.data.jsonl.replace("allowed", "denied") };
		const check = await verifyAuditExport(edited, KEY);
		expect(check.ok).toBe(false);
		expect(check.problems).toContain("file hash does not match manifest");
		expect((await verifyAuditExport(r.data, "other-key")).ok).toBe(false);
	});

	it("refuses to export without a signing key", async () => {
		const db = await setup();
		const r = await exportAudit(db, {});
		expect(r).toMatchObject({ success: false, error: { code: "NO_SIGNING_KEY" } });
	});
});
