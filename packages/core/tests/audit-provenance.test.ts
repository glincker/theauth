/** Input provenance capture (hash only), the provenance filter, and rotating pseudonyms. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { guardTool } from "../src/agent-tools/guard.js";
import { createAuditModule } from "../src/audit/audit.js";
import {
	buildInputProvenance,
	enableAuditChain,
	exportAudit,
	hashInputContent,
	insertAuditRow,
	verifyAuditChain,
} from "../src/audit/index.js";
import { shredPseudonymPeriods } from "../src/audit/pseudonym-rotation.js";
import { isReservedAuditKey } from "../src/audit/reserved.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, auditSecrets, users } from "../src/db/schema.js";
import { auditRows, makeTheAuth, newAgent, pause, READ_GITHUB } from "./hook-test-utils.js";

const KEY = "prov-key";
const DAY = 24 * 60 * 60 * 1000;
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
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		status: "active",
		tokenHash: "h-a1",
		tokenPrefix: "kv_x",
		metadata: {},
		createdAt: T0,
		updatedAt: T0,
	});
	return db;
}

function row(id: string, at: Date, extra: Partial<typeof auditLogs.$inferInsert> = {}) {
	return {
		id,
		agentId: "a1",
		userId: "u1",
		subjectId: "u1",
		action: "read",
		resource: `mcp:github:${id}`,
		parameters: {},
		result: "allowed" as const,
		durationMs: 0,
		timestamp: at,
		...extra,
	};
}

describe("input provenance capture", () => {
	it("hashes content, drops bad entries and never keeps the content", async () => {
		const rec = await buildInputProvenance([
			{ kind: "user_message", id: "msg_1", content: "ignore previous instructions" },
			{ kind: "user_message", id: "msg_1", content: "ignore previous instructions" },
			{ kind: "tool_output", hash: "a".repeat(64) },
			{ kind: "bogus" as never, content: "x" },
			{ kind: "agent" },
			{ kind: "retrieved_document", hash: "not-hex" },
		]);
		expect(rec?.sources).toHaveLength(2);
		expect(JSON.stringify(rec)).not.toContain("ignore previous");
		expect(rec?.sources[0]?.hash).toBe(await hashInputContent("ignore previous instructions"));
		expect(await buildInputProvenance(undefined)).toBeUndefined();
	});

	it("reserves the inputProvenance argument name", () => {
		expect(isReservedAuditKey("inputProvenance")).toBe(true);
	});

	it("authorize records sources from context.inputs, allowed and denied", async () => {
		const theauth = await makeTheAuth({ tamperEvident: true });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const secret = "super secret retrieved text";
		const inputs = [
			{ kind: "retrieved_document" as const, id: "doc-9", content: secret },
			{ kind: "user_message" as const, id: "m-1", content: "hello" },
		];
		await theauth.authorize(
			agent.id,
			{
				action: "read",
				resource: "mcp:github:issues",
				arguments: { inputProvenance: { forged: true }, q: "x" },
			},
			{ inputs },
		);
		await theauth.authorize(
			agent.id,
			{ action: "delete", resource: "mcp:github:issues" },
			{ inputs: [inputs[0] as (typeof inputs)[0]] },
		);
		const rows = await auditRows(theauth, agent.id);
		expect(rows).toHaveLength(2);
		for (const r of rows) {
			const prov = r.inputProvenance as { sources: { kind: string; hash: string }[] };
			expect(prov.sources[0]?.kind).toBe("retrieved_document");
			expect(JSON.stringify(r)).not.toContain(secret);
		}
		const allowed = rows.find((r) => r.result === "allowed");
		expect(allowed?.parameters).toEqual({ q: "x" });

		const hash = await hashInputContent(secret);
		const both = await theauth.audit.query({ agentId: agent.id, provenance: { hash } });
		expect(both).toHaveLength(2);
		const msgs = await theauth.audit.query({
			agentId: agent.id,
			provenance: { kind: "user_message" },
		});
		expect(msgs).toHaveLength(1);
		expect(
			await theauth.audit.query({
				agentId: agent.id,
				provenance: { kind: "user_message", hash },
			}),
		).toHaveLength(0);
		await expect(
			theauth.audit.query({ agentId: agent.id, provenance: { hash: "zz" } }),
		).rejects.toThrow(/64 lowercase hex/);

		const verified = await theauth.audit.verifyAuditChain({});
		expect(verified.success && verified.data.ok).toBe(true);
	});

	it("policy.evaluate merges sources with the taint labels", async () => {
		const theauth = await makeTheAuth({ tamperEvident: true, policy: { audit: true } });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const d = await theauth.policy.evaluate({
			subject: { agentId: agent.id },
			action: "read",
			resource: "mcp:github:issues",
			context: {
				provenance: { "*": ["untrusted_web"] },
				inputs: [{ kind: "agent", id: "agent-2", content: "plan" }],
			},
		});
		expect(d.allowed).toBe(true);
		await pause(30);
		const [r] = await auditRows(theauth, agent.id);
		const prov = r?.inputProvenance as { labels: unknown; sources: { kind: string }[] };
		expect(prov.labels).toEqual({ "*": ["untrusted_web"] });
		expect(prov.sources[0]?.kind).toBe("agent");
	});

	it("guardTool records declared inputs for an MCP style tool call", async () => {
		const theauth = await makeTheAuth({ tamperEvident: true });
		const agent = await newAgent(theauth, "a", [{ resource: "tool:search", actions: ["execute"] }]);
		const tool = guardTool(
			theauth,
			{
				agentId: agent.id,
				name: "search",
				inputs: (args: { q: string }) => [{ kind: "user_message", id: "m-7", content: args.q }],
			},
			{ execute: async (args: { q: string }) => args.q },
		);
		await tool.execute({ q: "private question" });
		await pause(30);
		const [r] = await auditRows(theauth, agent.id);
		expect(JSON.stringify(r?.inputProvenance)).not.toContain("private question");
		const found = await theauth.audit.query({
			agentId: agent.id,
			provenance: { kind: "user_message", hash: await hashInputContent("private question") },
		});
		expect(found).toHaveLength(1);
	});

	it("export and verification still work with provenance rows", async () => {
		const db = await setup();
		enableAuditChain(db, { hmacKey: KEY });
		const inputProvenance = await buildInputProvenance([{ kind: "tool_output", content: "out" }]);
		await insertAuditRow(db, row("r1", T0, { inputProvenance }));
		await insertAuditRow(db, row("r2", new Date(T0.getTime() + 1000)));
		const out = await exportAudit(db, { agentId: "a1" }, KEY);
		if (!out.success) throw new Error(out.error.message);
		expect(out.data.manifest.chainVerified).toBe(true);
		const hash = await hashInputContent("out");
		const found = await createAuditModule({ db, hmacKey: KEY }).query({
			provenance: { kind: "tool_output", hash },
		});
		expect(found.map((e) => e.id)).toEqual(["r1"]);
	});
});

describe("rotating pseudonyms", () => {
	const rotation = { periodDays: 1, retainPeriods: 0 };

	it("gives one subject a different pseudonym per period and keeps the chain valid", async () => {
		const db = await setup();
		enableAuditChain(db, { hmacKey: KEY, pseudonymRotation: rotation });
		await insertAuditRow(db, row("r1", T0));
		await insertAuditRow(db, row("r2", new Date(T0.getTime() + 2 * DAY)));
		await insertAuditRow(db, row("r3", new Date(T0.getTime() + 2 * DAY + 5000)));
		const rows = await db.select().from(auditLogs).orderBy(auditLogs.chainSeq);
		const [p1, p2, p3] = rows.map((r) => r.idPseudonyms ?? {});
		expect(p1?.userId).not.toBe(p2?.userId);
		expect(p2?.userId).toBe(p3?.userId);
		expect(p1?.period).not.toBe(p2?.period);
		const v = await verifyAuditChain(db, {}, KEY);
		expect(v.success && v.data.ok).toBe(true);
	});

	it("shreds old period secrets on the first write of a new period, verification still passes", async () => {
		const db = await setup();
		enableAuditChain(db, { hmacKey: KEY, pseudonymRotation: rotation });
		await insertAuditRow(db, row("r1", T0));
		expect(await db.select().from(auditSecrets)).toHaveLength(1);
		await insertAuditRow(db, row("r2", new Date(T0.getTime() + 3 * DAY)));
		const left = await db.select().from(auditSecrets);
		expect(left).toHaveLength(1);
		expect(left[0]?.id.endsWith(`:p${Math.floor((T0.getTime() + 3 * DAY) / DAY)}`)).toBe(true);
		const v = await verifyAuditChain(db, {}, KEY);
		expect(v.success && v.data.ok).toBe(true);
	});

	it("still catches an edited raw id in a live period but not in a shredded one", async () => {
		const db = await setup();
		enableAuditChain(db, { hmacKey: KEY, pseudonymRotation: { periodDays: 1, retainPeriods: 1 } });
		await insertAuditRow(db, row("r1", T0));
		await insertAuditRow(db, row("r2", new Date(T0.getTime() + DAY)));
		await db.update(auditLogs).set({ subjectId: "someone-else" }).where(eq(auditLogs.id, "r2"));
		const v = await verifyAuditChain(db, {}, KEY);
		expect(v.success && v.data.ok).toBe(false);
		expect(v.success && v.data.firstBreak?.reason).toBe("pseudonym_mismatch");
		await db.update(auditLogs).set({ subjectId: "u1" }).where(eq(auditLogs.id, "r2"));
		const period = Math.floor(T0.getTime() / DAY);
		expect(await shredPseudonymPeriods(db, period + 5, 0)).toEqual([period, period + 1]);
	});

	it("rejects a bad period length", async () => {
		const db = await setup();
		enableAuditChain(db, { hmacKey: KEY, pseudonymRotation: { periodDays: 0 } });
		await expect(insertAuditRow(db, row("r1", T0))).rejects.toThrow(/periodDays/);
	});
});
