/**
 * Denials that happen before permission evaluation (revoked or expired agent,
 * revoked or expired token) still leave an audit row for the known agent.
 */

import { eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { verifyAuditChain } from "../src/audit/index.js";
import { agents, auditLogs, users } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const KEY = "denials-test-key";

async function setup(opts: { auditAll?: boolean; tamperEvident?: boolean } = {}): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { auditAll: opts.auditAll ?? true },
		...(opts.tamperEvident ? { audit: { tamperEvident: true, hmacKey: KEY } } : {}),
	});
	await theauth.db.insert(users).values({
		id: "user-1",
		email: "denials@example.com",
		name: "Denials",
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	return theauth;
}

async function makeAgent(theauth: TheAuth, name: string) {
	return theauth.agent.create({
		ownerId: "user-1",
		name,
		type: "service",
		permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
	});
}

const req = { action: "read", resource: "mcp:github:repos" };

async function rowsFor(theauth: TheAuth, agentId: string) {
	return theauth.db.select().from(auditLogs).where(eq(auditLogs.agentId, agentId));
}

describe("audit rows for denials before permission evaluation", () => {
	it("records a revoked agent denial with reason agent_revoked", async () => {
		const theauth = await setup();
		const a = await makeAgent(theauth, "revoked-agent");
		await theauth.agent.revoke(a.id);

		const result = await theauth.authorize(a.id, req);
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("revoked");
		expect(result.auditId).not.toBe("");

		const rows = await rowsFor(theauth, a.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			id: result.auditId,
			result: "denied",
			reason: "agent_revoked",
			action: "read",
			resource: "mcp:github:repos",
			userId: "user-1",
		});
	});

	it("records an expired agent denial with reason agent_expired", async () => {
		const theauth = await setup();
		const a = await makeAgent(theauth, "expired-agent");
		await theauth.db.update(agents).set({ status: "expired" }).where(eq(agents.id, a.id));

		const result = await theauth.authorize(a.id, req);
		expect(result.allowed).toBe(false);
		const rows = await rowsFor(theauth, a.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({ result: "denied", reason: "agent_expired" });
	});

	it("records authorizeByToken for a revoked agent and never stores the token", async () => {
		const theauth = await setup();
		const a = await makeAgent(theauth, "token-revoked");
		await theauth.agent.revoke(a.id);

		const result = await theauth.authorizeByToken(a.token, req);
		expect(result.allowed).toBe(false);
		const rows = await rowsFor(theauth, a.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.reason).toBe("agent_revoked");
		expect(JSON.stringify(rows)).not.toContain(a.token);
	});

	it("records authorizeByToken for a token past its expiry as agent_expired", async () => {
		const theauth = await setup();
		const a = await makeAgent(theauth, "token-expired");
		await theauth.db
			.update(agents)
			.set({ expiresAt: new Date(Date.now() - 60_000) })
			.where(eq(agents.id, a.id));

		const result = await theauth.authorizeByToken(a.token, req);
		expect(result.allowed).toBe(false);
		const rows = await rowsFor(theauth, a.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({ result: "denied", reason: "agent_expired" });

		// Second attempt: status is now expired, still recorded.
		await theauth.authorizeByToken(a.token, req);
		expect(await rowsFor(theauth, a.id)).toHaveLength(2);
	});

	it("keeps the chain valid over a mix of allowed and denied rows", async () => {
		const theauth = await setup({ tamperEvident: true });
		const a = await makeAgent(theauth, "mixed");

		expect((await theauth.authorize(a.id, req)).allowed).toBe(true);
		expect((await theauth.authorize(a.id, { action: "write", resource: "x" })).allowed).toBe(false);
		await theauth.agent.revoke(a.id);
		expect((await theauth.authorize(a.id, req)).allowed).toBe(false);
		expect((await theauth.authorizeByToken(a.token, req)).allowed).toBe(false);

		const rows = await rowsFor(theauth, a.id);
		expect(rows).toHaveLength(4);
		expect(rows.map((r) => r.reason)).toEqual(
			expect.arrayContaining(["agent_revoked", "agent_revoked"]),
		);

		const verified = await verifyAuditChain(theauth.db, { agentId: a.id }, KEY);
		expect(verified.success).toBe(true);
		if (verified.success) {
			expect(verified.data.ok).toBe(true);
			expect(verified.data.checked).toBe(4);
		}
	});

	it("writes nothing when auditAll is false, and the denial is unchanged", async () => {
		const theauth = await setup({ auditAll: false });
		const a = await makeAgent(theauth, "quiet");
		await theauth.agent.revoke(a.id);

		const result = await theauth.authorize(a.id, req);
		expect(result.allowed).toBe(false);
		expect(result.auditId).toBe("");
		expect(await rowsFor(theauth, a.id)).toHaveLength(0);
	});

	it("writes no row for an unknown agent id or an unknown token", async () => {
		const theauth = await setup();
		const before = await theauth.db.select().from(auditLogs);

		const r1 = await theauth.authorize("no-such-agent", req);
		const r2 = await theauth.authorizeByToken("not-a-real-token", req);
		expect(r1.allowed).toBe(false);
		expect(r2.allowed).toBe(false);
		expect(r1.auditId).toBe("");
		expect(r2.auditId).toBe("");

		const after = await theauth.db.select().from(auditLogs);
		expect(after).toHaveLength(before.length);
	});

	it("stays denied, without throwing, when the audit write fails", async () => {
		const theauth = await setup();
		const a = await makeAgent(theauth, "broken-audit");
		await theauth.agent.revoke(a.id);
		await theauth.db.run(sql`DROP TABLE theauth_audit_logs`);

		const result = await theauth.authorize(a.id, req);
		expect(result.allowed).toBe(false);
		expect(result.auditId).toBe("");
	});
});
