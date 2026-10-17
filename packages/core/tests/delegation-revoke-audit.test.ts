/** delegation.revoke writes a chained audit row for every revoked link, cascade included. */
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { verifyAuditChain } from "../src/audit/index.js";
import { auditLogs, users } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const KEY = "revoke-audit-key";
const EXP = new Date(Date.now() + 3_600_000);
const PERMS = [{ resource: "mcp:github:*", actions: ["read"] }];

async function setup(): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], tokenExpiry: "24h" },
		audit: { tamperEvident: true, hmacKey: KEY },
	});
	await theauth.db.insert(users).values({
		id: "user-1",
		email: "u@example.com",
		name: "U",
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	return theauth;
}

describe("delegation.revoke audit", () => {
	let theauth: TheAuth;
	beforeEach(async () => {
		theauth = await setup();
	});

	const mk = (name: string, permissions = PERMS) =>
		theauth.agent.create({ ownerId: "user-1", name, type: "delegated", permissions });

	async function revokeRows(agentId: string) {
		const rows = await theauth.db.select().from(auditLogs).where(eq(auditLogs.agentId, agentId));
		return rows.filter((r) => r.action === "delegation.revoke");
	}

	it("writes one chained row for a revoked link", async () => {
		const a = await mk("a");
		const b = await mk("b", []);
		const link = await theauth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: PERMS,
			expiresAt: EXP,
		});
		await theauth.delegation.revoke(link.id);

		const rows = await revokeRows(b.id);
		expect(rows).toHaveLength(1);
		const [r] = rows;
		expect(r?.resource).toBe(`delegation:${link.id}`);
		expect(r?.hash).not.toBeNull();
		expect(r?.parameters).toMatchObject({
			delegationId: link.id,
			fromAgent: a.id,
			toAgent: b.id,
			cascade: false,
			cascadeFrom: null,
		});
		const v = await verifyAuditChain(theauth.db, { agentId: b.id }, KEY);
		expect(v.success && v.data.ok).toBe(true);
	});

	it("writes a row for each link revoked by cascade, pointing at its parent link", async () => {
		const a = await mk("a");
		const b = await mk("b", []);
		const c = await mk("c", []);
		const ab = await theauth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: PERMS,
			expiresAt: EXP,
		});
		const bc = await theauth.delegate({
			fromAgent: b.id,
			toAgent: c.id,
			permissions: PERMS,
			expiresAt: EXP,
		});
		await theauth.delegation.revoke(ab.id);

		const [rb] = await revokeRows(b.id);
		const [rc] = await revokeRows(c.id);
		expect(rb?.parameters).toMatchObject({ delegationId: ab.id, cascade: false });
		expect(rc?.parameters).toMatchObject({
			delegationId: bc.id,
			cascade: true,
			cascadeFrom: ab.id,
			rootDelegationId: ab.id,
		});
		for (const id of [b.id, c.id]) {
			const v = await verifyAuditChain(theauth.db, { agentId: id }, KEY);
			expect(v.success && v.data.ok).toBe(true);
		}
	});

	it("does not write a second row when the link is already revoked", async () => {
		const a = await mk("a");
		const b = await mk("b", []);
		const link = await theauth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: PERMS,
			expiresAt: EXP,
		});
		await theauth.delegation.revoke(link.id);
		await theauth.delegation.revoke(link.id);
		expect(await revokeRows(b.id)).toHaveLength(1);
	});
});
