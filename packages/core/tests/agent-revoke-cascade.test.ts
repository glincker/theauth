import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { verifyAuditChain } from "../src/audit/index.js";
import * as schema from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const KEY = "cascade-test-key";
const PERMS = [{ resource: "mcp:github:*", actions: ["read"] }];

interface Fixture {
	theauth: TheAuth;
	revokedHook: string[];
	ids: { a: string; b: string; c: string; x: string; y: string };
	chains: { ab: string; bc: string; xy: string };
}

async function setup(): Promise<Fixture> {
	const revokedHook: string[] = [];
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], tokenExpiry: "24h" },
		audit: { tamperEvident: true, hmacKey: KEY },
		hooks: {
			onAgentRevoke: async (agentId: string) => {
				revokedHook.push(agentId);
			},
		},
	});
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "u@example.com",
			name: "U",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	const mk = async (name: string, permissions = PERMS) =>
		(await theauth.agent.create({ ownerId: "user-1", name, type: "autonomous", permissions })).id;
	const a = await mk("a");
	const b = await mk("b", []);
	const c = await mk("c", []);
	const x = await mk("x");
	const y = await mk("y", []);
	const expiresAt = new Date(Date.now() + 3_600_000);
	const ab = await theauth.delegate({ fromAgent: a, toAgent: b, permissions: PERMS, expiresAt });
	const bc = await theauth.delegate({ fromAgent: b, toAgent: c, permissions: PERMS, expiresAt });
	const xy = await theauth.delegate({ fromAgent: x, toAgent: y, permissions: PERMS, expiresAt });
	return {
		theauth,
		revokedHook,
		ids: { a, b, c, x, y },
		chains: { ab: ab.id, bc: bc.id, xy: xy.id },
	};
}

async function statusOf(theauth: TheAuth, id: string): Promise<string | undefined> {
	const rows = await theauth.db
		.select()
		.from(schema.delegationChains)
		.where(eq(schema.delegationChains.id, id));
	return rows[0]?.status;
}

describe("agent.revoke cascade", () => {
	let f: Fixture;
	beforeEach(async () => {
		f = await setup();
	});

	it("revokes chains where the agent is the source, and child chains", async () => {
		const result = await f.theauth.agent.revoke(f.ids.a);
		expect(await statusOf(f.theauth, f.chains.ab)).toBe("revoked");
		expect(result.revokedDelegations).toContain(f.chains.ab);
	});

	it("revokes chains where the agent is the target", async () => {
		const result = await f.theauth.agent.revoke(f.ids.b);
		expect(await statusOf(f.theauth, f.chains.ab)).toBe("revoked");
		expect(result.revokedDelegations).toContain(f.chains.ab);
	});

	it("revokes child chains transitively", async () => {
		const result = await f.theauth.agent.revoke(f.ids.a);
		expect(await statusOf(f.theauth, f.chains.bc)).toBe("revoked");
		expect([...result.revokedDelegations].sort()).toEqual([f.chains.ab, f.chains.bc].sort());
		expect(await f.theauth.delegation.getEffectivePermissions(f.ids.c)).toEqual([]);
	});

	it("leaves an unrelated agent's chains untouched", async () => {
		await f.theauth.agent.revoke(f.ids.a);
		expect(await statusOf(f.theauth, f.chains.xy)).toBe("active");
	});

	it("is idempotent: a second revoke revokes nothing and writes no row", async () => {
		await f.theauth.agent.revoke(f.ids.a);
		const again = await f.theauth.agent.revoke(f.ids.a);
		expect(again.revokedDelegations).toEqual([]);
		const rows = await f.theauth.db
			.select()
			.from(schema.auditLogs)
			.where(eq(schema.auditLogs.action, "agent.cascade.revoked"));
		expect(rows).toHaveLength(1);
	});

	it("writes a chained audit row listing the revoked chains", async () => {
		await f.theauth.agent.revoke(f.ids.a);
		const rows = await f.theauth.db
			.select()
			.from(schema.auditLogs)
			.where(eq(schema.auditLogs.action, "agent.cascade.revoked"));
		expect(rows).toHaveLength(1);
		const row = rows[0];
		expect(row?.agentId).toBe(f.ids.a);
		expect(row?.hash).toBeTruthy();
		expect([...(row?.delegationChain ?? [])].sort()).toEqual([f.chains.ab, f.chains.bc].sort());

		const verified = await verifyAuditChain(f.theauth.db, {}, KEY);
		expect(verified.success).toBe(true);
		if (verified.success) expect(verified.data.ok).toBe(true);
	});

	it("fires the onAgentRevoke hook", async () => {
		await f.theauth.agent.revoke(f.ids.a);
		expect(f.revokedHook).toContain(f.ids.a);
	});
});
