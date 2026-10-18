/** Banning, deleting, erasing or deprovisioning a user pushes `sub` and `agent` revocations, so MCP tokens die everywhere. */

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAdminModule } from "../src/auth/admin.js";
import { createGdprModule } from "../src/auth/gdpr.js";
import { createScimModule } from "../src/auth/scim.js";
import { createTables } from "../src/db/migrations.js";
import { agents, mcpRevocations, users } from "../src/db/schema.js";
import type { McpAuthModule } from "../src/mcp/types.js";
import { bootDb, finishBoot } from "./mcp-db-harness.js";
import { basicAuth, codeFlow, REDIRECT, RESOURCE, tokenRequest } from "./mcp-test-harness.js";

const SECRET = "plain-secret";
const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];

// The default skew allowance also kills tokens issued shortly after a revoke; these tests wait past the second instead.
const SKEW_ENV = "THEAUTH_MCP_REVOCATION_SKEW_MS";
let savedSkew: string | undefined;
beforeAll(() => {
	savedSkew = process.env[SKEW_ENV];
	process.env[SKEW_ENV] = "0";
});
afterAll(() => {
	if (savedSkew === undefined) delete process.env[SKEW_ENV];
	else process.env[SKEW_ENV] = savedSkew;
});

async function world() {
	const base = await bootDb();
	const agent = await base.auth.agent.create({
		ownerId: base.userId,
		name: "owned",
		type: "autonomous",
		permissions: PERMS,
	});
	const d = finishBoot(base.auth, base.userId, {
		preRegisteredClients: [
			{
				clientId: "plain",
				clientSecret: SECRET,
				redirectUris: [REDIRECT],
				scope: "mcp:read offline_access",
				grantTypes: ["authorization_code", "refresh_token"],
			},
		],
	});
	await new Promise((r) => setTimeout(r, 20));
	await createTables(base.auth.db, "sqlite");
	return { d, owner: base.userId, agentId: agent.id, auth: base.auth };
}

async function call(mcp: McpAuthModule, token: string): Promise<number> {
	const guarded = mcp.requireMcpAuth(async () => new Response("ok"));
	return (
		await guarded(
			new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } }),
		)
	).status;
}

async function rows(w: Awaited<ReturnType<typeof world>>, kind: "sub" | "agent") {
	const all = await w.auth.db.select().from(mcpRevocations);
	return all.filter((r) => r.kind === kind);
}

async function issue(w: Awaited<ReturnType<typeof world>>) {
	return codeFlow(
		{ mcp: w.d.mcp, clients: new Map(), codes: new Map(), tokens: new Map() },
		"plain",
		{ secret: SECRET, scope: "mcp:read offline_access" },
	);
}

describe("admin.banUser revokes MCP access", () => {
	it("kills the unbound access token and the refresh token, and pushes sub and agent rows", async () => {
		const w = await world();
		const admin = createAdminModule(
			{ adminUserIds: ["root"] },
			w.auth.db,
			null,
			w.auth.revocations,
		);
		const first = await issue(w);
		expect(await call(w.d.mcp, first.access_token)).toBe(200);

		await admin.banUser(w.owner, "compromised");

		expect(await call(w.d.mcp, first.access_token)).toBe(401);
		expect((await rows(w, "sub")).map((r) => r.id)).toEqual([w.owner]);
		expect((await rows(w, "sub"))[0]?.reason).toBe("admin.banUser");
		expect((await rows(w, "agent")).map((r) => r.id)).toEqual([w.agentId]);

		await new Promise((r) => setTimeout(r, 1100));
		const next = await w.d.mcp.token(
			tokenRequest(
				{
					grant_type: "refresh_token",
					refresh_token: first.refresh_token as string,
					client_id: "plain",
				},
				basicAuth("plain", SECRET),
			),
		);
		if (next.success) expect(await call(w.d.mcp, next.data.access_token)).toBe(401);
		else expect(next.success).toBe(false);
	});

	it("marks the owner's agents revoked so delegation chains rooted at the user stop validating", async () => {
		const w = await world();
		const admin = createAdminModule({}, w.auth.db, null, w.auth.revocations);
		await admin.banUser(w.owner);
		const [row] = await w.auth.db.select().from(agents).where(eq(agents.id, w.agentId));
		expect(row?.status).toBe("revoked");
	});

	it("unban does not resurrect tokens issued before the ban or the revoked agents", async () => {
		const w = await world();
		const admin = createAdminModule({}, w.auth.db, null, w.auth.revocations);
		const first = await issue(w);
		await admin.banUser(w.owner);
		await admin.unbanUser(w.owner);
		expect(await call(w.d.mcp, first.access_token)).toBe(401);
		expect((await rows(w, "sub")).length).toBe(1);
		const [row] = await w.auth.db.select().from(agents).where(eq(agents.id, w.agentId));
		expect(row?.status).toBe("revoked");
		// A token issued after the unban is not caught by the old watermark.
		await new Promise((r) => setTimeout(r, 1100));
		const fresh = await issue(w);
		expect(await call(w.d.mcp, fresh.access_token)).toBe(200);
	});

	it("is wired through createTheAuth (auth.admin pushes to the instance bus)", async () => {
		const { createTheAuth } = await import("../src/theauth.js");
		const { mcpConfig } = await import("./mcp-db-harness.js");
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 5, auditAll: true, tokenExpiry: "24h" },
			mcp: mcpConfig(),
			admin: { adminUserIds: ["root"] },
		});
		await createTables(auth.db, "sqlite");
		const user = await auth.user.create({ email: "wired@example.com" });
		await auth.admin?.banUser(user.id);
		const all = await auth.db.select().from(mcpRevocations);
		expect(all.some((r) => r.kind === "sub" && r.id === user.id)).toBe(true);
	});
});

describe("other user-ending flows push the same revocations", () => {
	it("admin.deleteUser", async () => {
		const w = await world();
		const admin = createAdminModule({}, w.auth.db, null, w.auth.revocations);
		const first = await issue(w);
		// The user row delete can hit a foreign key (pre-existing: agent rows keep pointing at the owner).
		// The revocation is pushed before it, which is what this test pins.
		await admin.deleteUser(w.owner).catch(() => undefined);
		expect((await rows(w, "sub")).map((r) => r.id)).toEqual([w.owner]);
		expect((await rows(w, "sub"))[0]?.reason).toBe("admin.deleteUser");
		expect((await rows(w, "agent")).map((r) => r.id)).toEqual([w.agentId]);
		expect(await call(w.d.mcp, first.access_token)).toBe(401);
	});

	it("gdpr.deleteUser (erasure)", async () => {
		const w = await world();
		const gdpr = createGdprModule(w.auth.db, w.auth.revocations);
		await gdpr.deleteUser(w.owner);
		expect((await rows(w, "sub")).map((r) => r.id)).toEqual([w.owner]);
		expect((await rows(w, "sub"))[0]?.reason).toBe("gdpr.deleteUser");
		expect((await rows(w, "agent")).map((r) => r.id)).toEqual([w.agentId]);
	});

	it("scim deprovision (DELETE) and deactivate (PATCH active=false)", async () => {
		const w = await world();
		const scim = createScimModule({ bearerToken: "tok" }, w.auth.db, w.auth.revocations);
		const hdr = { Authorization: "Bearer tok", "Content-Type": "application/scim+json" };
		const patch = await scim.handleRequest(
			new Request(`https://x.test/scim/v2/Users/${w.owner}`, {
				method: "PATCH",
				headers: hdr,
				body: JSON.stringify({
					schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
					Operations: [{ op: "replace", path: "active", value: false }],
				}),
			}),
		);
		expect(patch?.status).toBe(200);
		expect((await rows(w, "sub"))[0]?.reason).toBe("scim.deactivate");
		expect((await rows(w, "agent")).map((r) => r.id)).toEqual([w.agentId]);

		const w2 = await world();
		const scim2 = createScimModule({ bearerToken: "tok" }, w2.auth.db, w2.auth.revocations);
		const del = await scim2.handleRequest(
			new Request(`https://x.test/scim/v2/Users/${w2.owner}`, { method: "DELETE", headers: hdr }),
		);
		expect(del?.status).toBe(204);
		expect((await rows(w2, "sub"))[0]?.reason).toBe("scim.deprovision");
		const [u] = await w2.auth.db.select().from(users).where(eq(users.id, w2.owner));
		expect(u?.banned).toBe(1);
	});
});
