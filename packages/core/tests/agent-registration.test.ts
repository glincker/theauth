import { eq } from "drizzle-orm";
import { describe, expect, it, vi } from "vitest";
import type { AgentRegistrationEvent } from "../src/auth/agent-registration.js";
import { createAgentRegistrationModule } from "../src/auth/agent-registration.js";
import { agentRegistration } from "../src/auth/agent-registration-plugin.js";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";
import type { Permission } from "../src/types.js";

const PERMS: Permission[] = [{ resource: "mcp:github:*", actions: ["read"] }];
const SECRET = "y".repeat(40);

async function setup(opts: { maxPerUser?: number } = {}) {
	const events: AgentRegistrationEvent[] = [];
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: opts.maxPerUser ?? 10 },
	});
	for (const id of ["u1", "u2"]) {
		auth.db
			.insert(schema.users)
			.values({ id, email: `${id}@x.io`, name: id, createdAt: new Date(), updatedAt: new Date() })
			.run();
	}
	const mod = createAgentRegistrationModule({
		db: auth.db,
		agents: auth.agent,
		onEvent: (e) => void events.push(e),
	});
	return { auth, mod, events };
}

describe("agent registration tokens", () => {
	it("mints a token, stores only its hash, and redeems it into an agent", async () => {
		const { auth, mod, events } = await setup();
		const made = await mod.create({
			ownerId: "u1",
			permissions: PERMS,
			label: "ci",
			createdBy: "admin",
		});
		if (!made.success) throw new Error("create failed");
		const rows = await auth.db.select().from(schema.agentRegistrationTokens);
		expect(JSON.stringify(rows)).not.toContain(made.data.token);

		const res = await mod.redeem(made.data.token, { name: "ci-bot" });
		if (!res.success) throw new Error(res.error.message);
		expect(res.data.ownerId).toBe("u1");
		expect(res.data.permissions).toEqual(PERMS);
		expect(res.data.token.startsWith("kv_")).toBe(true);

		const audit = await auth.db
			.select()
			.from(schema.auditLogs)
			.where(eq(schema.auditLogs.agentId, res.data.id));
		expect(audit[0]?.resource).toContain(made.data.id);
		expect(events.map((e) => e.type)).toEqual([
			"agent_registration.token_created",
			"agent_registration.redeemed",
		]);
	});

	it("is single use, including under concurrent redemption", async () => {
		const { mod } = await setup();
		const made = await mod.create({ ownerId: "u1", permissions: PERMS });
		if (!made.success) throw new Error("x");
		const results = await Promise.all(
			[1, 2, 3, 4].map((i) => mod.redeem(made.data.token, { name: `bot-${i}` })),
		);
		expect(results.filter((r) => r.success)).toHaveLength(1);
		const again = await mod.redeem(made.data.token, { name: "late" });
		expect(again).toMatchObject({ success: false, error: { code: "INVALID_TOKEN" } });
	});

	it("rejects expired, revoked and unknown tokens with one error code", async () => {
		const { mod } = await setup();
		vi.useFakeTimers();
		const exp = await mod.create({ ownerId: "u1", permissions: PERMS, expiresInSeconds: 5 });
		const rev = await mod.create({ ownerId: "u1", permissions: PERMS });
		if (!exp.success || !rev.success) throw new Error("x");
		await mod.revoke(rev.data.id, "admin");
		vi.advanceTimersByTime(6_000);
		for (const t of [exp.data.token, rev.data.token, "kvr_nope", "garbage"]) {
			expect(await mod.redeem(t, { name: "a" })).toMatchObject({
				success: false,
				error: { code: "INVALID_TOKEN" },
			});
		}
		vi.useRealTimers();
	});

	it("enforces name prefix and cannot widen permissions or owner", async () => {
		const { mod } = await setup();
		const made = await mod.create({ ownerId: "u1", permissions: PERMS, namePrefix: "ci-" });
		if (!made.success) throw new Error("x");
		expect(await mod.redeem(made.data.token, { name: "other" })).toMatchObject({
			success: false,
			error: { code: "INVALID_NAME" },
		});
		// a bad name does not burn the token
		const ok = await mod.redeem(made.data.token, { name: "ci-1" });
		expect(ok.success).toBe(true);
	});

	it("gives the token back when agent creation fails", async () => {
		const { mod, auth } = await setup({ maxPerUser: 1 });
		await auth.agent.create({
			ownerId: "u1",
			name: "existing",
			type: "autonomous",
			permissions: [],
		});
		const made = await mod.create({ ownerId: "u1", permissions: PERMS });
		if (!made.success) throw new Error("x");
		expect(await mod.redeem(made.data.token, { name: "b" })).toMatchObject({
			success: false,
			error: { code: "AGENT_CREATE_FAILED" },
		});
		expect((await mod.list({ status: "active" })).map((t) => t.id)).toContain(made.data.id);
	});

	it("validates create input and lists by status", async () => {
		const { mod } = await setup();
		expect(await mod.create({ ownerId: "u1", permissions: [] })).toMatchObject({ success: false });
		expect(
			await mod.create({ ownerId: "u1", permissions: PERMS, expiresInSeconds: 10 ** 9 }),
		).toMatchObject({ success: false });
		const a = await mod.create({ ownerId: "u1", permissions: PERMS });
		await mod.create({ ownerId: "u2", permissions: PERMS });
		if (!a.success) throw new Error("x");
		await mod.revoke(a.data.id);
		expect((await mod.list({ ownerId: "u1" }))[0]?.status).toBe("revoked");
		expect(await mod.list({ status: "active" })).toHaveLength(1);
	});
});

describe("agentRegistration plugin", () => {
	async function plugin() {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true },
			auth: { session: { secret: SECRET } },
			plugins: [agentRegistration({ isAdmin: (u) => u.id === "admin" })],
		});
		for (const id of ["admin", "u1", "u2"]) {
			auth.db
				.insert(schema.users)
				.values({ id, email: `${id}@x.io`, name: id, createdAt: new Date(), updatedAt: new Date() })
				.run();
		}
		const bearer = async (id: string) => ({
			authorization: `Bearer ${(await auth.auth.session!.create(id)).token}`,
		});
		const call = (method: string, path: string, headers: Record<string, string>, body?: unknown) =>
			auth.plugins.handleRequest(
				new Request(`http://x${path}`, {
					method,
					headers: { "content-type": "application/json", ...headers },
					body: body ? JSON.stringify(body) : undefined,
				}),
			);
		return { auth, bearer, call };
	}

	it("full flow: user mints, agent registers without a session", async () => {
		const { bearer, call } = await plugin();
		const mint = await call("POST", "/auth/agent-registration/tokens", await bearer("u1"), {
			permissions: PERMS,
			label: "x",
		});
		expect(mint?.status).toBe(201);
		const { token, id } = (await mint!.json()) as { token: string; id: string };

		const reg = await call(
			"POST",
			"/auth/agent-registration/register",
			{ authorization: `Bearer ${token}` },
			{ name: "bot" },
		);
		expect(reg?.status).toBe(201);
		expect(((await reg!.json()) as { token: string }).token).toMatch(/^kv_/);

		const replay = await call(
			"POST",
			"/auth/agent-registration/register",
			{ authorization: `Bearer ${token}` },
			{ name: "bot2" },
		);
		expect(replay?.status).toBe(401);

		const list = await call("GET", "/auth/agent-registration/tokens", await bearer("u1"));
		expect(
			((await list!.json()) as { tokens: Array<{ id: string; status: string }> }).tokens[0],
		).toMatchObject({ id, status: "used" });
	});

	it("requires a session to mint, and non-admins cannot mint, list or revoke for others", async () => {
		const { bearer, call } = await plugin();
		expect(
			(await call("POST", "/auth/agent-registration/tokens", {}, { permissions: PERMS }))?.status,
		).toBe(401);
		const forOther = await call("POST", "/auth/agent-registration/tokens", await bearer("u1"), {
			owner_id: "u2",
			permissions: PERMS,
		});
		expect(forOther?.status).toBe(403);
		const adminMint = await call("POST", "/auth/agent-registration/tokens", await bearer("admin"), {
			owner_id: "u2",
			permissions: PERMS,
		});
		expect(adminMint?.status).toBe(201);
		const { id } = (await adminMint!.json()) as { id: string };
		const u1List = await call("GET", "/auth/agent-registration/tokens", await bearer("u1"));
		expect(((await u1List!.json()) as { tokens: unknown[] }).tokens).toHaveLength(0);
		expect(
			(await call("DELETE", `/auth/agent-registration/tokens/${id}`, await bearer("u1")))?.status,
		).toBe(404);
		expect(
			(await call("DELETE", `/auth/agent-registration/tokens/${id}`, await bearer("admin")))
				?.status,
		).toBe(200);
	});
});
