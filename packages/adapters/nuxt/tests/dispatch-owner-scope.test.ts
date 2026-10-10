import { describe, expect, it } from "vitest";
import type { AdapterSecurityOptions } from "../../../core/src/adapter-guard.js";
import { createAdapterGuard } from "../../../core/src/adapter-guard.js";
import { users } from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { dispatch } from "../src/dispatch.js";

// This file is shared by the nuxt, sveltekit and astro adapters, whose
// dispatch.ts files are byte identical.

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const READ_DOCS = [{ resource: "docs", actions: ["read"] }];
const BASE = "http://localhost/api/theauth";
const ALLOWED_IP = "203.0.113.5";

async function makeAuth(): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		auth: { session: { secret: SECRET } },
	});
}

async function seedUser(auth: TheAuth, id: string): Promise<string> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now })
		.onConflictDoNothing();
	const sessions = auth.auth.session;
	if (!sessions) throw new Error("session manager missing");
	const { token } = await sessions.create(id);
	return token;
}

type User = "u1" | "u2";

interface World {
	auth: TheAuth;
	a1: string;
	a2: string;
	chain: string;
	call: (
		options: AdapterSecurityOptions | undefined,
		user: User,
		method: string,
		path: string,
		body?: unknown,
	) => Promise<Response>;
}

/** u1 owns a1, u2 owns a2, and u1 delegated docs:read from a1 to a2. */
async function makeWorld(): Promise<World> {
	const auth = await makeAuth();
	const tokens = { u1: await seedUser(auth, "u1"), u2: await seedUser(auth, "u2") };
	const a1 = await auth.agent.create({
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		permissions: READ_DOCS,
	});
	const a2 = await auth.agent.create({
		ownerId: "u2",
		name: "a2",
		type: "autonomous",
		permissions: READ_DOCS,
	});
	const chain = await auth.delegate({
		fromAgent: a1.id,
		toAgent: a2.id,
		permissions: READ_DOCS,
		expiresAt: new Date(Date.now() + 3_600_000),
	});
	await auth.authorize(a1.id, { action: "read", resource: "docs" });
	await auth.authorize(a2.id, { action: "read", resource: "docs" });
	const call: World["call"] = (options, user, method, path, body) => {
		const guard = createAdapterGuard(auth, options, "test");
		const request = new Request(`${BASE}${path}`, {
			method,
			headers: { Authorization: `Bearer ${tokens[user]}`, "Content-Type": "application/json" },
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		});
		return dispatch(request, auth, undefined, "/api/theauth", guard);
	};
	return { auth, a1: a1.id, a2: a2.id, chain: chain.id, call };
}

async function dataOf<T>(res: Response): Promise<T> {
	return ((await res.json()) as { data: T }).data;
}

describe("dispatch owner scope with the default guard", () => {
	it("POST /agents accepts the caller as owner and rejects another owner", async () => {
		const w = await makeWorld();
		const body = { name: "n", type: "autonomous", permissions: READ_DOCS };
		const own = await w.call(undefined, "u1", "POST", "/agents", { ...body, ownerId: "u1" });
		expect(own.status).toBe(201);
		const other = await w.call(undefined, "u1", "POST", "/agents", { ...body, ownerId: "u2" });
		expect(other.status).toBe(403);
		expect((await w.auth.agent.list({ userId: "u2" })).length).toBe(1);
	});

	it("GET /agents lists only the caller's agents and rejects a foreign userId", async () => {
		const w = await makeWorld();
		const list = await dataOf<{ id: string }[]>(await w.call(undefined, "u1", "GET", "/agents"));
		expect(list.map((a) => a.id)).toEqual([w.a1]);
		expect((await w.call(undefined, "u1", "GET", "/agents?userId=u2")).status).toBe(403);
		expect((await w.call(undefined, "u1", "GET", "/agents?userId=u1")).status).toBe(200);
	});

	it("agent id routes allow own agents and deny another user's agent", async () => {
		const w = await makeWorld();
		const c = (m: string, p: string, b?: unknown) => w.call(undefined, "u1", m, p, b);
		expect((await c("GET", `/agents/${w.a1}`)).status).toBe(200);
		expect((await c("GET", `/agents/${w.a2}`)).status).toBe(404);
		expect((await c("GET", "/agents/missing")).status).toBe(404);
		expect((await c("PATCH", `/agents/${w.a1}`, { name: "x" })).status).toBe(200);
		expect((await c("PATCH", `/agents/${w.a2}`, { name: "x" })).status).toBe(404);
		expect((await c("POST", `/agents/${w.a1}/rotate`)).status).toBe(200);
		expect((await c("POST", `/agents/${w.a2}/rotate`)).status).toBe(404);
		expect((await c("DELETE", `/agents/${w.a2}`)).status).toBe(404);
		expect((await w.auth.agent.get(w.a2))?.status).toBe("active");
		expect((await w.auth.agent.get(w.a2))?.name).toBe("a2");
		expect((await c("DELETE", `/agents/${w.a1}`)).status).toBe(204);
	});

	it("POST /authorize only works for the caller's own agents", async () => {
		const w = await makeWorld();
		const body = { action: "read", resource: "docs" };
		const own = await w.call(undefined, "u1", "POST", "/authorize", { agentId: w.a1, ...body });
		expect(own.status).toBe(200);
		const other = await w.call(undefined, "u1", "POST", "/authorize", { agentId: w.a2, ...body });
		expect(other.status).toBe(404);
	});

	it("delegation routes are keyed to the owner of the from agent", async () => {
		const w = await makeWorld();
		const body = { permissions: READ_DOCS, expiresAt: new Date(Date.now() + 60_000) };
		const bad = await w.call(undefined, "u1", "POST", "/delegations", {
			fromAgent: w.a2,
			toAgent: w.a1,
			...body,
		});
		expect(bad.status).toBe(404);
		const good = await w.call(undefined, "u1", "POST", "/delegations", {
			fromAgent: w.a1,
			toAgent: w.a2,
			...body,
		});
		expect(good.status).toBe(201);

		expect((await w.call(undefined, "u1", "GET", `/delegations/${w.a1}`)).status).toBe(200);
		expect((await w.call(undefined, "u1", "GET", `/delegations/${w.a2}`)).status).toBe(404);

		expect((await w.call(undefined, "u2", "DELETE", `/delegations/${w.chain}`)).status).toBe(404);
		expect((await w.auth.delegation.listChains(w.a1)).length).toBeGreaterThan(0);
		expect((await w.call(undefined, "u1", "DELETE", `/delegations/${w.chain}`)).status).toBe(204);
	});

	it("audit routes only return the caller's rows", async () => {
		const w = await makeWorld();
		for (const path of ["/audit", "/dashboard/audit"]) {
			const rows = await dataOf<{ userId: string }[]>(await w.call(undefined, "u1", "GET", path));
			expect(rows.length, path).toBeGreaterThan(0);
			expect(
				rows.every((r) => r.userId === "u1"),
				path,
			).toBe(true);
			expect((await w.call(undefined, "u1", "GET", `${path}?userId=u2`)).status, path).toBe(403);
		}
		const spoofAgent = await w.call(undefined, "u1", "GET", `/audit?agentId=${w.a2}`);
		expect(await dataOf<unknown[]>(spoofAgent)).toEqual([]);

		const exported = await w.call(undefined, "u1", "GET", "/audit/export?format=json");
		const rows = JSON.parse(await exported.text()) as { userId: string }[];
		expect(rows.length).toBeGreaterThan(0);
		expect(rows.every((r) => r.userId === "u1")).toBe(true);
	});

	it("dashboard routes are limited to the caller's own data", async () => {
		const w = await makeWorld();
		const stats = await dataOf<{ agents: { total: number }; users: { total: number } }>(
			await w.call(undefined, "u1", "GET", "/dashboard/stats"),
		);
		expect(stats.agents.total).toBe(1);
		expect(stats.users.total).toBe(1);
		const agents = await dataOf<{ id: string }[]>(
			await w.call(undefined, "u1", "GET", "/dashboard/agents"),
		);
		expect(agents.map((a) => a.id)).toEqual([w.a1]);
		expect((await w.call(undefined, "u1", "GET", "/dashboard/agents?userId=u2")).status).toBe(403);
	});

	it("still rejects anonymous callers", async () => {
		const w = await makeWorld();
		const guard = createAdapterGuard(w.auth, undefined, "test");
		const res = await dispatch(
			new Request(`${BASE}/agents`),
			w.auth,
			undefined,
			"/api/theauth",
			guard,
		);
		expect(res.status).toBe(401);
	});
});

describe("dispatch with a custom authenticate resolver", () => {
	const authenticate = async (req: Request) =>
		req.headers.get("x-api-user") === "admin" ? { id: "admin" } : null;
	const admin = { "x-api-user": "admin", "Content-Type": "application/json" };

	it("keeps treating the resolver's principal as authorized for every route", async () => {
		const w = await makeWorld();
		const guard = createAdapterGuard(w.auth, { authenticate }, "test");
		const run = (path: string, init: RequestInit = {}) =>
			dispatch(
				new Request(`${BASE}${path}`, { headers: admin, ...init }),
				w.auth,
				undefined,
				"/api/theauth",
				guard,
			);

		const created = await run("/agents", {
			method: "POST",
			body: JSON.stringify({ ownerId: "u2", name: "svc", type: "service", permissions: READ_DOCS }),
		});
		expect(created.status).toBe(201);
		expect((await dataOf<unknown[]>(await run("/agents"))).length).toBe(3);
		expect((await run(`/agents/${w.a2}`)).status).toBe(200);
		expect((await run(`/delegations/${w.a2}`)).status).toBe(200);
		expect((await run("/agents?userId=u2")).status).toBe(200);
		const stats = await dataOf<{ users: { total: number } }>(await run("/dashboard/stats"));
		expect(stats.users.total).toBe(2);
		const audit = await dataOf<{ userId: string }[]>(await run("/audit"));
		expect(new Set(audit.map((r) => r.userId))).toEqual(new Set(["u1", "u2"]));
		expect((await run(`/delegations/${w.chain}`, { method: "DELETE" })).status).toBe(204);
	});
});

describe("dispatch client ip", () => {
	async function setup(options: Partial<AdapterSecurityOptions> = {}) {
		const auth = await makeAuth();
		const now = new Date();
		await auth.db
			.insert(users)
			.values({ id: "owner", email: "o@test.com", name: "o", createdAt: now, updatedAt: now });
		const agent = await auth.agent.create({
			ownerId: "owner",
			name: "ip-bound",
			type: "autonomous",
			permissions: [
				{ resource: "docs", actions: ["read"], constraints: { ipAllowlist: [ALLOWED_IP] } },
			],
		});
		const guard = createAdapterGuard(
			auth,
			{ authenticate: async () => ({ id: "admin" }), ...options },
			"test",
		);
		const send = async (path: string, headers: Record<string, string>, body: unknown) => {
			const res = await dispatch(
				new Request(`${BASE}${path}`, {
					method: "POST",
					headers: { "Content-Type": "application/json", ...headers },
					body: JSON.stringify(body),
				}),
				auth,
				undefined,
				"/api/theauth",
				guard,
			);
			return res.status;
		};
		const viaToken = (headers: Record<string, string>) =>
			send(
				"/authorize/token",
				{ Authorization: `Bearer ${agent.token}`, ...headers },
				{ action: "read", resource: "docs" },
			);
		const viaAgentId = (headers: Record<string, string>) =>
			send("/authorize", headers, { agentId: agent.id, action: "read", resource: "docs" });
		return { viaToken, viaAgentId };
	}

	it("denies an ipAllowlist agent when forwarded headers are spoofed (default)", async () => {
		const { viaToken, viaAgentId } = await setup();
		const spoof = { "x-forwarded-for": ALLOWED_IP, "x-real-ip": ALLOWED_IP };
		expect(await viaToken(spoof)).toBe(403);
		expect(await viaAgentId(spoof)).toBe(403);
	});

	it("honors the right-most entry with trustedProxyCount and ignores a spoofed first entry", async () => {
		const { viaToken, viaAgentId } = await setup({ trustedProxy: { trustedProxyCount: 1 } });
		expect(await viaToken({ "x-forwarded-for": `9.9.9.9, ${ALLOWED_IP}` })).toBe(200);
		expect(await viaAgentId({ "x-forwarded-for": `9.9.9.9, ${ALLOWED_IP}` })).toBe(200);
		expect(await viaToken({ "x-forwarded-for": `${ALLOWED_IP}, 9.9.9.9` })).toBe(403);
	});

	it("honors a single trustedHeader and ignores x-forwarded-for", async () => {
		const { viaToken } = await setup({ trustedProxy: { trustedHeader: "cf-connecting-ip" } });
		expect(await viaToken({ "cf-connecting-ip": ALLOWED_IP })).toBe(200);
		expect(await viaToken({ "cf-connecting-ip": "9.9.9.9", "x-forwarded-for": ALLOWED_IP })).toBe(
			403,
		);
	});
});
