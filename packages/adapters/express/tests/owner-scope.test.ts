import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import type { TheAuthExpressOptions } from "../src/adapter.js";
import { theAuthExpress } from "../src/adapter.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const READ_DOCS = [{ resource: "docs", actions: ["read"] }];
const BASE = "/api/auth/theauth";
const ALLOWED_IP = "203.0.113.5";

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

async function makeWorld(options?: TheAuthExpressOptions) {
	const auth = await createTheAuth({
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
	const t1 = await seedUser(auth, "u1");
	await seedUser(auth, "u2");
	const a1 = await auth.agent.create({
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		permissions: [
			{ resource: "docs", actions: ["read"], constraints: { ipAllowlist: [ALLOWED_IP] } },
		],
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
	await auth.authorize(a2.id, { action: "read", resource: "docs" });
	const app = express();
	app.use(express.json());
	app.use(BASE, theAuthExpress(auth, options));
	return { auth, app, bearer: `Bearer ${t1}`, a1, a2, chain: chain.id };
}

describe("express adapter owner scope with the default guard", () => {
	it("POST /agents rejects another owner and accepts the caller", async () => {
		const w = await makeWorld();
		const body = { name: "n", type: "autonomous", permissions: READ_DOCS };
		const bad = await request(w.app)
			.post(`${BASE}/agents`)
			.set("Authorization", w.bearer)
			.send({ ...body, ownerId: "u2" });
		expect(bad.status).toBe(403);
		const good = await request(w.app)
			.post(`${BASE}/agents`)
			.set("Authorization", w.bearer)
			.send({ ...body, ownerId: "u1" });
		expect(good.status).toBe(201);
	});

	it("lists, reads and mutates only the caller's agents", async () => {
		const w = await makeWorld();
		const get = (path: string) =>
			request(w.app).get(`${BASE}${path}`).set("Authorization", w.bearer);
		const list = await get("/agents");
		expect(list.body.data.map((a: { id: string }) => a.id)).toEqual([w.a1.id]);
		expect((await get("/agents?userId=u2")).status).toBe(403);
		expect((await get(`/agents/${w.a1.id}`)).status).toBe(200);
		expect((await get(`/agents/${w.a2.id}`)).status).toBe(404);
		const patch = await request(w.app)
			.patch(`${BASE}/agents/${w.a2.id}`)
			.set("Authorization", w.bearer)
			.send({ name: "x" });
		expect(patch.status).toBe(404);
		const del = await request(w.app)
			.delete(`${BASE}/agents/${w.a2.id}`)
			.set("Authorization", w.bearer);
		expect(del.status).toBe(404);
		expect((await w.auth.agent.get(w.a2.id))?.status).toBe("active");
		const rotate = await request(w.app)
			.post(`${BASE}/agents/${w.a2.id}/rotate`)
			.set("Authorization", w.bearer);
		expect(rotate.status).toBe(404);
	});

	it("scopes authorize, delegations, audit and dashboard to the caller", async () => {
		const w = await makeWorld();
		const post = (path: string, body: unknown) =>
			request(w.app)
				.post(`${BASE}${path}`)
				.set("Authorization", w.bearer)
				.send(body as object);
		const get = (path: string) =>
			request(w.app).get(`${BASE}${path}`).set("Authorization", w.bearer);

		expect(
			(await post("/authorize", { agentId: w.a2.id, action: "read", resource: "docs" })).status,
		).toBe(404);
		const delegate = { permissions: READ_DOCS, expiresAt: new Date(Date.now() + 60_000) };
		expect(
			(await post("/delegations", { fromAgent: w.a2.id, toAgent: w.a1.id, ...delegate })).status,
		).toBe(404);
		expect((await get(`/delegations/${w.a2.id}`)).status).toBe(404);
		expect((await get(`/delegations/${w.a1.id}`)).status).toBe(200);

		const audit = await get("/audit");
		expect(audit.body.data).toEqual([]);
		expect((await get("/audit?userId=u2")).status).toBe(403);
		expect((await get("/dashboard/audit?userId=u2")).status).toBe(403);
		const exported = await get("/audit/export?format=json");
		expect(JSON.parse(exported.text)).toEqual([]);

		const stats = await get("/dashboard/stats");
		expect(stats.body.data.agents.total).toBe(1);
		expect(stats.body.data.users.total).toBe(1);
		expect((await get("/dashboard/agents?userId=u2")).status).toBe(403);
	});

	it("revokes only chains the caller owns", async () => {
		const w = await makeWorld();
		const t2 = await seedUser(w.auth, "u2");
		const other = await request(w.app)
			.delete(`${BASE}/delegations/${w.chain}`)
			.set("Authorization", `Bearer ${t2}`);
		expect(other.status).toBe(404);
		const own = await request(w.app)
			.delete(`${BASE}/delegations/${w.chain}`)
			.set("Authorization", w.bearer);
		expect(own.status).toBe(204);
	});
});

describe("express adapter with a custom authenticate resolver", () => {
	it("is unchanged: the principal may act on any owner", async () => {
		const w = await makeWorld({ authenticate: async () => ({ id: "admin" }) });
		const created = await request(w.app)
			.post(`${BASE}/agents`)
			.send({ ownerId: "u2", name: "svc", type: "service", permissions: READ_DOCS });
		expect(created.status).toBe(201);
		const list = await request(w.app).get(`${BASE}/agents`);
		expect(list.body.data.length).toBe(3);
		expect((await request(w.app).get(`${BASE}/agents/${w.a2.id}`)).status).toBe(200);
	});
});

describe("express adapter client ip", () => {
	const authorize = (w: Awaited<ReturnType<typeof makeWorld>>, headers: Record<string, string>) =>
		request(w.app)
			.post(`${BASE}/authorize/token`)
			.set("Authorization", `Bearer ${w.a1.token}`)
			.set(headers)
			.send({ action: "read", resource: "docs" });

	it("ignores spoofed forwarded headers by default", async () => {
		const w = await makeWorld();
		const res = await authorize(w, { "x-forwarded-for": ALLOWED_IP, "x-real-ip": ALLOWED_IP });
		expect(res.status).toBe(403);
	});

	it("honors trustedProxyCount from the right and trustedHeader", async () => {
		const counted = await makeWorld({ trustedProxy: { trustedProxyCount: 1 } });
		expect((await authorize(counted, { "x-forwarded-for": `9.9.9.9, ${ALLOWED_IP}` })).status).toBe(
			200,
		);
		expect((await authorize(counted, { "x-forwarded-for": `${ALLOWED_IP}, 9.9.9.9` })).status).toBe(
			403,
		);
		const header = await makeWorld({ trustedProxy: { trustedHeader: "cf-connecting-ip" } });
		expect((await authorize(header, { "cf-connecting-ip": ALLOWED_IP })).status).toBe(200);
	});
});
