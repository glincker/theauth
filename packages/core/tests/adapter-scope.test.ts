import { describe, expect, it } from "vitest";
import { createAdapterGuard } from "../src/adapter-guard.js";
import type { AdapterScope } from "../src/adapter-scope.js";
import { users } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

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

async function seedUser(auth: TheAuth, id: string): Promise<void> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id, email: `${id || "empty"}@test.com`, name: id, createdAt: now, updatedAt: now })
		.onConflictDoNothing();
}

async function newAgent(auth: TheAuth, ownerId: string, name: string) {
	await seedUser(auth, ownerId);
	return auth.agent.create({
		ownerId,
		name,
		type: "autonomous",
		permissions: [{ resource: "docs", actions: ["read"] }],
	});
}

async function bearerFor(auth: TheAuth, userId: string): Promise<Request> {
	const sessions = auth.auth.session;
	if (!sessions) throw new Error("session manager missing");
	await seedUser(auth, userId);
	const { token } = await sessions.create(userId);
	return new Request("http://x/agents", { headers: { Authorization: `Bearer ${token}` } });
}

async function scopeFor(auth: TheAuth, userId: string): Promise<AdapterScope> {
	const guard = createAdapterGuard(auth, undefined, "testAdapter");
	const resolved = await guard.resolve(await bearerFor(auth, userId));
	if (!resolved.ok) throw new Error("expected a scope");
	return resolved.scope;
}

describe("default guard owner scope", () => {
	it("restricts a signed-in caller to their own id", async () => {
		const auth = await makeAuth();
		const scope = await scopeFor(auth, "u1");
		expect(scope.restricted).toBe(true);
		expect(scope.ownerId).toBe("u1");
		expect(scope.statsOwnerId()).toBe("u1");
	});

	it("still returns 401 without a session", async () => {
		const auth = await makeAuth();
		const guard = createAdapterGuard(auth, undefined, "testAdapter");
		const resolved = await guard.resolve(new Request("http://x/agents"));
		expect(resolved.ok).toBe(false);
		if (!resolved.ok) expect(resolved.response.status).toBe(401);
	});

	it("allows creating an agent for yourself and rejects another owner with 403", async () => {
		const scope = await scopeFor(await makeAuth(), "u1");
		expect(scope.checkAgentCreate("u1")).toBeNull();
		expect(scope.checkAgentCreate("u2")?.status).toBe(403);
	});

	it("allows own agents and reports foreign or unknown agents as not found", async () => {
		const auth = await makeAuth();
		const mine = await newAgent(auth, "u1", "mine");
		const theirs = await newAgent(auth, "u2", "theirs");
		const scope = await scopeFor(auth, "u1");
		expect(await scope.checkAgent(mine.id)).toBeNull();
		expect((await scope.checkAgent(theirs.id))?.status).toBe(404);
		expect((await scope.checkAgent("does-not-exist"))?.status).toBe(404);
	});

	it("scopes delegation chains to the owner of the from agent", async () => {
		const auth = await makeAuth();
		const mine = await newAgent(auth, "u1", "mine");
		const theirs = await newAgent(auth, "u2", "theirs");
		const chain = await auth.delegate({
			fromAgent: mine.id,
			toAgent: theirs.id,
			permissions: [{ resource: "docs", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60_000),
		});
		const owner = await scopeFor(auth, "u1");
		const other = await scopeFor(auth, "u2");
		expect(await owner.checkChain(chain.id)).toBeNull();
		expect((await other.checkChain(chain.id))?.status).toBe(404);
		expect((await owner.checkChain("nope"))?.status).toBe(404);
	});

	it("pins agent filters to the caller and rejects a foreign userId", async () => {
		const scope = await scopeFor(await makeAuth(), "u1");
		const pinned = scope.scopeAgentFilter({ status: "active" });
		expect(pinned).toEqual({ ok: true, value: { status: "active", userId: "u1" } });
		const own = scope.scopeAgentFilter({ userId: "u1" });
		expect(own.ok).toBe(true);
		const foreign = scope.scopeAgentFilter({ userId: "u2" });
		expect(foreign.ok).toBe(false);
		if (!foreign.ok) expect(foreign.denial.status).toBe(403);
	});

	it("pins audit filters and exports to the caller", async () => {
		const scope = await scopeFor(await makeAuth(), "u1");
		const filter = scope.scopeAuditFilter({ agentId: "a1", limit: 5 });
		expect(filter).toEqual({ ok: true, value: { agentId: "a1", limit: 5, userId: "u1" } });
		expect(scope.scopeAuditFilter({ userId: "u2" }).ok).toBe(false);
		const exp = scope.scopeAuditExport({ format: "json" });
		expect(exp).toEqual({ ok: true, value: { format: "json", userId: "u1" } });
		expect(scope.scopeAuditExport({ format: "csv", userId: "u2" }).ok).toBe(false);
	});

	it("exports only the caller's audit rows", async () => {
		const auth = await makeAuth();
		const mine = await newAgent(auth, "u1", "mine");
		const theirs = await newAgent(auth, "u2", "theirs");
		await auth.authorize(mine.id, { action: "read", resource: "docs" });
		await auth.authorize(theirs.id, { action: "read", resource: "docs" });
		const all = JSON.parse(await auth.audit.export({ format: "json" })) as { userId: string }[];
		expect(new Set(all.map((r) => r.userId))).toEqual(new Set(["u1", "u2"]));
		const scoped = JSON.parse(await auth.audit.export({ format: "json", userId: "u1" })) as {
			userId: string;
		}[];
		expect(scoped.length).toBe(1);
		expect(scoped[0]?.userId).toBe("u1");
	});

	it("rejects a principal with an empty id", async () => {
		const auth = await makeAuth();
		// A custom resolver is unrestricted, so exercise the default path through
		// a session whose user id is empty.
		const guard = createAdapterGuard(auth, undefined, "testAdapter");
		const resolved = await guard.resolve(await bearerFor(auth, ""));
		expect(resolved.ok).toBe(false);
	});
});

describe("explicit trust decisions stay unrestricted", () => {
	it("custom authenticate is unrestricted", async () => {
		const auth = await makeAuth();
		const guard = createAdapterGuard(auth, { authenticate: async () => ({ id: "svc" }) }, "t");
		const resolved = await guard.resolve(new Request("http://x/agents"));
		if (!resolved.ok) throw new Error("expected a scope");
		const scope = resolved.scope;
		expect(scope.restricted).toBe(false);
		expect(scope.checkAgentCreate("anyone")).toBeNull();
		expect(await scope.checkAgent("any-agent")).toBeNull();
		expect(await scope.checkChain("any-chain")).toBeNull();
		expect(scope.scopeAgentFilter({ userId: "u2" })).toEqual({ ok: true, value: { userId: "u2" } });
		expect(scope.scopeAuditFilter({})).toEqual({ ok: true, value: {} });
		expect(scope.statsOwnerId()).toBeUndefined();
	});

	it("custom authenticate still rejects anonymous callers", async () => {
		const auth = await makeAuth();
		const guard = createAdapterGuard(auth, { authenticate: async () => null }, "t");
		const resolved = await guard.resolve(new Request("http://x/agents"));
		expect(resolved.ok).toBe(false);
	});
});

describe("guard.clientIp", () => {
	const spoofed = () =>
		new Request("http://x/authorize", {
			headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.9", "x-real-ip": "5.6.7.8" },
		});

	it("ignores forwarded headers by default", async () => {
		const auth = await makeAuth();
		const guard = createAdapterGuard(auth, undefined, "t");
		expect(guard.clientIp(spoofed())).toBeNull();
	});

	it("counts back from the right with trustedProxyCount", async () => {
		const auth = await makeAuth();
		const guard = createAdapterGuard(auth, { trustedProxy: { trustedProxyCount: 1 } }, "t");
		expect(guard.clientIp(spoofed())).toBe("10.0.0.9");
	});

	it("reads one header with trustedHeader", async () => {
		const auth = await makeAuth();
		const guard = createAdapterGuard(auth, { trustedProxy: { trustedHeader: "x-real-ip" } }, "t");
		expect(guard.clientIp(spoofed())).toBe("5.6.7.8");
	});
});
