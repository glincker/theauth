/**
 * Regression for the HTTP review: PATCH /agents/:id must run the beforeAgentCreate policy on
 * the resulting agent, and POST /delegations must be owner scoped on both ends.
 */

import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { createTheAuth } from "../../src/theauth.js";
import type { Permission } from "../../src/types.js";
import { BASE, makeAuth, newAgent, SESSION_SECRET, seedUser, sessionToken } from "./helpers.js";

const noWildcards = async (input: { permissions: Permission[] }) =>
	input.permissions.some((p) => p.resource === "*" || p.actions.includes("*"))
		? { allow: false, reason: "wildcards are admin only" }
		: undefined;

async function policyAuth(hook: typeof noWildcards) {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		auth: { session: { secret: SESSION_SECRET } },
		hooks: { beforeAgentCreate: hook },
	});
	const token = await sessionToken(auth, "u1");
	const handler = createTheAuthHandler(auth, { rateLimit: false });
	const call = (method: string, path: string, body?: unknown) =>
		handler(
			new Request(`${BASE}${path}`, {
				method,
				headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
				body: body === undefined ? undefined : JSON.stringify(body),
			}),
		);
	return { auth, call };
}

describe("PATCH /agents/:id runs the agent policy", () => {
	it("refuses widening a compliant agent to '*' and leaves its grants unchanged", async () => {
		const { auth, call } = await policyAuth(noWildcards);
		const createdRes = await call("POST", "/agents", {
			ownerId: "u1",
			name: "x",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		expect(createdRes.status).toBe(201);
		const agent = ((await createdRes.json()) as { data: { id: string; token: string } }).data;

		const patched = await call("PATCH", `/agents/${agent.id}`, {
			permissions: [{ resource: "*", actions: ["*"] }],
		});
		expect(patched.status).toBe(403);

		const decision = await auth.authorizeByToken(agent.token, {
			action: "delete",
			resource: "billing",
		});
		expect(decision.allowed).toBe(false);
		const stored = await auth.agent.get(agent.id);
		expect(stored?.permissions.map((p) => p.resource)).toEqual(["docs"]);
	});

	it("still allows a compliant update", async () => {
		const { call } = await policyAuth(noWildcards);
		const res = await call("POST", "/agents", {
			ownerId: "u1",
			name: "x",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		const agent = ((await res.json()) as { data: { id: string } }).data;
		const patched = await call("PATCH", `/agents/${agent.id}`, {
			permissions: [{ resource: "docs", actions: ["read", "write"] }],
		});
		expect(patched.status).toBe(200);
	});

	it("fails closed when the policy hook throws on update", async () => {
		let calls = 0;
		const { auth } = await policyAuth(async () => {
			calls++;
			if (calls > 1) throw new Error("policy backend down");
			return undefined;
		});
		await seedUser(auth, "u1");
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "x",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		await expect(
			auth.agent.update(agent.id, { permissions: [{ resource: "*", actions: ["*"] }] }),
		).rejects.toThrow();
		expect((await auth.agent.get(agent.id))?.permissions[0]?.resource).toBe("docs");
	});

	it("covers direct calls to auth.agent.update, not only the HTTP route", async () => {
		const { auth } = await policyAuth(noWildcards);
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "x",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		await expect(
			auth.agent.update(agent.id, { permissions: [{ resource: "billing", actions: ["*"] }] }),
		).rejects.toThrow(/wildcards/);
	});
});

describe("POST /delegations is owner scoped on both ends", () => {
	async function setup() {
		const auth = await makeAuth();
		const handler = createTheAuthHandler(auth, { rateLimit: false });
		const mine = await newAgent(auth, "u1", "mine");
		const mine2 = await newAgent(auth, "u1", "mine2");
		const theirs = await newAgent(auth, "u2", "theirs");
		const token = await sessionToken(auth, "u1");
		const delegate = (fromAgent: string, toAgent: string) =>
			handler(
				new Request(`${BASE}/delegations`, {
					method: "POST",
					headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
					body: JSON.stringify({
						fromAgent,
						toAgent,
						permissions: [{ resource: "docs", actions: ["read"] }],
						expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
					}),
				}),
			);
		return { auth, delegate, mine, mine2, theirs };
	}

	it("refuses pushing a grant into another owner's agent", async () => {
		const { auth, delegate, mine, theirs } = await setup();
		const res = await delegate(mine.id, theirs.id);
		expect([403, 404]).toContain(res.status);
		expect(await auth.delegation.listChains(theirs.id)).toHaveLength(0);
	});

	it("refuses a nonexistent target agent", async () => {
		const { delegate, mine } = await setup();
		const res = await delegate(mine.id, "agent-that-does-not-exist");
		expect([403, 404]).toContain(res.status);
	});

	it("allows delegating between two agents the caller owns", async () => {
		const { delegate, mine, mine2 } = await setup();
		const res = await delegate(mine.id, mine2.id);
		expect(res.status).toBe(201);
	});
});
