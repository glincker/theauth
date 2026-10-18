import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import type { AgentLocals } from "../src/index.js";
import { requireScope, theAuthSvelteKit } from "../src/index.js";

const BASE = "http://localhost/api/theauth";

async function setup() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
	const agent = await auth.agent.create({
		ownerId: "u1",
		name: "smoke",
		type: "autonomous",
		permissions: [{ resource: "docs", actions: ["read"] }],
	});
	return { auth, agent };
}

const bearer = (token?: string): Record<string, string> =>
	token ? { Authorization: `Bearer ${token}` } : {};

async function mounted(
	auth: Awaited<ReturnType<typeof setup>>["auth"],
	request: Request,
): Promise<Response> {
	return theAuthSvelteKit(auth, { allowUnauthenticated: true }).POST({ request } as never);
}

function guarded(
	auth: Awaited<ReturnType<typeof setup>>["auth"],
	resource: string,
	headers: Record<string, string>,
): Promise<Response> {
	const route = requireScope(auth, { action: "read", resource }, ({ locals }) =>
		Response.json({ agent: (locals as Partial<AgentLocals>).agent?.id }),
	);
	return Promise.resolve(
		route({ request: new Request(`${BASE}/x`, { headers }), locals: {} } as never),
	);
}

describe("sveltekit smoke: handler and requireScope", () => {
	it("authorizes by bearer token through the mounted handler", async () => {
		const { auth, agent } = await setup();
		const res = await mounted(
			auth,
			new Request(`${BASE}/authorize/token`, {
				method: "POST",
				headers: { ...bearer(agent.token), "Content-Type": "application/json" },
				body: JSON.stringify({ action: "read", resource: "docs" }),
			}),
		);
		expect(res.status).toBe(200);
		expect(((await res.json()) as { data: { allowed: boolean } }).data.allowed).toBe(true);
	});

	it("requireScope allows an agent with the scope and attaches it", async () => {
		const { auth, agent } = await setup();
		const res = await guarded(auth, "docs", bearer(agent.token));
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ agent: agent.id });
	});

	it("requireScope answers 401 without a usable token", async () => {
		const { auth } = await setup();
		const none = await guarded(auth, "docs", {});
		expect(none.status).toBe(401);
		expect(((await none.json()) as { error: { code: string } }).error.code).toBe("invalid_token");
		expect((await guarded(auth, "docs", bearer("kv_nope"))).status).toBe(401);
	});

	it("requireScope answers 403 when the agent lacks the scope", async () => {
		const { auth, agent } = await setup();
		const res = await guarded(auth, "billing", bearer(agent.token));
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: { code: string } }).error.code).toBe("no_permission");
	});
});
