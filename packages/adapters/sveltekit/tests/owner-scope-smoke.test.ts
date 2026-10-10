import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthSvelteKit } from "../src/adapter.js";

const BASE = "http://localhost/api/theauth";
const READ_DOCS = [{ resource: "docs", actions: ["read"] }];
const ALLOWED_IP = "203.0.113.5";

async function invokeHandler(
	handlers: ReturnType<typeof theAuthSvelteKit>,
	method: "GET" | "POST",
	url: string,
	headers: Record<string, string>,
	body?: string,
): Promise<Response> {
	const request = new Request(url, { method, headers, body });
	return handlers[method]({ request } as never);
}

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
		auth: { session: { secret: "test-session-secret-that-is-at-least-32-chars!!" } },
	});
	const now = new Date();
	const tokens: Record<string, string> = {};
	for (const id of ["u1", "u2"]) {
		await auth.db
			.insert(users)
			.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now });
		const sessions = auth.auth.session;
		if (!sessions) throw new Error("session manager missing");
		tokens[id] = (await sessions.create(id)).token;
	}
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
		permissions: [
			{ resource: "docs", actions: ["read"], constraints: { ipAllowlist: [ALLOWED_IP] } },
		],
	});
	return { auth, a1: a1.id, a2: a2.id, a2Token: a2.token, tokens };
}

describe("theAuthSvelteKit owner scope and client ip", () => {
	it("limits a signed in user to their own agents by default", async () => {
		const { auth, a1, a2, tokens } = await setup();
		const handlers = theAuthSvelteKit(auth);
		const as = (token: string, path: string) =>
			invokeHandler(handlers, "GET", `${BASE}${path}`, { Authorization: `Bearer ${token}` });
		expect((await as(tokens.u1 ?? "", `/agents/${a1}`)).status).toBe(200);
		expect((await as(tokens.u1 ?? "", `/agents/${a2}`)).status).toBe(404);
		expect((await as(tokens.u1 ?? "", "/agents?userId=u2")).status).toBe(403);
		const list = (await (await as(tokens.u1 ?? "", "/agents")).json()) as {
			data: { id: string }[];
		};
		expect(list.data.map((a) => a.id)).toEqual([a1]);
	});

	it("ignores a spoofed X-Forwarded-For unless trustedProxy is set", async () => {
		const { auth, a2Token } = await setup();
		const authenticate = async () => ({ id: "admin" });
		const send = (handlers: ReturnType<typeof theAuthSvelteKit>) =>
			invokeHandler(
				handlers,
				"POST",
				`${BASE}/authorize/token`,
				{
					Authorization: `Bearer ${a2Token}`,
					"Content-Type": "application/json",
					"x-forwarded-for": ALLOWED_IP,
				},
				JSON.stringify({ action: "read", resource: "docs" }),
			);
		expect((await send(theAuthSvelteKit(auth, { authenticate }))).status).toBe(403);
		const trusted = theAuthSvelteKit(auth, {
			authenticate,
			trustedProxy: { trustedProxyCount: 1 },
		});
		expect((await send(trusted)).status).toBe(200);
	});
});
