/** Regression for GHSA-rw7g-rg23-6225: id-addressed management routes must not reach another owner's data. */
import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { BASE, makeAuth, newAgent, sessionToken } from "./helpers.js";

async function setup() {
	const auth = await makeAuth();
	const handler = createTheAuthHandler(auth, { rateLimit: false });
	const mine = await newAgent(auth, "u1", "mine");
	const theirs = await newAgent(auth, "u2", "theirs");
	const token = await sessionToken(auth, "u1");
	const call = (method: string, path: string, body?: unknown) =>
		handler(
			new Request(`${BASE}${path}`, {
				method,
				headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
				...(body !== undefined && { body: JSON.stringify(body) }),
			}),
		);
	return { auth, call, mine, theirs };
}

describe("id-addressed routes are scoped to the caller", () => {
	it("a foreign agent cannot be read, changed, rotated or revoked", async () => {
		const { auth, call, theirs } = await setup();
		const attempts = [
			await call("GET", `/agents/${theirs.id}`),
			await call("PATCH", `/agents/${theirs.id}`, { name: "hijacked" }),
			await call("POST", `/agents/${theirs.id}/rotate`),
			await call("DELETE", `/agents/${theirs.id}`),
		];
		for (const res of attempts) expect([403, 404]).toContain(res.status);
		const after = await auth.agent.get(theirs.id);
		expect(after?.status).toBe("active");
		expect(after?.name).toBe("theirs");
	});

	it("the owner still reaches their own agent", async () => {
		const { call, mine } = await setup();
		expect((await call("GET", `/agents/${mine.id}`)).status).toBe(200);
	});

	it("a foreign agent cannot be targeted when creating or listing delegations", async () => {
		const { call, mine, theirs } = await setup();
		const create = await call("POST", "/delegations", {
			fromAgentId: theirs.id,
			toAgentId: mine.id,
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		expect(create.status).toBeGreaterThanOrEqual(400);
		const list = await call("GET", `/delegations/${theirs.id}`);
		if (list.status === 200) {
			const body = (await list.json()) as unknown;
			expect(JSON.stringify(body)).not.toContain(theirs.id);
		} else {
			expect([403, 404]).toContain(list.status);
		}
	});
});
