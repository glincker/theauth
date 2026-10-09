import { describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import { simulator } from "../src/simulator/index.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "simulator-route-test-secret-0123456789abcdef";

async function setup() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true },
		auth: { session: { secret: SECRET } },
		plugins: [simulator({ isAdmin: (u) => u.id === "admin" })],
	});
	for (const id of ["admin", "u1"]) {
		auth.db
			.insert(schema.users)
			.values({ id, email: `${id}@x.io`, name: id, createdAt: new Date(), updatedAt: new Date() })
			.run();
	}
	const agent = await auth.agent.create({
		ownerId: "u1",
		name: "bot",
		type: "autonomous",
		permissions: [{ resource: "tool:*", actions: ["read"] }],
	});
	const headers = async (id?: string) => ({
		"content-type": "application/json",
		...(id ? { authorization: `Bearer ${(await auth.auth.session?.create(id))?.token}` } : {}),
	});
	const post = async (id: string | undefined, path: string, body: unknown) =>
		auth.plugins.handleRequest(
			new Request(`http://x${path}`, {
				method: "POST",
				headers: await headers(id),
				body: JSON.stringify(body),
			}),
		);
	return { auth, agent, post };
}

describe("POST /agents/:id/simulate", () => {
	it("rejects anonymous callers and non-admins", async () => {
		const { agent, post } = await setup();
		const body = { action: "read", resource: "tool:x" };
		expect((await post(undefined, `/agents/${agent.id}/simulate`, body))?.status).toBe(401);
		expect((await post("u1", `/agents/${agent.id}/simulate`, body))?.status).toBe(403);
	});

	it("returns a decision with a trace for admins", async () => {
		const { agent, post } = await setup();
		const res = await post("admin", `/agents/${agent.id}/simulate`, {
			action: "read",
			resource: "tool:x",
		});
		expect(res?.status).toBe(200);
		const json = (await res?.json()) as { decision: string; trace: unknown[] };
		expect(json.decision).toBe("allow");
		expect(json.trace.length).toBeGreaterThan(0);
	});

	it("supports what-if overrides, matrix and effective modes", async () => {
		const { agent, post } = await setup();
		const path = `/agents/${agent.id}/simulate`;
		const whatIf = await post("admin", path, {
			action: "write",
			resource: "tool:x",
			overrides: { extraPermissions: [{ resource: "tool:*", actions: ["write"] }] },
		});
		expect(((await whatIf?.json()) as { decision: string }).decision).toBe("allow");

		const matrix = await post("admin", path, {
			matrix: { actions: ["read", "write"], resources: ["tool:x"] },
		});
		expect(((await matrix?.json()) as { cells: unknown[] }).cells).toHaveLength(2);

		const eff = await post("admin", path, { effective: true });
		expect(((await eff?.json()) as { permissions: unknown[] }).permissions).toHaveLength(1);
	});

	it("rejects malformed bodies", async () => {
		const { agent, post } = await setup();
		const res = await post("admin", `/agents/${agent.id}/simulate`, { action: "read" });
		expect(res?.status).toBe(400);
	});
});
