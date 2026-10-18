/** POST /authorize/token carries approvalId to core, so an approved request is spent once over HTTP. */
import { describe, expect, it } from "vitest";
import { users } from "../../src/db/schema.js";
import { createTheAuthHandler } from "../../src/http/index.js";
import type { Permission } from "../../src/index.js";
import { createTheAuth } from "../../src/index.js";

const GATED: Permission[] = [
	{ resource: "bank:transfer", actions: ["execute"], constraints: { requireApproval: true } },
];
const CALL = { action: "execute", resource: "bank:transfer" };
const ORIGIN = "http://localhost/api/theauth";

async function world() {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
	});
	await auth.db
		.insert(users)
		.values({
			id: "u1",
			email: "u1@example.com",
			name: "u1",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	const agent = await auth.agent.create({
		ownerId: "u1",
		name: "payer",
		type: "autonomous",
		permissions: GATED,
	});
	const handler = createTheAuthHandler(auth, { rateLimit: false, allowUnauthenticated: true });
	const post = (body: Record<string, unknown>) =>
		handler(
			new Request(`${ORIGIN}/authorize/token`, {
				method: "POST",
				headers: { "content-type": "application/json", authorization: `Bearer ${agent.token}` },
				body: JSON.stringify(body),
			}),
		);
	return { auth, agent, post };
}

describe("authorize over HTTP with an approval id", () => {
	it("denies without an approval, allows once with an approved id, then refuses a replay", async () => {
		const w = await world();
		const first = await w.post(CALL);
		expect(first.status).not.toBe(200);
		const req = await w.auth.approval.request({
			agentId: w.agent.id,
			userId: "u1",
			...CALL,
		});
		await w.auth.approval.approve(req.id, "u1");
		const spent = await w.post({ ...CALL, approvalId: req.id });
		expect(spent.status).toBe(200);
		const replay = await w.post({ ...CALL, approvalId: req.id });
		expect(replay.status).not.toBe(200);
		const body = (await replay.json()) as { data?: { code?: string } };
		expect(body.data?.code).toBe("approval_already_used");
	});
});
