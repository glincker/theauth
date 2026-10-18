/** `policy.taint.inputLabels`: input kinds become call labels a taint rule can forbid. */
import { describe, expect, it } from "vitest";
import { users } from "../src/db/schema.js";
import type { TaintConfig } from "../src/taint/index.js";
import { createTheAuth } from "../src/theauth.js";

const RULE: TaintConfig["rules"] = [
	{ id: "exec-no-docs", resource: "tool:exec", forbid: ["input:retrieved_document"] },
];

async function world(taint: TaintConfig) {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		policy: { taint },
	});
	auth.db
		.insert(users)
		.values({
			id: "u1",
			email: "u1@t.test",
			name: "u1",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	const agent = await auth.agent.create({
		ownerId: "u1",
		name: "a",
		type: "autonomous",
		permissions: [{ resource: "tool:exec", actions: ["execute"] }],
	});
	const call = (inputs?: { kind: "retrieved_document" | "user_message"; content: string }[]) =>
		auth.policy.evaluate(
			{
				subject: { agentId: agent.id },
				action: "execute",
				resource: "tool:exec",
				context: inputs ? { inputs } : undefined,
			},
			{ openApproval: false },
		);
	return { auth, agent, call };
}

describe("taint inputLabels", () => {
	it("holds a call that had a retrieved document in context, lets a user message through", async () => {
		const w = await world({ inputLabels: true, rules: RULE });
		const held = await w.call([{ kind: "retrieved_document", content: "page" }]);
		expect(held.decision).toBe("escalate");
		expect(held.taint?.matches[0]?.labels).toEqual(["input:retrieved_document"]);
		expect((await w.call([{ kind: "user_message", content: "run it" }])).decision).toBe("allow");
		expect((await w.call()).decision).toBe("allow");
	});

	it("is off by default, so inputs alone never change a decision", async () => {
		const w = await world({ rules: RULE });
		expect((await w.call([{ kind: "retrieved_document", content: "page" }])).decision).toBe(
			"allow",
		);
	});
});
