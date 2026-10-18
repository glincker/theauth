import { describe, expect, it } from "vitest";
import { createBeforeAuthorizeHook } from "./index.js";

const context = { agentId: "agent_1", action: "read", resource: "doc:1" };

describe("createBeforeAuthorizeHook", () => {
	it("allows when the evaluator allows", async () => {
		const hook = createBeforeAuthorizeHook({
			evaluator: async () => ({ allow: true }),
		});
		await expect(hook(context)).resolves.toEqual({ allow: true });
	});

	it("denies with the evaluator reason", async () => {
		const hook = createBeforeAuthorizeHook({
			evaluator: async () => ({ allow: false, reason: "outside policy" }),
		});
		await expect(hook(context)).resolves.toEqual({ allow: false, reason: "outside policy" });
	});

	it("denies by default when the evaluator throws", async () => {
		const hook = createBeforeAuthorizeHook({
			evaluator: async () => {
				throw new Error("backend down");
			},
		});
		const result = await hook(context);
		expect(result.allow).toBe(false);
		expect(result.reason).toContain("backend down");
	});

	it("denies when the evaluator times out", async () => {
		const hook = createBeforeAuthorizeHook({
			timeoutMs: 10,
			evaluator: () => new Promise(() => {}),
		});
		await expect(hook(context)).resolves.toEqual({
			allow: false,
			reason: "integration error: evaluation timed out",
		});
	});
});
