/** Wave 8 review probe: the integration gate allows only on a literal `allowed: true`, like the HTTP guard. */
import { describe, expect, it } from "vitest";
import type { AuthorizeLike, AuthorizeResultLike } from "../src/integrations/index.js";
import { createGate } from "../src/integrations/index.js";

/** What a custom `authorize` that forwards a loosely parsed response could hand back. */
const loose =
	(value: unknown): AuthorizeLike =>
	async () =>
		value as AuthorizeResultLike;

describe("createGate fails closed on a malformed decision", () => {
	it.each([
		["string false", { allowed: "false" }],
		["number one", { allowed: 1 }],
		["object", { allowed: {} }],
		["null result", null],
	])("denies when allowed is %s", async (_label, value) => {
		const gate = createGate({ authorize: loose(value), agentId: "agt_1" });
		const denial = await gate.check("send_email", { to: "a@example.com" });
		expect(denial?.denied).toBe(true);
	});

	it("still allows a real allow", async () => {
		const gate = createGate({ authorize: loose({ allowed: true }), agentId: "agt_1" });
		expect(await gate.check("send_email", {})).toBeNull();
	});
});
