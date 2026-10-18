/** An in-process guard that returns no verdict fails closed. */
import { describe, expect, it } from "vitest";
import type { ExternalGuard } from "../src/hooks/guard.js";
import { composeBeforeAuthorize, guardHook } from "../src/hooks/guard.js";
import { makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

const REQ = { action: "read", resource: "mcp:github:issues" };

const silent = (value: unknown): ExternalGuard => ({
	name: "silent",
	check: async () => value as never,
});

describe("guard returning no verdict", () => {
	for (const [label, value] of [
		["undefined", undefined],
		["null", null],
		["a string", "allow"],
		["a number", 1],
	] as const) {
		it(`guardHook denies when the guard returns ${label}`, async () => {
			const theauth = await makeTheAuth({ hooks: { beforeAuthorize: guardHook(silent(value)) } });
			const agent = await newAgent(theauth, "a", READ_GITHUB);
			const r = await theauth.authorize(agent.id, REQ);
			expect(r.allowed).toBe(false);
			expect(r.code).toBeTruthy();
		});

		it(`composeBeforeAuthorize over guardHook denies when the guard returns ${label}`, async () => {
			const hook = composeBeforeAuthorize(
				guardHook({ name: "ok", check: async () => ({ decision: "allow" }) }),
				guardHook(silent(value)),
			);
			const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
			const agent = await newAgent(theauth, "a", READ_GITHUB);
			const r = await theauth.authorize(agent.id, REQ);
			expect(r.allowed).toBe(false);
		});
	}

	it("a guard that returns a real allow still allows", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: guardHook(silent({ decision: "allow" })) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		expect((await theauth.authorize(agent.id, REQ)).allowed).toBe(true);
	});
});
