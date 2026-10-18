import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { makeHarness } from "../mcp-test-harness.js";
import { BASE, makeAuth } from "./helpers.js";

describe("basePath trailing slash trim", () => {
	it("finishes quickly on a long hostile run of slashes", async () => {
		const auth = await makeAuth();
		const hostile = `/auth${"/".repeat(200_000)}x`;
		const started = performance.now();
		createTheAuthHandler(auth, {
			mcp: makeHarness().mcp,
			rateLimit: false,
			allowUnauthenticated: true,
			basePath: hostile,
		});
		expect(performance.now() - started).toBeLessThan(1000);
	});

	it("still serves routes under a basePath given with trailing slashes", async () => {
		const auth = await makeAuth();
		const handler = createTheAuthHandler(auth, {
			mcp: makeHarness().mcp,
			rateLimit: false,
			allowUnauthenticated: true,
			basePath: "/custom///",
		});
		const res = await handler(
			new Request(
				`${BASE.replace("/api/theauth", "/custom")}/.well-known/oauth-authorization-server`,
			),
		);
		expect(res.status).toBe(200);
	});
});
