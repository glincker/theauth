/** The handler is a plain Request to Response function, so Elysia `mount` and React Router resource routes can use it as is. */
import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { createTheAuth } from "../../src/theauth.js";

async function make() {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
	});
}

describe("fetch-style mounting", () => {
	it("serves relative paths with an empty basePath (Elysia mount strips the prefix)", async () => {
		const handler = createTheAuthHandler(await make(), {
			basePath: "",
			authenticate: async () => ({ id: "admin" }),
		});
		expect((await handler(new Request("http://localhost/agents"))).status).toBe(200);
		expect((await handler(new Request("http://localhost/nope"))).status).toBe(404);
	});

	it("serves the full path with the default basePath (React Router resource route)", async () => {
		const handler = createTheAuthHandler(await make(), {
			authenticate: async () => ({ id: "admin" }),
		});
		expect((await handler(new Request("http://localhost/api/theauth/agents"))).status).toBe(200);
		expect((await handler(new Request("http://localhost/other/agents"))).status).toBe(404);
	});
});
