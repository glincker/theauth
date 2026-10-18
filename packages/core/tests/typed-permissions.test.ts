import { describe, expect, it } from "vitest";
import { definePermissions } from "../src/permission/index.js";
import { createTheAuth } from "../src/theauth.js";

describe("typed permissions runtime", () => {
	it("typed instance authorizes exactly like an untyped one", async () => {
		const permissions = definePermissions({ "mcp:github:*": ["read"] });
		const database = { provider: "sqlite" as const, url: ":memory:" };
		const agents = { enabled: true };
		const typed = await createTheAuth({ database, agents, permissions });
		const plain = await createTheAuth({ database, agents });
		const make = async (a: typeof plain | typeof typed) => {
			const user = await a.user.create({ email: "a@example.com", name: "A" });
			return a.agent.create({
				ownerId: user.id,
				name: "bot",
				type: "autonomous",
				permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
			});
		};
		const t = await make(typed);
		const p = await make(plain);
		const req = { resource: "mcp:github:issues", action: "read" } as const;
		expect((await typed.authorize(t.id, req)).allowed).toBe(true);
		expect((await plain.authorize(p.id, req)).allowed).toBe(true);
		expect(
			(await plain.authorize(p.id, { resource: "mcp:github:x", action: "write" })).allowed,
		).toBe(false);
	});
});
