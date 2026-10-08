import { createApp, toWebHandler, use } from "h3";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthNuxt } from "../src/adapter.js";

const BASE = "http://localhost/api/auth/theauth";

async function make() {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
}

const authenticate = async (req: Request) =>
	req.headers.get("x-api-user") === "admin" ? { id: "admin" } : null;

async function build() {
	const app = createApp();
	use(app, theAuthNuxt(await make(), { basePath: "/api/auth/theauth", authenticate }));
	return toWebHandler(app);
}

describe("theAuthNuxt authentication", () => {
	it("fails closed when no resolver is configured", async () => {
		const theauth = await make();
		expect(() => theAuthNuxt(theauth)).toThrow(/require authentication/);
	});

	it("rejects anonymous callers and accepts the resolver's callers", async () => {
		const handle = await build();
		for (const path of [
			"/agents",
			"/agents/abc",
			"/audit",
			"/audit/export",
			"/dashboard/stats",
			"/delegations/a",
		]) {
			const res = await handle(new Request(`${BASE}${path}`));
			expect(res.status, path).toBe(401);
		}
		const ok = await handle(new Request(`${BASE}/agents`, { headers: { "x-api-user": "admin" } }));
		expect(ok.status).toBe(200);
	});

	it("leaves /authorize/token to its own bearer check", async () => {
		const handle = await build();
		const res = await handle(
			new Request(`${BASE}/authorize/token`, {
				method: "POST",
				body: "{}",
				headers: { "Content-Type": "application/json" },
			}),
		);
		expect(res.status).toBe(401);
		expect(await res.text()).toMatch(/Authorization header/);
	});
});
