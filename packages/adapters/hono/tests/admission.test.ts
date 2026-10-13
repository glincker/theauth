import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthHono } from "../src/adapter.js";

async function appWith(options: Parameters<typeof theAuthHono>[1]) {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
	const app = new Hono();
	app.route("/api/theauth", theAuthHono(theauth, { allowUnauthenticated: true, ...options }));
	return app;
}

describe("hono adapter admission", () => {
	it("answers 429 once a tier is exhausted, even behind a mount prefix", async () => {
		const app = await appWith({ rateLimit: { strict: { max: 1, window: 60 } } });
		const call = () => app.request("/api/theauth/mcp/token", { method: "POST" });
		expect((await call()).status).not.toBe(429);
		const limited = await call();
		expect(limited.status).toBe(429);
		expect(limited.headers.get("retry-after")).toBeTruthy();
	});

	it("rejects a cookie write from another origin", async () => {
		const app = await appWith({ rateLimit: false });
		const res = await app.request("/api/theauth/agents", {
			method: "POST",
			headers: { cookie: "theauth_session=abc", origin: "https://evil.example" },
		});
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: { code: string } }).error.code).toBe("CSRF_REJECTED");
	});
});
