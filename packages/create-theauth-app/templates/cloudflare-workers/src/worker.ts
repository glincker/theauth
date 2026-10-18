/**
 * theAuth on Cloudflare Workers with D1.
 *
 * Deploy:
 *   wrangler d1 create __APP_NAME__-db      (paste the id into wrangler.toml)
 *   wrangler secret put SESSION_SECRET
 *   wrangler secret put ADMIN_API_KEY
 *   wrangler deploy
 */

import { createTheAuth } from "@glinr/theauth";
import { theAuthHono } from "@glinr/theauth-hono";
import { Hono } from "hono";

type Env = {
	DB: D1Database;
	SESSION_SECRET: string;
	ADMIN_API_KEY: string;
	OWNER_EMAIL?: string;
};

const app = new Hono<{ Bindings: Env }>();

app.get("/health", (c) => c.json({ status: "ok" }));

// Callers of the management routes send "Authorization: Bearer <ADMIN_API_KEY>".
async function sha256(value: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

async function sameKey(supplied: string, expected: string): Promise<boolean> {
	const [a, b] = await Promise.all([sha256(supplied), sha256(expected)]);
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	return diff === 0;
}

// Agents reference their owner by foreign key, so the owner user must exist first.
// user.create is idempotent, so it is safe to call once per isolate.
let ownerReady: Promise<string> | null = null;

// auth is created per-request so it picks up the correct D1 binding
app.all("/api/*", async (c) => {
	const auth = await createTheAuth({
		database: {
			provider: "d1",
			binding: c.env.DB,
			// Set skipMigrations: true once you've run `wrangler d1 migrations apply`
		},
		auth: {
			session: {
				secret: c.env.SESSION_SECRET,
			},
		},
		agents: {
			enabled: true,
			maxPerUser: 100,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	ownerReady ??= auth.user
		.create({ email: c.env.OWNER_EMAIL ?? "owner@example.com", name: "Owner" })
		.then((owner) => owner.id);
	await ownerReady;

	// Mount theAuthHono under the /api prefix by stripping it before dispatch.
	const api = theAuthHono(auth, {
		authenticate: async (request) => {
			const header = request.headers.get("authorization");
			if (!c.env.ADMIN_API_KEY || !header?.startsWith("Bearer ")) return null;
			return (await sameKey(header.slice("Bearer ".length), c.env.ADMIN_API_KEY))
				? { id: "admin" }
				: null;
		},
	});
	const url = new URL(c.req.url);
	const stripped = new Request(new URL(url.pathname.replace(/^\/api/, "") || "/", url), c.req.raw);
	return api.fetch(stripped, c.env, c.executionCtx);
});

export default app;
