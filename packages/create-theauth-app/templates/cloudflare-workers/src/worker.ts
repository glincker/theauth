/**
 * theAuth on Cloudflare Workers with D1.
 *
 * Deploy:
 *   wrangler d1 create __APP_NAME__-db      (paste the id into wrangler.toml)
 *   wrangler secret put SESSION_SECRET
 *   wrangler deploy
 */

import { createTheAuth } from "@glinr/theauth";
import { theAuthHono } from "@glinr/theauth-hono";
import { Hono } from "hono";

type Env = {
	DB: D1Database;
	SESSION_SECRET: string;
};

const app = new Hono<{ Bindings: Env }>();

app.get("/health", (c) => c.json({ status: "ok" }));

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

	// Mount theAuthHono under the /api prefix by stripping it before dispatch
	// Demo only: no authentication on the management routes. Real apps pass
	// `authenticate` (see the adapter docs).
	const api = theAuthHono(auth, { allowUnauthenticated: true });
	const url = new URL(c.req.url);
	const stripped = new Request(new URL(url.pathname.replace(/^\/api/, "") || "/", url), c.req.raw);
	return api.fetch(stripped, c.env, c.executionCtx);
});

export default app;
