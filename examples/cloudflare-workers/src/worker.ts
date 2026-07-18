/**
 * TheAuth on Cloudflare Workers with D1
 *
 * Deploy:
 *   wrangler d1 create theauth-db
 *   wrangler secret put SESSION_SECRET
 *   wrangler deploy
 *
 * The D1 binding is declared in wrangler.toml:
 *
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "theauth-db"
 *   database_id = "<your-database-id>"
 *
 * On first deploy, run migrations:
 *   wrangler d1 execute theauth-db --file=./migrations/0001_initial.sql
 */

import { createTheAuth } from "@glinr/theauth";
import { kavachHono } from "@glinr/theauth-hono";
import { Hono } from "hono";

// Cloudflare Workers env bindings
type Env = {
	DB: D1Database;
	SESSION_SECRET: string;
};

const app = new Hono<{ Bindings: Env }>();

// Health check — no DB required
app.get("/health", (c) => c.json({ status: "ok" }));

// All TheAuth routes under /api
// kavach is created per-request so it picks up the correct D1 binding
app.all("/api/*", async (c) => {
	const kavach = await createTheAuth({
		database: {
			provider: "d1",
			binding: c.env.DB,
			// Set skipMigrations: true once you've run `wrangler d1 migrations apply`
			// skipMigrations: true,
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

	// Mount kavachHono under the /api prefix by stripping it before dispatch
	const api = kavachHono(kavach);
	const url = new URL(c.req.url);
	const stripped = new Request(new URL(url.pathname.replace(/^\/api/, "") || "/", url), c.req.raw);
	return api.fetch(stripped, c.env, c.executionCtx);
});

export default app;
