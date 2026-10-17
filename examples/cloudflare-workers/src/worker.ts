/**
 * TheAuth on Cloudflare Workers with D1.
 * Deploy with `wrangler d1 create theauth-db`, `wrangler secret put SESSION_SECRET`, `wrangler deploy`.
 * The "DB" binding is declared in wrangler.toml; run the initial migration on first deploy.
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

// Created per request so it picks up the D1 binding from env.
app.all("/api/*", async (c) => {
	const auth = await createTheAuth({
		database: {
			provider: "d1",
			binding: c.env.DB,
			// Set skipMigrations: true after running `wrangler d1 migrations apply`.
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

	// Demo only: no authentication on the management routes. Real apps pass
	// `authenticate` (see the adapter docs).
	const api = theAuthHono(auth, { allowUnauthenticated: true });
	const url = new URL(c.req.url);
	const stripped = new Request(new URL(url.pathname.replace(/^\/api/, "") || "/", url), c.req.raw);
	return api.fetch(stripped, c.env, c.executionCtx);
});

export default app;
