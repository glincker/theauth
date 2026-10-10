import type { D1Database, ExecutionContext, ScheduledController } from "@cloudflare/workers-types";
import { createTheAuth } from "@glinr/theauth";
import type { Hono } from "hono";
import { createDemoApp } from "./app.js";
import type { DemoEnv } from "./config.js";
import { CLOUDFLARE_PROXY, readLimits } from "./config.js";
import type { DemoAuth } from "./store.js";
import { cleanupExpired, ensureOwner } from "./store.js";

interface Env extends DemoEnv {
	DB: D1Database;
}

interface Booted {
	app: Hono;
	auth: DemoAuth;
	ttlMs: number;
}

// One boot per isolate. A random fallback salt keeps the per client cap working
// inside an isolate when DEMO_CLIENT_SALT is not set.
let booted: Promise<Booted> | null = null;
let fallbackSalt: string | null = null;

function clientSalt(env: Env): string {
	if (env.DEMO_CLIENT_SALT) return env.DEMO_CLIENT_SALT;
	if (fallbackSalt === null) fallbackSalt = crypto.randomUUID();
	return fallbackSalt;
}

async function boot(env: Env): Promise<Booted> {
	const limits = readLimits(env);
	const auth = await createTheAuth({
		// Tables come from migrations/0001_init.sql (wrangler d1 migrations apply),
		// not from createTables, which has no D1 executor.
		database: { provider: "d1", binding: env.DB, skipMigrations: true },
		trustedProxy: CLOUDFLARE_PROXY,
		agents: {
			enabled: true,
			maxPerUser: limits.maxAgents,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: `${limits.ttlMinutes}m`,
		},
	});
	await ensureOwner(auth);
	const app = createDemoApp({
		auth,
		limits,
		trustedProxy: CLOUDFLARE_PROXY,
		clientSalt: clientSalt(env),
	});
	return { app, auth, ttlMs: limits.ttlMinutes * 60_000 };
}

function getBoot(env: Env): Promise<Booted> {
	if (!booted) {
		booted = boot(env).catch((error: unknown) => {
			booted = null;
			throw error;
		});
	}
	return booted;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const { app } = await getBoot(env);
		return app.fetch(request, env, ctx);
	},

	/** Cron trigger: remove expired agents and their audit rows. */
	async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
		const { auth, ttlMs } = await getBoot(env);
		ctx.waitUntil(cleanupExpired(auth, new Date(Date.now() - ttlMs)));
	},
};
