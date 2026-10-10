import { createTheAuth } from "@glinr/theauth";
import { serve } from "@hono/node-server";
import { createDemoApp } from "./app.js";
import type { DemoEnv } from "./config.js";
import { readLimits } from "./config.js";
import { cleanupExpired, ensureOwner } from "./store.js";

/**
 * Local fallback that needs no Cloudflare tooling. It uses the SDK's in-memory
 * SQLite provider, so everything is gone when the process stops.
 */
async function main(): Promise<void> {
	const env: DemoEnv = process.env;
	const limits = readLimits({
		// A local run has one visitor behind no proxy, so every request shares one bucket.
		DEMO_MAX_AGENTS_PER_CLIENT: "50",
		DEMO_REQUESTS_PER_MINUTE: "600",
		...env,
	});

	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: limits.maxAgents,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: `${limits.ttlMinutes}m`,
		},
	});
	await ensureOwner(auth);

	// Forwarded headers are not trusted locally: no trustedHeader, no proxy count.
	const app = createDemoApp({
		auth,
		limits,
		trustedProxy: {},
		clientSalt: env.DEMO_CLIENT_SALT ?? crypto.randomUUID(),
	});

	const ttlMs = limits.ttlMinutes * 60_000;
	const timer = setInterval(() => {
		cleanupExpired(auth, new Date(Date.now() - ttlMs)).catch((error: unknown) => {
			process.stderr.write(`cleanup failed: ${String(error)}\n`);
		});
	}, 60_000);
	timer.unref();

	const port = Number.parseInt(process.env.PORT ?? "8787", 10);
	serve({ fetch: app.fetch, port }, (info) => {
		process.stdout.write(`TheAuth demo on http://localhost:${info.port}\n`);
	});
}

main().catch((error: unknown) => {
	process.stderr.write(`Fatal: ${error instanceof Error ? error.message : String(error)}\n`);
	process.exit(1);
});
