import type { AuditEntry, TrustedProxyConfig } from "@glinr/theauth";
import { createRateLimiter, insertAuditRow, resolveClientIp } from "@glinr/theauth";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import type { DemoLimits } from "./config.js";
import { renderPage } from "./page.js";
import { findPreset, PRESETS } from "./presets.js";
import type { DemoAuth } from "./store.js";
import {
	cleanupExpired,
	clientFingerprint,
	countAgents,
	countAgentsForClient,
	countAuditRows,
	OWNER_ID,
} from "./store.js";

export interface DemoAppOptions {
	auth: DemoAuth;
	limits: DemoLimits;
	/** How to find the client IP. Pass the Cloudflare config on Workers. */
	trustedProxy: TrustedProxyConfig;
	/** Keys the client fingerprint. Without a stable value the per client cap is per process. */
	clientSalt: string;
}

const createBody = z.object({
	name: z
		.string()
		.trim()
		.min(1)
		.max(32)
		.regex(/^[A-Za-z0-9 _-]+$/, "Use letters, digits, spaces, dash or underscore"),
	preset: z.enum(["reader", "editor"]),
});

const authorizeBody = z.object({
	agentId: z.string().min(1).max(64),
	action: z
		.string()
		.trim()
		.min(1)
		.max(32)
		.regex(/^[a-z][a-z_-]*$/, "Use lowercase letters, dash or underscore"),
	resource: z
		.string()
		.trim()
		.min(1)
		.max(64)
		.regex(/^[a-z0-9][a-z0-9:_.*-]*$/, "Use lowercase letters, digits and : _ . * -"),
});

const CLEANUP_INTERVAL_MS = 60_000;

function securityHeaders(nonce?: string): Record<string, string> {
	const script = nonce ? `'nonce-${nonce}'` : "'none'";
	return {
		"Content-Security-Policy": [
			"default-src 'none'",
			`script-src ${script}`,
			`style-src ${script}`,
			"connect-src 'self'",
			"base-uri 'none'",
			"form-action 'none'",
			"frame-ancestors 'none'",
		].join("; "),
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy": "no-referrer",
		"X-Frame-Options": "DENY",
		"Cache-Control": "no-store",
	};
}

function toRow(entry: AuditEntry) {
	return {
		id: entry.id,
		agentId: entry.agentId,
		action: entry.action,
		resource: entry.resource,
		result: entry.result,
		reason: entry.reason ?? null,
		at: entry.timestamp.toISOString(),
	};
}

export function createDemoApp(options: DemoAppOptions): Hono {
	const { auth, limits, trustedProxy, clientSalt } = options;
	const limiter = createRateLimiter({ max: limits.requestsPerMinute, window: 60 });
	const ttlMs = limits.ttlMinutes * 60_000;
	let lastCleanup = 0;

	async function maybeCleanup(): Promise<void> {
		const now = Date.now();
		if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
		lastCleanup = now;
		await cleanupExpired(auth, new Date(now - ttlMs));
	}

	function clientIp(c: Context): string {
		return resolveClientIp(c.req.raw, trustedProxy) ?? "unknown";
	}

	const app = new Hono();

	app.get("/", (c) => {
		const nonce = crypto.randomUUID().replace(/-/g, "");
		return c.html(renderPage(nonce, PRESETS), 200, securityHeaders(nonce));
	});

	app.get("/healthz", (c) => c.json({ status: "ok" }, 200, securityHeaders()));

	app.use("/api/*", async (c, next) => {
		for (const [k, v] of Object.entries(securityHeaders())) c.header(k, v);
		const verdict = limiter.check(clientIp(c));
		if (!verdict.allowed) {
			const retry = Math.max(Math.ceil((verdict.resetAt.getTime() - Date.now()) / 1000), 1);
			c.header("Retry-After", String(retry));
			return c.json(
				{ error: { code: "RATE_LIMITED", message: "Too many requests. Slow down and retry." } },
				429,
			);
		}
		return next();
	});

	app.get("/api/info", (c) =>
		c.json({
			ttlMinutes: limits.ttlMinutes,
			maxAgentsPerClient: limits.maxAgentsPerClient,
			maxActionsPerAgent: limits.maxActionsPerAgent,
			presets: PRESETS,
		}),
	);

	app.post("/api/agents", async (c) => {
		const parsed = createBody.safeParse(await c.req.json().catch(() => null));
		if (!parsed.success) {
			return c.json(
				{ error: { code: "INVALID_INPUT", message: parsed.error.issues[0]?.message ?? "Invalid" } },
				400,
			);
		}
		const preset = findPreset(parsed.data.preset);
		if (!preset) {
			return c.json({ error: { code: "INVALID_INPUT", message: "Unknown preset" } }, 400);
		}

		await maybeCleanup();

		if ((await countAgents(auth)) >= limits.maxAgents) {
			return c.json(
				{
					error: {
						code: "SANDBOX_FULL",
						message: "The shared sandbox is full. Entries expire, so try again in a few minutes.",
					},
				},
				503,
			);
		}
		const client = await clientFingerprint(clientIp(c), clientSalt);
		if ((await countAgentsForClient(auth, client)) >= limits.maxAgentsPerClient) {
			return c.json(
				{
					error: {
						code: "CLIENT_CAP",
						message: `This network already holds ${limits.maxAgentsPerClient} demo agents. They expire after ${limits.ttlMinutes} minutes.`,
					},
				},
				429,
			);
		}

		const expiresAt = new Date(Date.now() + ttlMs);
		const agent = await auth.agent.create({
			ownerId: OWNER_ID,
			name: parsed.data.name,
			type: "autonomous",
			permissions: preset.permissions,
			expiresAt,
			metadata: { client, preset: preset.id },
		});

		return c.json(
			{
				agent: {
					id: agent.id,
					name: agent.name,
					preset: preset.id,
					permissions: preset.permissions,
					expiresAt: expiresAt.toISOString(),
				},
				token: agent.token,
				tokenNote: "Shown once. The server keeps only a SHA-256 hash of it.",
			},
			201,
		);
	});

	app.post("/api/authorize", async (c) => {
		const parsed = authorizeBody.safeParse(await c.req.json().catch(() => null));
		if (!parsed.success) {
			return c.json(
				{ error: { code: "INVALID_INPUT", message: parsed.error.issues[0]?.message ?? "Invalid" } },
				400,
			);
		}
		const { agentId, action, resource } = parsed.data;

		const agent = await auth.agent.get(agentId);
		if (!agent) {
			return c.json({
				allowed: false,
				reason: "No such agent. It may have expired and been cleaned up.",
				auditId: null,
			});
		}
		if ((await countAuditRows(auth, agentId)) >= limits.maxActionsPerAgent) {
			return c.json(
				{
					error: {
						code: "ACTION_CAP",
						message: `This agent reached ${limits.maxActionsPerAgent} actions. Create a new one to keep going.`,
					},
				},
				429,
			);
		}

		const result = await auth.authorize(agentId, { action, resource });

		// The SDK refuses a revoked or expired agent before it reaches the audit
		// writer, so no row exists for that denial. Record it here so the table
		// shows the retry after revocation.
		if (!result.allowed && result.auditId === "") {
			await insertAuditRow(auth.db, {
				id: crypto.randomUUID(),
				agentId,
				userId: agent.ownerId,
				action,
				resource,
				parameters: null,
				result: "denied",
				reason: result.reason ?? "Denied",
				durationMs: 0,
				timestamp: new Date(),
			});
		}

		return c.json({
			allowed: result.allowed,
			reason: result.reason ?? null,
			auditId: result.auditId === "" ? null : result.auditId,
		});
	});

	app.get("/api/audit", async (c) => {
		const agentId = c.req.query("agentId");
		if (!agentId || agentId.length > 64) {
			return c.json({ error: { code: "INVALID_INPUT", message: "agentId is required" } }, 400);
		}
		const entries = await auth.audit.query({ agentId, limit: limits.maxActionsPerAgent + 5 });
		return c.json({ rows: entries.map(toRow) });
	});

	app.post("/api/agents/:id/revoke", async (c) => {
		const id = c.req.param("id");
		const agent = id.length <= 64 ? await auth.agent.get(id) : null;
		if (!agent) {
			return c.json({ error: { code: "NOT_FOUND", message: "No such agent" } }, 404);
		}
		if (agent.status !== "revoked") await auth.agent.revoke(id);
		return c.json({ id, status: "revoked" });
	});

	return app;
}
