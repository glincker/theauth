/** Full TheAuth backend with in-memory SQLite, seed data, and dashboard UI. */

import { existsSync, readFileSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { extname, join, resolve } from "node:path";
import { env, stdout } from "node:process";
import { serve } from "@hono/node-server";
import { kavachHono } from "@theauth/hono";
import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Kavach, Permission } from "theauth";
import { createKavach, users } from "theauth";

export interface DemoServerOptions {
	port: number;
}

const MIME: Record<string, string> = {
	".html": "text/html; charset=utf-8",
	".js": "application/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".ico": "image/x-icon",
	".woff2": "font/woff2",
	".woff": "font/woff",
	".ttf": "font/ttf",
	".map": "application/json; charset=utf-8",
};

// ─── Dashboard dist resolution ───────────────────────────────────────────────

function resolveDashboardDistDir(): string {
	try {
		const require = createRequire(import.meta.url);
		const pkgPath = require.resolve("@theauth/dashboard/package.json");
		const pkgDir = resolve(pkgPath, "..");
		const distDir = join(pkgDir, "dist", "app");
		if (existsSync(distDir)) return distDir;
	} catch {
		// fall through
	}

	const thisDir = new URL(".", import.meta.url).pathname;
	const candidates = [
		join(thisDir, "..", "..", "dashboard", "dist", "app"),
		join(thisDir, "..", "dashboard", "dist", "app"),
		resolve("packages", "dashboard", "dist", "app"),
	];

	for (const candidate of candidates) {
		if (existsSync(candidate)) return candidate;
	}

	throw new Error(
		"Cannot find @theauth/dashboard dist directory.\n" +
			"Build the dashboard first: cd packages/dashboard && pnpm build\n",
	);
}

// ─── HTML injection ──────────────────────────────────────────────────────────

async function patchIndexHtml(distDir: string, apiUrl: string): Promise<string> {
	const html = await readFile(join(distDir, "index.html"), "utf-8");
	const injection = `<script>window.__THEAUTH_API_URL__ = ${JSON.stringify(apiUrl)};</script>`;
	return html.includes("</head>")
		? html.replace("</head>", `${injection}</head>`)
		: injection + html;
}

// ─── Seed data ───────────────────────────────────────────────────────────────

async function seedDemoData(kavach: Kavach): Promise<void> {
	// Seed a demo user
	kavach.db
		.insert(users)
		.values({
			id: "user-demo",
			email: "demo@theauth.dev",
			name: "Demo User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	// Agent 1: github-reader (autonomous)
	const githubPerms: Permission[] = [
		{ resource: "mcp:github:repos", actions: ["read", "list"] },
		{ resource: "mcp:github:issues", actions: ["read", "list", "write"] },
	];
	const githubAgent = await kavach.agent.create({
		ownerId: "user-demo",
		name: "github-reader",
		type: "autonomous",
		permissions: githubPerms,
	});

	// Agent 2: slack-bot (service)
	const slackPerms: Permission[] = [
		{ resource: "mcp:slack:channels", actions: ["read"] },
		{ resource: "mcp:slack:messages", actions: ["read"] },
	];
	const slackAgent = await kavach.agent.create({
		ownerId: "user-demo",
		name: "slack-bot",
		type: "service",
		permissions: slackPerms,
	});

	// Agent 3: deploy-helper (delegated)
	const deployPerms: Permission[] = [{ resource: "mcp:deploy:staging", actions: ["execute"] }];
	const deployAgent = await kavach.agent.create({
		ownerId: "user-demo",
		name: "deploy-helper",
		type: "delegated",
		permissions: deployPerms,
	});

	// Delegation: github-reader -> deploy-helper
	await kavach.delegate({
		fromAgent: githubAgent.id,
		toAgent: deployAgent.id,
		permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
		maxDepth: 2,
	});

	// Generate audit entries by running authorize calls
	const authorizeChecks = [
		{ agentId: githubAgent.id, action: "read", resource: "mcp:github:repos" },
		{ agentId: githubAgent.id, action: "list", resource: "mcp:github:issues" },
		{ agentId: githubAgent.id, action: "write", resource: "mcp:github:issues" },
		{ agentId: slackAgent.id, action: "read", resource: "mcp:slack:channels" },
		{ agentId: slackAgent.id, action: "read", resource: "mcp:slack:messages" },
		{ agentId: slackAgent.id, action: "write", resource: "mcp:slack:messages" }, // denied
		{ agentId: deployAgent.id, action: "execute", resource: "mcp:deploy:staging" },
		{ agentId: deployAgent.id, action: "execute", resource: "mcp:deploy:production" }, // denied
		{ agentId: githubAgent.id, action: "read", resource: "mcp:github:repos" },
		{ agentId: githubAgent.id, action: "delete", resource: "mcp:github:repos" }, // denied
	];

	for (const check of authorizeChecks) {
		await kavach.authorize(check.agentId, {
			action: check.action,
			resource: check.resource,
		});
	}

	stdout.write(`  Seeded: 3 agents, 1 delegation, ${authorizeChecks.length} audit entries\n`);
}

// ─── Auth middleware ─────────────────────────────────────────────────────────

function createAuthRoute(secret: string | null): Hono {
	const auth = new Hono();

	auth.all("/dashboard/auth", (c) => {
		if (secret === null) {
			return c.json({ ok: true, mode: "dev" });
		}

		const authHeader = c.req.header("Authorization") ?? "";
		const provided = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

		if (provided === secret) {
			return c.json({ ok: true });
		}
		return c.json({ code: "UNAUTHORIZED", message: "Invalid dashboard secret." }, 401);
	});

	return auth;
}

// ─── Server ──────────────────────────────────────────────────────────────────

export async function startDemoServer(options: DemoServerOptions): Promise<void> {
	const { port } = options;
	const dashboardSecret = env.THEAUTH_DASHBOARD_SECRET ?? null;

	if (dashboardSecret === null) {
		stdout.write("  [warn] THEAUTH_DASHBOARD_SECRET is not set -- dashboard auth is disabled.\n");
	}

	// 1. Create TheAuth with in-memory SQLite
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 50,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	// 2. Seed demo data
	await seedDemoData(kavach);

	// 3. Build the Hono app
	const api = kavachHono(kavach);
	const authRoute = createAuthRoute(dashboardSecret);
	const app = new Hono();

	app.use("/*", cors({ origin: "*" }));

	// Dashboard compatibility routes (transform core shape -> dashboard expected shape)
	app.get("/api/dashboard/stats", async (c) => {
		const allAgents = await kavach.agent.list({});
		const activeCount = allAgents.filter((a: { status: string }) => a.status === "active").length;
		const auditEntries = await kavach.audit.query({ limit: 10000 });
		// audit.query returns an array directly from core
		const entries = Array.isArray(auditEntries) ? auditEntries : [];
		const now = Date.now();
		const day = 24 * 60 * 60 * 1000;
		const recent = entries.filter(
			(e: { timestamp: Date | string }) => new Date(e.timestamp).getTime() > now - day,
		);
		const allowed = entries.filter((e: { result: string }) => e.result === "allowed").length;
		const total = entries.length;

		let activeDelegations = 0;
		try {
			const delegations = await kavach.delegation.listChains("");
			activeDelegations = Array.isArray(delegations) ? delegations.length : 0;
		} catch {
			// delegation.list may not exist or may throw
		}

		return c.json({
			totalAgents: allAgents.length,
			activeAgents: activeCount,
			totalAuditEvents: total,
			recentAuditEvents: recent.length,
			authAllowedRate: total > 0 ? Math.round((allowed / total) * 100) : 0,
			activeDelegations,
		});
	});

	// Audit logs (dashboard expects { entries, total, limit, offset })
	app.get("/api/audit", async (c) => {
		const limit = Number(c.req.query("limit") ?? "50");
		const offset = Number(c.req.query("offset") ?? "0");
		const agentId = c.req.query("agentId");
		const result = c.req.query("result");

		const allEntries = await kavach.audit.query({
			...(agentId ? { agentId } : {}),
			...(result ? { result: result as "allowed" | "denied" } : {}),
			limit: 10000,
		});
		const entries = Array.isArray(allEntries) ? allEntries : [];
		const paged = entries.slice(offset, offset + limit);

		return c.json({
			entries: paged.map((e) => ({
				...e,
				agentName: "agent",
				durationMs: 0,
				metadata: {},
			})),
			total: entries.length,
			limit,
			offset,
		});
	});

	// Agents list (dashboard expects array with permissionsCount)
	app.get("/api/agents", async (c) => {
		const agents = await kavach.agent.list({});
		return c.json(
			agents.map((a) => ({
				...a,
				permissionsCount: 0,
				lastActiveAt: null,
				metadata: {},
			})),
		);
	});

	// Delegations (aggregate from all agents)
	app.get("/api/delegations", async (c) => {
		try {
			const agents = await kavach.agent.list({});
			const allChains: Array<Record<string, unknown>> = [];
			for (const agent of agents) {
				const chains = await kavach.delegation.listChains(agent.id as string);
				if (Array.isArray(chains)) {
					for (const chain of chains) {
						allChains.push({
							...chain,
							fromAgentName: agent.name ?? "unknown",
							toAgentName: "agent",
						});
					}
				}
			}
			return c.json(allChains);
		} catch {
			return c.json([]);
		}
	});

	// Users
	app.get("/api/users", (c) => {
		return c.json([
			{
				id: "user-demo",
				email: "demo@theauth.dev",
				name: "Demo User",
				agentCount: 3,
				createdAt: new Date().toISOString(),
			},
		]);
	});

	// Permissions templates (in-memory store for demo)
	const templates: Array<Record<string, unknown>> = [];
	app.get("/api/permissions/templates", (c) => c.json(templates));
	app.post("/api/permissions/templates", async (c) => {
		const body = (await c.req.json()) as Record<string, unknown>;
		const template = { id: crypto.randomUUID(), ...body, createdAt: new Date().toISOString() };
		templates.push(template);
		return c.json(template, 201);
	});
	app.patch("/api/permissions/templates/:id", async (c) => {
		const id = c.req.param("id");
		const body = (await c.req.json()) as Record<string, unknown>;
		const idx = templates.findIndex((t) => t.id === id);
		if (idx === -1) return c.json({ code: "NOT_FOUND", message: "Template not found" }, 404);
		templates[idx] = { ...templates[idx], ...body };
		return c.json(templates[idx]);
	});
	app.delete("/api/permissions/templates/:id", (c) => {
		const id = c.req.param("id");
		const idx = templates.findIndex((t) => t.id === id);
		if (idx !== -1) templates.splice(idx, 1);
		return c.body(null, 204);
	});

	// Agent permissions (compatibility route)
	app.get("/api/agents/:id/permissions", async (c) => {
		const agentId = c.req.param("id");
		try {
			const agent = await kavach.agent.get(agentId);
			if (!agent) return c.json([], 200);
			return c.json(agent.permissions ?? []);
		} catch {
			return c.json([]);
		}
	});

	// MCP servers (in-memory)
	const mcpServers: Array<Record<string, unknown>> = [];
	app.get("/api/mcp/servers", (c) => c.json(mcpServers));
	app.post("/api/mcp/servers", async (c) => {
		const body = (await c.req.json()) as Record<string, unknown>;
		const server = {
			id: crypto.randomUUID(),
			...body,
			status: "unknown",
			createdAt: new Date().toISOString(),
		};
		mcpServers.push(server);
		return c.json(server, 201);
	});

	// Settings
	// Settings (in-memory)
	let currentSettings = {
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 50, auditAll: true, tokenExpiry: "24h" },
		rateLimits: { requestsPerWindow: 100, windowSeconds: 300 },
		audit: { retentionDays: 90, maxAgentsPerTenant: 50 },
	};
	app.get("/api/settings", (c) => c.json(currentSettings));
	app.patch("/api/settings", async (c) => {
		const body = (await c.req.json()) as Record<string, unknown>;
		currentSettings = { ...currentSettings, ...body } as typeof currentSettings;
		return c.json(currentSettings);
	});

	// Auth + API routes
	app.route("/api", authRoute);
	app.route("/api", api);

	// 4. Serve dashboard static files
	const distDir = resolveDashboardDistDir();
	const apiUrl = `http://localhost:${port}/api`;
	const indexHtml = await patchIndexHtml(distDir, apiUrl);

	// Serve static assets or fall back to SPA index.html
	app.get("*", (c) => {
		const pathname = decodeURIComponent(new URL(c.req.url).pathname);

		// Try serving a static file if the path has an extension
		if (extname(pathname) !== "") {
			const filePath = resolve(join(distDir, pathname));
			const resolvedDist = resolve(distDir);

			// Security: ensure within distDir
			if (filePath.startsWith(`${resolvedDist}/`) && existsSync(filePath)) {
				const mime = MIME[extname(filePath).toLowerCase()] ?? "application/octet-stream";
				const stat = statSync(filePath);
				const body = readFileSync(filePath);
				return new Response(body, {
					status: 200,
					headers: {
						"Content-Type": mime,
						"Content-Length": String(stat.size),
						"Cache-Control": "public, max-age=31536000, immutable",
					},
				});
			}
		}

		// SPA fallback: patched index.html
		return c.html(indexHtml);
	});

	// 5. Start the server
	serve({ fetch: app.fetch, port }, () => {
		stdout.write("\n");
		stdout.write("  TheAuth Dashboard (demo mode)\n");
		stdout.write("  ==============================\n\n");
		stdout.write(`  Local:     http://localhost:${port}\n`);
		stdout.write(`  API:       ${apiUrl}\n`);
		stdout.write(`  Database:  in-memory SQLite\n\n`);
		stdout.write("  Press Ctrl+C to stop.\n\n");
	});
}
