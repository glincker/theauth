import type {
	AgentFilter,
	AuditFilter,
	CreateAgentInput,
	DelegateInput,
	Permission,
	TheAuth,
	UpdateAgentInput,
} from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import { Hono } from "hono";
import { z } from "zod";

// ─── Zod Validation Schemas ──────────────────────────────────────────────────

const PermissionConstraintsSchema = z.object({
	maxCallsPerHour: z.number().int().positive().optional(),
	allowedArgPatterns: z.array(z.string()).optional(),
	requireApproval: z.boolean().optional(),
	timeWindow: z
		.object({
			start: z.string(),
			end: z.string(),
		})
		.optional(),
	ipAllowlist: z.array(z.string()).optional(),
});

const PermissionSchema = z.object({
	resource: z.string().min(1),
	actions: z.array(z.string().min(1)).min(1),
	constraints: PermissionConstraintsSchema.optional(),
});

const CreateAgentSchema = z.object({
	ownerId: z.string().min(1),
	name: z.string().min(1),
	type: z.enum(["autonomous", "delegated", "service"]),
	permissions: z.array(PermissionSchema).min(1),
	expiresAt: z.coerce.date().optional(),
	metadata: z.record(z.unknown()).optional(),
});

const UpdateAgentSchema = z.object({
	name: z.string().min(1).optional(),
	permissions: z.array(PermissionSchema).optional(),
	expiresAt: z.coerce.date().optional(),
	metadata: z.record(z.unknown()).optional(),
});

const AuthorizeSchema = z.object({
	agentId: z.string().min(1),
	action: z.string().min(1),
	resource: z.string().min(1),
	arguments: z.record(z.unknown()).optional(),
});

const AuthorizeByTokenSchema = z.object({
	action: z.string().min(1),
	resource: z.string().min(1),
	arguments: z.record(z.unknown()).optional(),
});

const DelegateSchema = z.object({
	fromAgent: z.string().min(1),
	toAgent: z.string().min(1),
	permissions: z.array(PermissionSchema).min(1),
	expiresAt: z.coerce.date(),
	maxDepth: z.number().int().positive().optional(),
});

// ─── Response Helpers ────────────────────────────────────────────────────────

function ok<T>(data: T, status = 200) {
	return new Response(JSON.stringify({ data }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function created<T>(data: T) {
	return ok(data, 201);
}

function errorResponse(code: string, message: string, status: number) {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function badRequest(message: string) {
	return errorResponse("BAD_REQUEST", message, 400);
}

function unauthorized(message = "Unauthorized") {
	return errorResponse("UNAUTHORIZED", message, 401);
}

function notFound(message = "Not found") {
	return errorResponse("NOT_FOUND", message, 404);
}

function internalError(message = "Internal server error") {
	return errorResponse("INTERNAL_ERROR", message, 500);
}

function validationError(issues: z.ZodIssue[]) {
	const message = issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ");
	return badRequest(`Validation failed: ${message}`);
}

// ─── MCP CORS Headers ────────────────────────────────────────────────────────

const MCP_CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization",
	"Access-Control-Max-Age": "86400",
};

function mcpOk<T>(data: T, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json", ...MCP_CORS_HEADERS },
	});
}

function mcpError(code: string, message: string, status: number) {
	return new Response(JSON.stringify({ error: code, error_description: message }), {
		status,
		headers: { "Content-Type": "application/json", ...MCP_CORS_HEADERS },
	});
}

function mcpNoStore<T>(data: T, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			...MCP_CORS_HEADERS,
		},
	});
}

// ─── Adapter Factory ─────────────────────────────────────────────────────────

/**
 * Create a Hono app with all TheAuth REST API routes mounted.
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { kavachHono } from '@glinr/theauth-hono';
 * import { serve } from '@hono/node-server';
 *
 * const kavach = createTheAuth({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const app = kavachHono(kavach);
 * serve({ fetch: app.fetch, port: 3000 });
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * const app = kavachHono(kavach, { mcp });
 * ```
 */
export function kavachHono(kavach: TheAuth, options?: { mcp?: McpAuthModule }): Hono {
	const app = new Hono();
	const mcp = options?.mcp;

	// ── Agent REST API ──────────────────────────────────────────────

	// POST /agents - create agent
	app.post("/agents", async (c) => {
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			const res = badRequest("Invalid JSON body");
			return c.newResponse(res.body, res);
		}
		const parsed = CreateAgentSchema.safeParse(body);
		if (!parsed.success) {
			const res = validationError(parsed.error.issues);
			return c.newResponse(res.body, res);
		}
		try {
			const input: CreateAgentInput = {
				...parsed.data,
				permissions: parsed.data.permissions as Permission[],
			};
			const agent = await kavach.agent.create(input);
			const res = created(agent);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to create agent";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// GET /agents - list agents
	app.get("/agents", async (c) => {
		const userId = c.req.query("userId");
		const statusRaw = c.req.query("status");
		const typeRaw = c.req.query("type");

		const filter: AgentFilter = {};
		if (userId) filter.userId = userId;
		if (statusRaw === "active" || statusRaw === "revoked" || statusRaw === "expired") {
			filter.status = statusRaw;
		}
		if (typeRaw === "autonomous" || typeRaw === "delegated" || typeRaw === "service") {
			filter.type = typeRaw;
		}

		try {
			const agents = await kavach.agent.list(filter);
			const res = ok(agents);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to list agents";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// GET /agents/:id - get agent
	app.get("/agents/:id", async (c) => {
		const id = c.req.param("id");
		try {
			const agent = await kavach.agent.get(id);
			if (!agent) {
				const res = notFound(`Agent "${id}" not found`);
				return c.newResponse(res.body, res);
			}
			const res = ok(agent);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to get agent";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// PATCH /agents/:id - update agent
	app.patch("/agents/:id", async (c) => {
		const id = c.req.param("id");
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			const res = badRequest("Invalid JSON body");
			return c.newResponse(res.body, res);
		}
		const parsed = UpdateAgentSchema.safeParse(body);
		if (!parsed.success) {
			const res = validationError(parsed.error.issues);
			return c.newResponse(res.body, res);
		}
		try {
			const input: UpdateAgentInput = {
				...parsed.data,
				permissions: parsed.data.permissions as Permission[] | undefined,
			};
			const agent = await kavach.agent.update(id, input);
			const res = ok(agent);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to update agent";
			if (message.includes("not found")) {
				const res = notFound(message);
				return c.newResponse(res.body, res);
			}
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// DELETE /agents/:id - revoke agent
	app.delete("/agents/:id", async (c) => {
		const id = c.req.param("id");
		try {
			await kavach.agent.revoke(id);
			return new Response(null, { status: 204 });
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to revoke agent";
			if (message.includes("not found")) {
				const res = notFound(message);
				return c.newResponse(res.body, res);
			}
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// POST /agents/:id/rotate - rotate token
	app.post("/agents/:id/rotate", async (c) => {
		const id = c.req.param("id");
		try {
			const agent = await kavach.agent.rotate(id);
			const res = ok(agent);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to rotate agent token";
			if (message.includes("not found")) {
				const res = notFound(message);
				return c.newResponse(res.body, res);
			}
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── Authorization ───────────────────────────────────────────────

	// POST /authorize - authorize action by agentId
	app.post("/authorize", async (c) => {
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			const res = badRequest("Invalid JSON body");
			return c.newResponse(res.body, res);
		}
		const parsed = AuthorizeSchema.safeParse(body);
		if (!parsed.success) {
			const res = validationError(parsed.error.issues);
			return c.newResponse(res.body, res);
		}
		try {
			const ip =
				c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
				c.req.header("x-real-ip") ??
				undefined;
			const userAgent = c.req.header("user-agent") ?? undefined;
			const result = await kavach.authorize(
				parsed.data.agentId,
				{
					action: parsed.data.action,
					resource: parsed.data.resource,
					arguments: parsed.data.arguments,
				},
				{ ip, userAgent },
			);
			const status = result.allowed ? 200 : 403;
			const res = new Response(JSON.stringify({ data: result }), {
				status,
				headers: { "Content-Type": "application/json" },
			});
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Authorization check failed";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// POST /authorize/token - authorize by bearer token
	app.post("/authorize/token", async (c) => {
		const authHeader = c.req.header("Authorization");
		if (!authHeader?.startsWith("Bearer ")) {
			const res = unauthorized("Missing or invalid Authorization header");
			return c.newResponse(res.body, res);
		}
		const token = authHeader.slice(7);

		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			const res = badRequest("Invalid JSON body");
			return c.newResponse(res.body, res);
		}
		const parsed = AuthorizeByTokenSchema.safeParse(body);
		if (!parsed.success) {
			const res = validationError(parsed.error.issues);
			return c.newResponse(res.body, res);
		}
		try {
			const ip =
				c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
				c.req.header("x-real-ip") ??
				undefined;
			const userAgent = c.req.header("user-agent") ?? undefined;
			const result = await kavach.authorizeByToken(
				token,
				{
					action: parsed.data.action,
					resource: parsed.data.resource,
					arguments: parsed.data.arguments,
				},
				{ ip, userAgent },
			);
			const status = result.allowed ? 200 : 403;
			const res = new Response(JSON.stringify({ data: result }), {
				status,
				headers: { "Content-Type": "application/json" },
			});
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Authorization check failed";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── Delegation ──────────────────────────────────────────────────

	// POST /delegations - create delegation
	app.post("/delegations", async (c) => {
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			const res = badRequest("Invalid JSON body");
			return c.newResponse(res.body, res);
		}
		const parsed = DelegateSchema.safeParse(body);
		if (!parsed.success) {
			const res = validationError(parsed.error.issues);
			return c.newResponse(res.body, res);
		}
		try {
			const input: DelegateInput = {
				...parsed.data,
				permissions: parsed.data.permissions as Permission[],
			};
			const chain = await kavach.delegate(input);
			const res = created(chain);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to create delegation";
			if (message.includes("not found")) {
				const res = notFound(message);
				return c.newResponse(res.body, res);
			}
			if (message.includes("exceeds") || message.includes("depth")) {
				const res = badRequest(message);
				return c.newResponse(res.body, res);
			}
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// DELETE /delegations/:id - revoke delegation
	app.delete("/delegations/:id", async (c) => {
		const id = c.req.param("id");
		try {
			await kavach.delegation.revoke(id);
			return new Response(null, { status: 204 });
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to revoke delegation";
			if (message.includes("not found")) {
				const res = notFound(message);
				return c.newResponse(res.body, res);
			}
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// GET /delegations/:agentId - list chains for agent
	app.get("/delegations/:agentId", async (c) => {
		const agentId = c.req.param("agentId");
		try {
			const chains = await kavach.delegation.listChains(agentId);
			const res = ok(chains);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to list delegation chains";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── Audit ───────────────────────────────────────────────────────

	// GET /audit - query audit logs
	app.get("/audit", async (c) => {
		const filter: AuditFilter = {};

		const agentId = c.req.query("agentId");
		const userId = c.req.query("userId");
		const since = c.req.query("since");
		const until = c.req.query("until");
		const actions = c.req.query("actions");
		const resultRaw = c.req.query("result");
		const limit = c.req.query("limit");
		const offset = c.req.query("offset");

		if (agentId) filter.agentId = agentId;
		if (userId) filter.userId = userId;
		if (since) {
			const d = new Date(since);
			if (!Number.isNaN(d.getTime())) filter.since = d;
		}
		if (until) {
			const d = new Date(until);
			if (!Number.isNaN(d.getTime())) filter.until = d;
		}
		if (actions) filter.actions = actions.split(",").map((a) => a.trim());
		if (resultRaw === "allowed" || resultRaw === "denied" || resultRaw === "rate_limited") {
			filter.result = resultRaw;
		}
		if (limit) {
			const n = Number.parseInt(limit, 10);
			if (!Number.isNaN(n) && n > 0) filter.limit = n;
		}
		if (offset) {
			const n = Number.parseInt(offset, 10);
			if (!Number.isNaN(n) && n >= 0) filter.offset = n;
		}

		try {
			const entries = await kavach.audit.query(filter);
			const res = ok(entries);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to query audit logs";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// GET /audit/export - export audit logs
	app.get("/audit/export", async (c) => {
		const format = c.req.query("format") ?? "json";
		if (format !== "json" && format !== "csv") {
			const res = badRequest('format must be "json" or "csv"');
			return c.newResponse(res.body, res);
		}

		const since = c.req.query("since");
		const until = c.req.query("until");

		const options: { format: "json" | "csv"; since?: Date; until?: Date } = { format };
		if (since) {
			const d = new Date(since);
			if (!Number.isNaN(d.getTime())) options.since = d;
		}
		if (until) {
			const d = new Date(until);
			if (!Number.isNaN(d.getTime())) options.until = d;
		}

		try {
			const exported = await kavach.audit.export(options);
			const contentType = format === "csv" ? "text/csv" : "application/json";
			return new Response(exported, {
				status: 200,
				headers: {
					"Content-Type": contentType,
					"Content-Disposition": `attachment; filename="audit-export.${format}"`,
				},
			});
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to export audit logs";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── MCP OAuth 2.1 Endpoints ─────────────────────────────────────

	// OPTIONS preflight for MCP routes
	app.options("/mcp/*", (_c) => {
		return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
	});

	app.options("/.well-known/*", (_c) => {
		return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
	});

	// GET /.well-known/oauth-authorization-server
	app.get("/.well-known/oauth-authorization-server", (c) => {
		if (!mcp) {
			const res = notFound("MCP module not configured");
			return c.newResponse(res.body, res);
		}
		const metadata = mcp.getMetadata();
		return c.newResponse(mcpOk(metadata).body, mcpOk(metadata));
	});

	// GET /.well-known/oauth-protected-resource
	app.get("/.well-known/oauth-protected-resource", (c) => {
		if (!mcp) {
			const res = notFound("MCP module not configured");
			return c.newResponse(res.body, res);
		}
		const metadata = mcp.getProtectedResourceMetadata();
		return c.newResponse(mcpOk(metadata).body, mcpOk(metadata));
	});

	// POST /mcp/register - dynamic client registration
	app.post("/mcp/register", async (c) => {
		if (!mcp) {
			const res = notFound("MCP module not configured");
			return c.newResponse(res.body, res);
		}
		let body: unknown;
		try {
			body = await c.req.json();
		} catch {
			const res = mcpError("invalid_request", "Invalid JSON body", 400);
			return c.newResponse(res.body, res);
		}
		try {
			const result = await mcp.registerClient(body as Parameters<typeof mcp.registerClient>[0]);
			if (!result.success) {
				const res = mcpError("invalid_client_metadata", result.error.message, 400);
				return c.newResponse(res.body, res);
			}
			const res = mcpNoStore(result.data, 201);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Registration failed";
			const res = mcpError("server_error", message, 500);
			return c.newResponse(res.body, res);
		}
	});

	// GET /mcp/authorize - authorization endpoint
	app.get("/mcp/authorize", async (c) => {
		if (!mcp) {
			const res = notFound("MCP module not configured");
			return c.newResponse(res.body, res);
		}
		try {
			const result = await mcp.authorize(c.req.raw);
			if (!result.success) {
				if (result.error.code === "LOGIN_REQUIRED") {
					const details = result.error.details as
						| { loginPage?: string; returnTo?: string }
						| undefined;
					if (details?.loginPage) {
						const loginUrl = new URL(details.loginPage);
						if (details.returnTo) {
							loginUrl.searchParams.set("returnTo", details.returnTo);
						}
						return c.redirect(loginUrl.toString(), 302);
					}
				}
				const res = mcpError(result.error.code.toLowerCase(), result.error.message, 400);
				return c.newResponse(res.body, res);
			}
			return c.redirect(result.data.redirectUri, 302);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Authorization failed";
			const res = mcpError("server_error", message, 500);
			return c.newResponse(res.body, res);
		}
	});

	// POST /mcp/token - token endpoint
	app.post("/mcp/token", async (c) => {
		if (!mcp) {
			const res = notFound("MCP module not configured");
			return c.newResponse(res.body, res);
		}
		try {
			const result = await mcp.token(c.req.raw);
			if (!result.success) {
				const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
				const res = mcpNoStore(
					{
						error: result.error.code.toLowerCase(),
						error_description: result.error.message,
					},
					status,
				);
				return c.newResponse(res.body, res);
			}
			const successRes = mcpNoStore(result.data);
			return c.newResponse(successRes.body, successRes);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Token exchange failed";
			const res = mcpNoStore({ error: "server_error", error_description: message }, 500);
			return c.newResponse(res.body, res);
		}
	});

	// ── Dashboard API ───────────────────────────────────────────────

	// GET /dashboard/stats
	app.get("/dashboard/stats", async (c) => {
		try {
			const [agents, recentAudit] = await Promise.all([
				kavach.agent.list(),
				kavach.audit.query({
					since: new Date(Date.now() - 24 * 60 * 60 * 1000),
					limit: 1000,
				}),
			]);

			const ownerIds = new Set(agents.map((a) => a.ownerId));
			const activeAgents = agents.filter((a) => a.status === "active");
			const revokedAgents = agents.filter((a) => a.status === "revoked");
			const expiredAgents = agents.filter((a) => a.status === "expired");

			const stats = {
				agents: {
					total: agents.length,
					active: activeAgents.length,
					revoked: revokedAgents.length,
					expired: expiredAgents.length,
				},
				users: {
					total: ownerIds.size,
				},
				audit: {
					last24h: recentAudit.length,
					allowed: recentAudit.filter((e) => e.result === "allowed").length,
					denied: recentAudit.filter((e) => e.result === "denied").length,
					rateLimited: recentAudit.filter((e) => e.result === "rate_limited").length,
				},
			};
			const res = ok(stats);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to fetch dashboard stats";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// GET /dashboard/agents - agents with stats
	app.get("/dashboard/agents", async (c) => {
		const userId = c.req.query("userId");
		const statusRaw = c.req.query("status");
		const typeRaw = c.req.query("type");

		const filter: AgentFilter = {};
		if (userId) filter.userId = userId;
		if (statusRaw === "active" || statusRaw === "revoked" || statusRaw === "expired") {
			filter.status = statusRaw;
		}
		if (typeRaw === "autonomous" || typeRaw === "delegated" || typeRaw === "service") {
			filter.type = typeRaw;
		}

		try {
			const agents = await kavach.agent.list(filter);
			const res = ok(agents);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to list agents";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// GET /dashboard/audit - same as GET /audit
	app.get("/dashboard/audit", async (c) => {
		const filter: AuditFilter = {};

		const agentId = c.req.query("agentId");
		const userId = c.req.query("userId");
		const since = c.req.query("since");
		const until = c.req.query("until");
		const actions = c.req.query("actions");
		const resultRaw = c.req.query("result");
		const limit = c.req.query("limit");
		const offset = c.req.query("offset");

		if (agentId) filter.agentId = agentId;
		if (userId) filter.userId = userId;
		if (since) {
			const d = new Date(since);
			if (!Number.isNaN(d.getTime())) filter.since = d;
		}
		if (until) {
			const d = new Date(until);
			if (!Number.isNaN(d.getTime())) filter.until = d;
		}
		if (actions) filter.actions = actions.split(",").map((a) => a.trim());
		if (resultRaw === "allowed" || resultRaw === "denied" || resultRaw === "rate_limited") {
			filter.result = resultRaw;
		}
		if (limit) {
			const n = Number.parseInt(limit, 10);
			if (!Number.isNaN(n) && n > 0) filter.limit = n;
		}
		if (offset) {
			const n = Number.parseInt(offset, 10);
			if (!Number.isNaN(n) && n >= 0) filter.offset = n;
		}

		try {
			const entries = await kavach.audit.query(filter);
			const res = ok(entries);
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Failed to query audit logs";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── Password Reset ──────────────────────────────────────────────

	// POST /auth/forgot-password - request a reset link
	app.post("/auth/forgot-password", async (c) => {
		if (!kavach.passwordReset) {
			const res = notFound("Password reset not configured");
			return c.newResponse(res.body, res);
		}
		try {
			const response = await kavach.passwordReset.handleRequest(c.req.raw);
			if (response) return c.newResponse(response.body, response);
			const res = notFound("Not found");
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Password reset request failed";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// POST /auth/reset-password - confirm a reset with token + new password
	app.post("/auth/reset-password", async (c) => {
		if (!kavach.passwordReset) {
			const res = notFound("Password reset not configured");
			return c.newResponse(res.body, res);
		}
		try {
			const response = await kavach.passwordReset.handleRequest(c.req.raw);
			if (response) return c.newResponse(response.body, response);
			const res = notFound("Not found");
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Password reset failed";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── Email Verification ──────────────────────────────────────────

	// POST /auth/verify-email/send - send a verification email
	app.post("/auth/verify-email/send", async (c) => {
		if (!kavach.emailVerification) {
			const res = notFound("Email verification not configured");
			return c.newResponse(res.body, res);
		}
		try {
			const response = await kavach.emailVerification.handleRequest(c.req.raw);
			if (response) return c.newResponse(response.body, response);
			const res = notFound("Not found");
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Email verification send failed";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// POST /auth/verify-email/confirm - confirm with token
	app.post("/auth/verify-email/confirm", async (c) => {
		if (!kavach.emailVerification) {
			const res = notFound("Email verification not configured");
			return c.newResponse(res.body, res);
		}
		try {
			const response = await kavach.emailVerification.handleRequest(c.req.raw);
			if (response) return c.newResponse(response.body, response);
			const res = notFound("Not found");
			return c.newResponse(res.body, res);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Email verification confirm failed";
			const res = internalError(message);
			return c.newResponse(res.body, res);
		}
	});

	// ── Plugin Endpoints ────────────────────────────────────────────

	for (const endpoint of kavach.plugins.getEndpoints()) {
		const method = endpoint.method.toLowerCase() as "get" | "post" | "put" | "patch" | "delete";
		app[method](endpoint.path, async (c) => {
			const response = await kavach.plugins.handleRequest(c.req.raw);
			return c.newResponse(response?.body ?? null, response ?? new Response(null, { status: 404 }));
		});
	}

	return app;
}
