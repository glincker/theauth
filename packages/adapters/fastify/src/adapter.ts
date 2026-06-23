import type {
	AgentFilter,
	AuditFilter,
	CreateAgentInput,
	DelegateInput,
	Kavach,
	Permission,
	UpdateAgentInput,
} from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
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

function sendOk<T>(reply: FastifyReply, data: T, status = 200): FastifyReply {
	return reply.status(status).header("Content-Type", "application/json").send({ data });
}

function sendCreated<T>(reply: FastifyReply, data: T): FastifyReply {
	return sendOk(reply, data, 201);
}

function sendError(
	reply: FastifyReply,
	code: string,
	message: string,
	status: number,
): FastifyReply {
	return reply
		.status(status)
		.header("Content-Type", "application/json")
		.send({ error: { code, message } });
}

function sendBadRequest(reply: FastifyReply, message: string): FastifyReply {
	return sendError(reply, "BAD_REQUEST", message, 400);
}

function sendUnauthorized(reply: FastifyReply, message = "Unauthorized"): FastifyReply {
	return sendError(reply, "UNAUTHORIZED", message, 401);
}

function sendNotFound(reply: FastifyReply, message = "Not found"): FastifyReply {
	return sendError(reply, "NOT_FOUND", message, 404);
}

function sendInternalError(reply: FastifyReply, message = "Internal server error"): FastifyReply {
	return sendError(reply, "INTERNAL_ERROR", message, 500);
}

function sendValidationError(reply: FastifyReply, issues: z.ZodIssue[]): FastifyReply {
	const message = issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ");
	return sendBadRequest(reply, `Validation failed: ${message}`);
}

// ─── MCP CORS Headers ────────────────────────────────────────────────────────

const MCP_CORS_HEADERS: Record<string, string> = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization",
	"Access-Control-Max-Age": "86400",
};

function applyMcpCors(reply: FastifyReply): FastifyReply {
	for (const [key, value] of Object.entries(MCP_CORS_HEADERS)) {
		reply.header(key, value);
	}
	return reply;
}

function sendMcpOk<T>(reply: FastifyReply, data: T, status = 200): FastifyReply {
	return applyMcpCors(reply).status(status).header("Content-Type", "application/json").send(data);
}

function sendMcpError(
	reply: FastifyReply,
	code: string,
	message: string,
	status: number,
): FastifyReply {
	return applyMcpCors(reply)
		.status(status)
		.header("Content-Type", "application/json")
		.send({ error: code, error_description: message });
}

function sendMcpNoStore<T>(reply: FastifyReply, data: T, status = 200): FastifyReply {
	return applyMcpCors(reply)
		.status(status)
		.header("Content-Type", "application/json")
		.header("Cache-Control", "no-store")
		.header("Pragma", "no-cache")
		.send(data);
}

// ─── Audit Filter Builder ────────────────────────────────────────────────────

function buildAuditFilter(query: FastifyRequest["query"]): AuditFilter {
	const q = query as Record<string, string | undefined>;
	const filter: AuditFilter = {};

	if (q.agentId) filter.agentId = q.agentId;
	if (q.userId) filter.userId = q.userId;

	if (q.since) {
		const d = new Date(q.since);
		if (!Number.isNaN(d.getTime())) filter.since = d;
	}
	if (q.until) {
		const d = new Date(q.until);
		if (!Number.isNaN(d.getTime())) filter.until = d;
	}
	if (q.actions) {
		filter.actions = q.actions.split(",").map((a) => a.trim());
	}
	const resultRaw = q.result;
	if (resultRaw === "allowed" || resultRaw === "denied" || resultRaw === "rate_limited") {
		filter.result = resultRaw;
	}
	if (q.limit) {
		const n = Number.parseInt(q.limit, 10);
		if (!Number.isNaN(n) && n > 0) filter.limit = n;
	}
	if (q.offset) {
		const n = Number.parseInt(q.offset, 10);
		if (!Number.isNaN(n) && n >= 0) filter.offset = n;
	}

	return filter;
}

// ─── Adapter Options ─────────────────────────────────────────────────────────

export interface AuthFastifyOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * URL prefix to mount all routes under. Defaults to no prefix (routes are
	 * registered directly on the provided FastifyInstance).
	 *
	 * Use Fastify's built-in prefix option when calling `fastify.register` instead:
	 * `fastify.register(plugin, { prefix: '/api/kavach' })`
	 */
}

/** @deprecated Use {@link AuthFastifyOptions} instead. Will be removed in v3.0. */
export type KavachFastifyOptions = AuthFastifyOptions;

// ─── Adapter Factory ─────────────────────────────────────────────────────────

/**
 * Create a Fastify plugin that registers all TheAuth REST API routes.
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { createKavach } from '@glinr/theauth';
 * import { kavachFastify } from '@glinr/theauth-fastify';
 *
 * const app = Fastify();
 * const kavach = createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 *
 * await app.register(kavachFastify(kavach), { prefix: '/api/kavach' });
 * await app.listen({ port: 3000 });
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * await app.register(kavachFastify(kavach, { mcp }), { prefix: '/api/kavach' });
 * ```
 */
export function authFastify(kavach: Kavach, options?: AuthFastifyOptions) {
	const mcp = options?.mcp;

	return async function plugin(fastify: FastifyInstance): Promise<void> {
		// ── MCP OPTIONS preflight ────────────────────────────────────

		fastify.options("/mcp/*", (_request, reply) => {
			return reply.status(204).headers(MCP_CORS_HEADERS).send();
		});

		fastify.options("/.well-known/*", (_request, reply) => {
			return reply.status(204).headers(MCP_CORS_HEADERS).send();
		});

		// ── Agent REST API ───────────────────────────────────────────

		// POST /agents
		fastify.post("/agents", async (request, reply) => {
			const parsed = CreateAgentSchema.safeParse(request.body);
			if (!parsed.success) return sendValidationError(reply, parsed.error.issues);

			try {
				const input: CreateAgentInput = {
					...parsed.data,
					permissions: parsed.data.permissions as Permission[],
				};
				const agent = await kavach.agent.create(input);
				return sendCreated(reply, agent);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to create agent";
				return sendInternalError(reply, message);
			}
		});

		// GET /agents
		fastify.get("/agents", async (request, reply) => {
			const q = request.query as Record<string, string | undefined>;
			const filter: AgentFilter = {};

			if (q.userId) filter.userId = q.userId;
			const statusRaw = q.status;
			if (statusRaw === "active" || statusRaw === "revoked" || statusRaw === "expired") {
				filter.status = statusRaw;
			}
			const typeRaw = q.type;
			if (typeRaw === "autonomous" || typeRaw === "delegated" || typeRaw === "service") {
				filter.type = typeRaw;
			}

			try {
				const agents = await kavach.agent.list(filter);
				return sendOk(reply, agents);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to list agents";
				return sendInternalError(reply, message);
			}
		});

		// GET /agents/:id
		fastify.get<{ Params: { id: string } }>("/agents/:id", async (request, reply) => {
			const { id } = request.params;
			try {
				const agent = await kavach.agent.get(id);
				if (!agent) return sendNotFound(reply, `Agent "${id}" not found`);
				return sendOk(reply, agent);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to get agent";
				return sendInternalError(reply, message);
			}
		});

		// PATCH /agents/:id
		fastify.patch<{ Params: { id: string } }>("/agents/:id", async (request, reply) => {
			const { id } = request.params;
			const parsed = UpdateAgentSchema.safeParse(request.body);
			if (!parsed.success) return sendValidationError(reply, parsed.error.issues);

			try {
				const input: UpdateAgentInput = {
					...parsed.data,
					permissions: parsed.data.permissions as Permission[] | undefined,
				};
				const agent = await kavach.agent.update(id, input);
				return sendOk(reply, agent);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to update agent";
				if (message.includes("not found")) return sendNotFound(reply, message);
				return sendInternalError(reply, message);
			}
		});

		// DELETE /agents/:id
		fastify.delete<{ Params: { id: string } }>("/agents/:id", async (request, reply) => {
			const { id } = request.params;
			try {
				await kavach.agent.revoke(id);
				return reply.status(204).send();
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to revoke agent";
				if (message.includes("not found")) return sendNotFound(reply, message);
				return sendInternalError(reply, message);
			}
		});

		// POST /agents/:id/rotate
		fastify.post<{ Params: { id: string } }>("/agents/:id/rotate", async (request, reply) => {
			const { id } = request.params;
			try {
				const agent = await kavach.agent.rotate(id);
				return sendOk(reply, agent);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to rotate agent token";
				if (message.includes("not found")) return sendNotFound(reply, message);
				return sendInternalError(reply, message);
			}
		});

		// ── Authorization ────────────────────────────────────────────

		// POST /authorize
		fastify.post("/authorize", async (request, reply) => {
			const parsed = AuthorizeSchema.safeParse(request.body);
			if (!parsed.success) return sendValidationError(reply, parsed.error.issues);

			try {
				const xForwardedFor = request.headers["x-forwarded-for"];
				const ip =
					(Array.isArray(xForwardedFor)
						? xForwardedFor[0]
						: xForwardedFor?.split(",")[0]?.trim()) ??
					request.ip ??
					undefined;
				const userAgent =
					(Array.isArray(request.headers["user-agent"])
						? request.headers["user-agent"][0]
						: request.headers["user-agent"]) ?? undefined;
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
				return reply
					.status(status)
					.header("Content-Type", "application/json")
					.send({ data: result });
			} catch (err) {
				const message = err instanceof Error ? err.message : "Authorization check failed";
				return sendInternalError(reply, message);
			}
		});

		// POST /authorize/token
		fastify.post("/authorize/token", async (request, reply) => {
			const authHeader = request.headers.authorization;
			if (!authHeader?.startsWith("Bearer ")) {
				return sendUnauthorized(reply, "Missing or invalid Authorization header");
			}
			const token = authHeader.slice(7);

			const parsed = AuthorizeByTokenSchema.safeParse(request.body);
			if (!parsed.success) return sendValidationError(reply, parsed.error.issues);

			try {
				const xForwardedFor = request.headers["x-forwarded-for"];
				const ip =
					(Array.isArray(xForwardedFor)
						? xForwardedFor[0]
						: xForwardedFor?.split(",")[0]?.trim()) ??
					request.ip ??
					undefined;
				const userAgent =
					(Array.isArray(request.headers["user-agent"])
						? request.headers["user-agent"][0]
						: request.headers["user-agent"]) ?? undefined;
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
				return reply
					.status(status)
					.header("Content-Type", "application/json")
					.send({ data: result });
			} catch (err) {
				const message = err instanceof Error ? err.message : "Authorization check failed";
				return sendInternalError(reply, message);
			}
		});

		// ── Delegation ───────────────────────────────────────────────

		// POST /delegations
		fastify.post("/delegations", async (request, reply) => {
			const parsed = DelegateSchema.safeParse(request.body);
			if (!parsed.success) return sendValidationError(reply, parsed.error.issues);

			try {
				const input: DelegateInput = {
					...parsed.data,
					permissions: parsed.data.permissions as Permission[],
				};
				const chain = await kavach.delegate(input);
				return sendCreated(reply, chain);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to create delegation";
				if (message.includes("not found")) return sendNotFound(reply, message);
				if (message.includes("exceeds") || message.includes("depth"))
					return sendBadRequest(reply, message);
				return sendInternalError(reply, message);
			}
		});

		// DELETE /delegations/:id
		fastify.delete<{ Params: { id: string } }>("/delegations/:id", async (request, reply) => {
			const { id } = request.params;
			try {
				await kavach.delegation.revoke(id);
				return reply.status(204).send();
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to revoke delegation";
				if (message.includes("not found")) return sendNotFound(reply, message);
				return sendInternalError(reply, message);
			}
		});

		// GET /delegations/:agentId
		fastify.get<{ Params: { agentId: string } }>(
			"/delegations/:agentId",
			async (request, reply) => {
				const { agentId } = request.params;
				try {
					const chains = await kavach.delegation.listChains(agentId);
					return sendOk(reply, chains);
				} catch (err) {
					const message = err instanceof Error ? err.message : "Failed to list delegation chains";
					return sendInternalError(reply, message);
				}
			},
		);

		// ── Audit ─────────────────────────────────────────────────────

		// GET /audit/export — must be registered before /audit to avoid route shadowing
		fastify.get("/audit/export", async (request, reply) => {
			const q = request.query as Record<string, string | undefined>;
			const format = q.format ?? "json";
			if (format !== "json" && format !== "csv") {
				return sendBadRequest(reply, 'format must be "json" or "csv"');
			}

			const options: { format: "json" | "csv"; since?: Date; until?: Date } = { format };
			if (q.since) {
				const d = new Date(q.since);
				if (!Number.isNaN(d.getTime())) options.since = d;
			}
			if (q.until) {
				const d = new Date(q.until);
				if (!Number.isNaN(d.getTime())) options.until = d;
			}

			try {
				const exported = await kavach.audit.export(options);
				const contentType = format === "csv" ? "text/csv" : "application/json";
				return reply
					.status(200)
					.header("Content-Type", contentType)
					.header("Content-Disposition", `attachment; filename="audit-export.${format}"`)
					.send(exported);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to export audit logs";
				return sendInternalError(reply, message);
			}
		});

		// GET /audit
		fastify.get("/audit", async (request, reply) => {
			const filter = buildAuditFilter(request.query);
			try {
				const entries = await kavach.audit.query(filter);
				return sendOk(reply, entries);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to query audit logs";
				return sendInternalError(reply, message);
			}
		});

		// ── Dashboard API ────────────────────────────────────────────

		// GET /dashboard/stats
		fastify.get("/dashboard/stats", async (_request, reply) => {
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
				return sendOk(reply, stats);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to fetch dashboard stats";
				return sendInternalError(reply, message);
			}
		});

		// GET /dashboard/agents
		fastify.get("/dashboard/agents", async (request, reply) => {
			const q = request.query as Record<string, string | undefined>;
			const filter: AgentFilter = {};

			if (q.userId) filter.userId = q.userId;
			const statusRaw = q.status;
			if (statusRaw === "active" || statusRaw === "revoked" || statusRaw === "expired") {
				filter.status = statusRaw;
			}
			const typeRaw = q.type;
			if (typeRaw === "autonomous" || typeRaw === "delegated" || typeRaw === "service") {
				filter.type = typeRaw;
			}

			try {
				const agents = await kavach.agent.list(filter);
				return sendOk(reply, agents);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to list agents";
				return sendInternalError(reply, message);
			}
		});

		// GET /dashboard/audit
		fastify.get("/dashboard/audit", async (request, reply) => {
			const filter = buildAuditFilter(request.query);
			try {
				const entries = await kavach.audit.query(filter);
				return sendOk(reply, entries);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Failed to query audit logs";
				return sendInternalError(reply, message);
			}
		});

		// ── MCP OAuth 2.1 Endpoints ──────────────────────────────────

		// GET /.well-known/oauth-authorization-server
		fastify.get("/.well-known/oauth-authorization-server", (_request, reply) => {
			if (!mcp) return sendNotFound(reply, "MCP module not configured");
			const metadata = mcp.getMetadata();
			return sendMcpOk(reply, metadata);
		});

		// GET /.well-known/oauth-protected-resource
		fastify.get("/.well-known/oauth-protected-resource", (_request, reply) => {
			if (!mcp) return sendNotFound(reply, "MCP module not configured");
			const metadata = mcp.getProtectedResourceMetadata();
			return sendMcpOk(reply, metadata);
		});

		// POST /mcp/register
		fastify.post("/mcp/register", async (request, reply) => {
			if (!mcp) return sendNotFound(reply, "MCP module not configured");
			try {
				const result = await mcp.registerClient(
					request.body as Parameters<typeof mcp.registerClient>[0],
				);
				if (!result.success) {
					return sendMcpError(reply, "invalid_client_metadata", result.error.message, 400);
				}
				return sendMcpNoStore(reply, result.data, 201);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Registration failed";
				return sendMcpError(reply, "server_error", message, 500);
			}
		});

		// GET /mcp/authorize
		fastify.get("/mcp/authorize", async (request, reply) => {
			if (!mcp) return sendNotFound(reply, "MCP module not configured");
			try {
				// Build a Web API Request from the Fastify request for MCP module compatibility
				const url = `${request.protocol}://${request.hostname}${request.url}`;
				const webRequest = new Request(url, {
					method: "GET",
					headers: request.headers as HeadersInit,
				});
				const result = await mcp.authorize(webRequest);
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
							return reply.redirect(loginUrl.toString(), 302);
						}
					}
					return sendMcpError(reply, result.error.code.toLowerCase(), result.error.message, 400);
				}
				return reply.redirect(result.data.redirectUri, 302);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Authorization failed";
				return sendMcpError(reply, "server_error", message, 500);
			}
		});

		// ── Plugin Endpoints ─────────────────────────────────────────

		for (const endpoint of kavach.plugins.getEndpoints()) {
			const method = endpoint.method.toLowerCase() as "get" | "post" | "put" | "patch" | "delete";
			fastify[method](endpoint.path, async (request, reply) => {
				const url = `${request.protocol}://${request.hostname}${request.url}`;
				const headers = new Headers(request.headers as Record<string, string>);
				const hasBody = request.method !== "GET" && request.method !== "HEAD";
				const body =
					hasBody && request.body !== undefined ? JSON.stringify(request.body) : undefined;
				const webReq = new Request(url, { method: request.method, headers, body });

				const response = await kavach.plugins.handleRequest(webReq);
				if (!response) {
					return sendNotFound(reply, "Plugin endpoint not found");
				}

				reply.status(response.status);
				response.headers.forEach((value, key) => {
					reply.header(key, value);
				});
				const text = await response.text();
				return reply.send(text);
			});
		}

		// POST /mcp/token
		fastify.post("/mcp/token", async (request, reply) => {
			if (!mcp) return sendNotFound(reply, "MCP module not configured");
			try {
				// Build a Web API Request from the Fastify request for MCP module compatibility
				const url = `${request.protocol}://${request.hostname}${request.url}`;
				const body = JSON.stringify(request.body);
				const webRequest = new Request(url, {
					method: "POST",
					headers: {
						...(request.headers as Record<string, string>),
						"Content-Type": "application/json",
					},
					body,
				});
				const result = await mcp.token(webRequest);
				if (!result.success) {
					const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
					return sendMcpNoStore(
						reply,
						{
							error: result.error.code.toLowerCase(),
							error_description: result.error.message,
						},
						status,
					);
				}
				return sendMcpNoStore(reply, result.data);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Token exchange failed";
				return sendMcpNoStore(reply, { error: "server_error", error_description: message }, 500);
			}
		});
	};
}

/** @deprecated Use {@link authFastify} instead. Will be removed in v3.0. */
export const kavachFastify = authFastify;
