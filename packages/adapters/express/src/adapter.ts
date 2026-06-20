import type { Request, Response } from "express";
import { Router } from "express";
import type {
	AgentFilter,
	AuditFilter,
	CreateAgentInput,
	DelegateInput,
	Kavach,
	Permission,
	UpdateAgentInput,
} from "theauth";
import type { McpAuthModule } from "theauth/mcp";
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

function sendOk<T>(res: Response, data: T, status = 200): void {
	res.status(status).json({ data });
}

function sendCreated<T>(res: Response, data: T): void {
	sendOk(res, data, 201);
}

function sendNoContent(res: Response): void {
	res.status(204).end();
}

function sendError(res: Response, code: string, message: string, status: number): void {
	res.status(status).json({ error: { code, message } });
}

function sendBadRequest(res: Response, message: string): void {
	sendError(res, "BAD_REQUEST", message, 400);
}

function sendUnauthorized(res: Response, message = "Unauthorized"): void {
	sendError(res, "UNAUTHORIZED", message, 401);
}

function sendNotFound(res: Response, message = "Not found"): void {
	sendError(res, "NOT_FOUND", message, 404);
}

function sendInternalError(res: Response, message = "Internal server error"): void {
	sendError(res, "INTERNAL_ERROR", message, 500);
}

function sendValidationError(res: Response, issues: z.ZodIssue[]): void {
	const message = issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ");
	sendBadRequest(res, `Validation failed: ${message}`);
}

// ─── MCP CORS Headers ────────────────────────────────────────────────────────

const MCP_CORS_HEADERS: Record<string, string> = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization",
	"Access-Control-Max-Age": "86400",
};

function setMcpCors(res: Response): void {
	for (const [key, value] of Object.entries(MCP_CORS_HEADERS)) {
		res.setHeader(key, value);
	}
}

function sendMcpOk<T>(res: Response, data: T, status = 200): void {
	setMcpCors(res);
	res.status(status).json(data);
}

function sendMcpError(res: Response, code: string, message: string, status: number): void {
	setMcpCors(res);
	res.status(status).json({ error: code, error_description: message });
}

function sendMcpNoStore<T>(res: Response, data: T, status = 200): void {
	setMcpCors(res);
	res.setHeader("Cache-Control", "no-store");
	res.setHeader("Pragma", "no-cache");
	res.status(status).json(data);
}

/** Extract a route param as string (Express 5 params can be string | string[] | undefined) */
function param(req: Request, name: string): string {
	const val = req.params[name];
	return Array.isArray(val) ? (val[0] ?? "") : (val ?? "");
}

// ─── Helpers for building a Web-compatible Request from Express ──────────────

function buildWebRequest(req: Request): globalThis.Request {
	const protocol = req.protocol ?? "http";
	const host = req.headers.host ?? "localhost";
	const url = `${protocol}://${host}${req.originalUrl ?? req.url}`;

	const headers = new Headers();
	for (const [key, value] of Object.entries(req.headers)) {
		if (value !== undefined) {
			if (Array.isArray(value)) {
				for (const v of value) {
					headers.append(key, v);
				}
			} else {
				headers.set(key, value);
			}
		}
	}

	// For POST requests encode body as URL-encoded or JSON
	let body: string | null = null;
	if (req.method !== "GET" && req.method !== "HEAD" && req.body !== undefined) {
		const contentType = req.headers["content-type"] ?? "";
		if (contentType.includes("application/x-www-form-urlencoded")) {
			const params = new URLSearchParams();
			for (const [k, v] of Object.entries(req.body as Record<string, string>)) {
				params.set(k, v);
			}
			body = params.toString();
		} else {
			body = JSON.stringify(req.body);
		}
	}

	return new Request(url, {
		method: req.method,
		headers,
		body: body ?? undefined,
	});
}

// ─── Adapter Factory ─────────────────────────────────────────────────────────

/**
 * Create an Express Router with all TheAuth REST API routes mounted.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createKavach } from 'theauth';
 * import { kavachExpress } from '@theauth/express';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(express.urlencoded({ extended: true }));
 *
 * const kavach = createKavach({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * app.use('/auth', kavachExpress(kavach));
 *
 * app.listen(3000);
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from 'theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * app.use('/auth', kavachExpress(kavach, { mcp }));
 * ```
 */
export function kavachExpress(kavach: Kavach, options?: { mcp?: McpAuthModule }): Router {
	const router = Router();
	const mcp = options?.mcp;

	// ── Agent REST API ──────────────────────────────────────────────

	// POST /agents - create agent
	router.post("/agents", (req: Request, res: Response) => {
		const parsed = CreateAgentSchema.safeParse(req.body);
		if (!parsed.success) {
			sendValidationError(res, parsed.error.issues);
			return;
		}
		const input: CreateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		kavach.agent
			.create(input)
			.then((agent) => sendCreated(res, agent))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to create agent";
				sendInternalError(res, message);
			});
	});

	// GET /agents - list agents
	router.get("/agents", (req: Request, res: Response) => {
		const filter: AgentFilter = {};
		const { userId, status, type } = req.query;
		if (typeof userId === "string") filter.userId = userId;
		if (typeof status === "string" && ["active", "revoked", "expired"].includes(status)) {
			filter.status = status as AgentFilter["status"];
		}
		if (typeof type === "string" && ["autonomous", "delegated", "service"].includes(type)) {
			filter.type = type as AgentFilter["type"];
		}
		kavach.agent
			.list(filter)
			.then((agents) => sendOk(res, agents))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to list agents";
				sendInternalError(res, message);
			});
	});

	// GET /agents/:id - get agent
	router.get("/agents/:id", (req: Request, res: Response) => {
		const id = param(req, "id");
		kavach.agent
			.get(id)
			.then((agent) => {
				if (!agent) {
					sendNotFound(res, `Agent "${id}" not found`);
					return;
				}
				sendOk(res, agent);
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to get agent";
				sendInternalError(res, message);
			});
	});

	// PATCH /agents/:id - update agent
	router.patch("/agents/:id", (req: Request, res: Response) => {
		const id = param(req, "id");
		const parsed = UpdateAgentSchema.safeParse(req.body);
		if (!parsed.success) {
			sendValidationError(res, parsed.error.issues);
			return;
		}
		const input: UpdateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[] | undefined,
		};
		kavach.agent
			.update(id, input)
			.then((agent) => sendOk(res, agent))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to update agent";
				if (message.includes("not found")) {
					sendNotFound(res, message);
					return;
				}
				sendInternalError(res, message);
			});
	});

	// DELETE /agents/:id - revoke agent
	router.delete("/agents/:id", (req: Request, res: Response) => {
		const id = param(req, "id");
		kavach.agent
			.revoke(id)
			.then(() => sendNoContent(res))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to revoke agent";
				if (message.includes("not found")) {
					sendNotFound(res, message);
					return;
				}
				sendInternalError(res, message);
			});
	});

	// POST /agents/:id/rotate - rotate token
	router.post("/agents/:id/rotate", (req: Request, res: Response) => {
		const id = param(req, "id");
		kavach.agent
			.rotate(id)
			.then((agent) => sendOk(res, agent))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to rotate agent token";
				if (message.includes("not found")) {
					sendNotFound(res, message);
					return;
				}
				sendInternalError(res, message);
			});
	});

	// ── Authorization ───────────────────────────────────────────────

	// POST /authorize - authorize action by agentId
	router.post("/authorize", (req: Request, res: Response) => {
		const parsed = AuthorizeSchema.safeParse(req.body);
		if (!parsed.success) {
			sendValidationError(res, parsed.error.issues);
			return;
		}
		const xForwardedFor = req.headers["x-forwarded-for"];
		const ip =
			(Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor?.split(",")[0]?.trim()) ??
			req.ip ??
			undefined;
		const userAgent =
			(Array.isArray(req.headers["user-agent"])
				? req.headers["user-agent"][0]
				: req.headers["user-agent"]) ?? undefined;
		kavach
			.authorize(
				parsed.data.agentId,
				{
					action: parsed.data.action,
					resource: parsed.data.resource,
					arguments: parsed.data.arguments,
				},
				{ ip, userAgent },
			)
			.then((result) => {
				const status = result.allowed ? 200 : 403;
				res.status(status).json({ data: result });
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Authorization check failed";
				sendInternalError(res, message);
			});
	});

	// POST /authorize/token - authorize by bearer token
	router.post("/authorize/token", (req: Request, res: Response) => {
		const authHeader = req.headers.authorization;
		if (!authHeader?.startsWith("Bearer ")) {
			sendUnauthorized(res, "Missing or invalid Authorization header");
			return;
		}
		const token = authHeader.slice(7);

		const parsed = AuthorizeByTokenSchema.safeParse(req.body);
		if (!parsed.success) {
			sendValidationError(res, parsed.error.issues);
			return;
		}
		const xForwardedFor = req.headers["x-forwarded-for"];
		const ip =
			(Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor?.split(",")[0]?.trim()) ??
			req.ip ??
			undefined;
		const userAgent =
			(Array.isArray(req.headers["user-agent"])
				? req.headers["user-agent"][0]
				: req.headers["user-agent"]) ?? undefined;
		kavach
			.authorizeByToken(
				token,
				{
					action: parsed.data.action,
					resource: parsed.data.resource,
					arguments: parsed.data.arguments,
				},
				{ ip, userAgent },
			)
			.then((result) => {
				const status = result.allowed ? 200 : 403;
				res.status(status).json({ data: result });
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Authorization check failed";
				sendInternalError(res, message);
			});
	});

	// ── Delegation ──────────────────────────────────────────────────

	// POST /delegations - create delegation
	router.post("/delegations", (req: Request, res: Response) => {
		const parsed = DelegateSchema.safeParse(req.body);
		if (!parsed.success) {
			sendValidationError(res, parsed.error.issues);
			return;
		}
		const input: DelegateInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		kavach
			.delegate(input)
			.then((chain) => sendCreated(res, chain))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to create delegation";
				if (message.includes("not found")) {
					sendNotFound(res, message);
					return;
				}
				if (message.includes("exceeds") || message.includes("depth")) {
					sendBadRequest(res, message);
					return;
				}
				sendInternalError(res, message);
			});
	});

	// DELETE /delegations/:id - revoke delegation
	router.delete("/delegations/:id", (req: Request, res: Response) => {
		const id = param(req, "id");
		kavach.delegation
			.revoke(id)
			.then(() => sendNoContent(res))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to revoke delegation";
				if (message.includes("not found")) {
					sendNotFound(res, message);
					return;
				}
				sendInternalError(res, message);
			});
	});

	// GET /delegations/:agentId - list chains for agent
	router.get("/delegations/:agentId", (req: Request, res: Response) => {
		const agentId = param(req, "agentId");
		kavach.delegation
			.listChains(agentId)
			.then((chains) => sendOk(res, chains))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to list delegation chains";
				sendInternalError(res, message);
			});
	});

	// ── Audit ───────────────────────────────────────────────────────

	// GET /audit - query audit logs
	router.get("/audit", (req: Request, res: Response) => {
		const filter: AuditFilter = {};
		const { agentId, userId, since, until, actions, result, limit, offset } = req.query;

		if (typeof agentId === "string") filter.agentId = agentId;
		if (typeof userId === "string") filter.userId = userId;
		if (typeof since === "string") {
			const d = new Date(since);
			if (!Number.isNaN(d.getTime())) filter.since = d;
		}
		if (typeof until === "string") {
			const d = new Date(until);
			if (!Number.isNaN(d.getTime())) filter.until = d;
		}
		if (typeof actions === "string") {
			filter.actions = actions.split(",").map((a) => a.trim());
		}
		if (typeof result === "string" && ["allowed", "denied", "rate_limited"].includes(result)) {
			filter.result = result as AuditFilter["result"];
		}
		if (typeof limit === "string") {
			const n = Number.parseInt(limit, 10);
			if (!Number.isNaN(n) && n > 0) filter.limit = n;
		}
		if (typeof offset === "string") {
			const n = Number.parseInt(offset, 10);
			if (!Number.isNaN(n) && n >= 0) filter.offset = n;
		}

		kavach.audit
			.query(filter)
			.then((entries) => sendOk(res, entries))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to query audit logs";
				sendInternalError(res, message);
			});
	});

	// GET /audit/export - export audit logs
	router.get("/audit/export", (req: Request, res: Response) => {
		const format = (req.query.format as string | undefined) ?? "json";
		if (format !== "json" && format !== "csv") {
			sendBadRequest(res, 'format must be "json" or "csv"');
			return;
		}

		const options: { format: "json" | "csv"; since?: Date; until?: Date } = { format };
		const { since, until } = req.query;
		if (typeof since === "string") {
			const d = new Date(since);
			if (!Number.isNaN(d.getTime())) options.since = d;
		}
		if (typeof until === "string") {
			const d = new Date(until);
			if (!Number.isNaN(d.getTime())) options.until = d;
		}

		kavach.audit
			.export(options)
			.then((exported) => {
				const contentType = format === "csv" ? "text/csv" : "application/json";
				res.setHeader("Content-Type", contentType);
				res.setHeader("Content-Disposition", `attachment; filename="audit-export.${format}"`);
				res.status(200).send(exported);
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to export audit logs";
				sendInternalError(res, message);
			});
	});

	// ── MCP OAuth 2.1 Endpoints ─────────────────────────────────────

	// OPTIONS preflight for MCP/well-known routes
	router.options("/.well-known/*path", (_req: Request, res: Response) => {
		setMcpCors(res);
		res.status(204).end();
	});

	router.options("/mcp/*path", (_req: Request, res: Response) => {
		setMcpCors(res);
		res.status(204).end();
	});

	// GET /.well-known/oauth-authorization-server
	router.get("/.well-known/oauth-authorization-server", (_req: Request, res: Response) => {
		if (!mcp) {
			sendNotFound(res, "MCP module not configured");
			return;
		}
		const metadata = mcp.getMetadata();
		sendMcpOk(res, metadata);
	});

	// GET /.well-known/oauth-protected-resource
	router.get("/.well-known/oauth-protected-resource", (_req: Request, res: Response) => {
		if (!mcp) {
			sendNotFound(res, "MCP module not configured");
			return;
		}
		const metadata = mcp.getProtectedResourceMetadata();
		sendMcpOk(res, metadata);
	});

	// POST /mcp/register - dynamic client registration
	router.post("/mcp/register", (req: Request, res: Response) => {
		if (!mcp) {
			sendNotFound(res, "MCP module not configured");
			return;
		}
		mcp
			.registerClient(req.body as Parameters<typeof mcp.registerClient>[0])
			.then((result) => {
				if (!result.success) {
					sendMcpError(res, "invalid_client_metadata", result.error.message, 400);
					return;
				}
				sendMcpNoStore(res, result.data, 201);
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Registration failed";
				sendMcpError(res, "server_error", message, 500);
			});
	});

	// GET /mcp/authorize - authorization endpoint
	router.get("/mcp/authorize", (req: Request, res: Response) => {
		if (!mcp) {
			sendNotFound(res, "MCP module not configured");
			return;
		}
		const webRequest = buildWebRequest(req);
		mcp
			.authorize(webRequest)
			.then((result) => {
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
							res.redirect(302, loginUrl.toString());
							return;
						}
					}
					sendMcpError(res, result.error.code.toLowerCase(), result.error.message, 400);
					return;
				}
				res.redirect(302, result.data.redirectUri);
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Authorization failed";
				sendMcpError(res, "server_error", message, 500);
			});
	});

	// POST /mcp/token - token endpoint
	router.post("/mcp/token", (req: Request, res: Response) => {
		if (!mcp) {
			sendNotFound(res, "MCP module not configured");
			return;
		}
		const webRequest = buildWebRequest(req);
		mcp
			.token(webRequest)
			.then((result) => {
				if (!result.success) {
					const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
					sendMcpNoStore(
						res,
						{
							error: result.error.code.toLowerCase(),
							error_description: result.error.message,
						},
						status,
					);
					return;
				}
				sendMcpNoStore(res, result.data);
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Token exchange failed";
				sendMcpNoStore(res, { error: "server_error", error_description: message }, 500);
			});
	});

	// ── Dashboard API ───────────────────────────────────────────────

	// GET /dashboard/stats
	router.get("/dashboard/stats", (_req: Request, res: Response) => {
		Promise.all([
			kavach.agent.list(),
			kavach.audit.query({
				since: new Date(Date.now() - 24 * 60 * 60 * 1000),
				limit: 1000,
			}),
		])
			.then(([agents, recentAudit]) => {
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
				sendOk(res, stats);
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to fetch dashboard stats";
				sendInternalError(res, message);
			});
	});

	// GET /dashboard/agents - agents with stats (same as GET /agents)
	router.get("/dashboard/agents", (req: Request, res: Response) => {
		const filter: AgentFilter = {};
		const { userId, status, type } = req.query;
		if (typeof userId === "string") filter.userId = userId;
		if (typeof status === "string" && ["active", "revoked", "expired"].includes(status)) {
			filter.status = status as AgentFilter["status"];
		}
		if (typeof type === "string" && ["autonomous", "delegated", "service"].includes(type)) {
			filter.type = type as AgentFilter["type"];
		}
		kavach.agent
			.list(filter)
			.then((agents) => sendOk(res, agents))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to list agents";
				sendInternalError(res, message);
			});
	});

	// GET /dashboard/audit - same as GET /audit
	router.get("/dashboard/audit", (req: Request, res: Response) => {
		const filter: AuditFilter = {};
		const { agentId, userId, since, until, actions, result, limit, offset } = req.query;

		if (typeof agentId === "string") filter.agentId = agentId;
		if (typeof userId === "string") filter.userId = userId;
		if (typeof since === "string") {
			const d = new Date(since);
			if (!Number.isNaN(d.getTime())) filter.since = d;
		}
		if (typeof until === "string") {
			const d = new Date(until);
			if (!Number.isNaN(d.getTime())) filter.until = d;
		}
		if (typeof actions === "string") {
			filter.actions = actions.split(",").map((a) => a.trim());
		}
		if (typeof result === "string" && ["allowed", "denied", "rate_limited"].includes(result)) {
			filter.result = result as AuditFilter["result"];
		}
		if (typeof limit === "string") {
			const n = Number.parseInt(limit, 10);
			if (!Number.isNaN(n) && n > 0) filter.limit = n;
		}
		if (typeof offset === "string") {
			const n = Number.parseInt(offset, 10);
			if (!Number.isNaN(n) && n >= 0) filter.offset = n;
		}

		kavach.audit
			.query(filter)
			.then((entries) => sendOk(res, entries))
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Failed to query audit logs";
				sendInternalError(res, message);
			});
	});

	// ── Plugin Endpoints ────────────────────────────────────────────

	for (const endpoint of kavach.plugins.getEndpoints()) {
		const method = endpoint.method.toLowerCase() as "get" | "post" | "put" | "patch" | "delete";
		router[method](endpoint.path, (req: Request, res: Response) => {
			const webReq = buildWebRequest(req);
			kavach.plugins
				.handleRequest(webReq)
				.then((response) => {
					if (!response) {
						res.status(404).end();
						return;
					}
					res.status(response.status);
					response.headers.forEach((value, key) => {
						res.setHeader(key, value);
					});
					return response.text().then((body) => {
						res.send(body);
					});
				})
				.catch((err: unknown) => {
					const message = err instanceof Error ? err.message : "Plugin endpoint error";
					sendInternalError(res, message);
				});
		});
	}

	return router;
}
