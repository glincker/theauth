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

function ok<T>(data: T, status = 200): Response {
	return new Response(JSON.stringify({ data }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function created<T>(data: T): Response {
	return ok(data, 201);
}

function errorResponse(code: string, message: string, status: number): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function badRequest(message: string): Response {
	return errorResponse("BAD_REQUEST", message, 400);
}

function unauthorized(message = "Unauthorized"): Response {
	return errorResponse("UNAUTHORIZED", message, 401);
}

function notFound(message = "Not found"): Response {
	return errorResponse("NOT_FOUND", message, 404);
}

function methodNotAllowed(): Response {
	return errorResponse("METHOD_NOT_ALLOWED", "Method not allowed", 405);
}

function internalError(message = "Internal server error"): Response {
	return errorResponse("INTERNAL_ERROR", message, 500);
}

function validationError(issues: z.ZodIssue[]): Response {
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

function mcpOk<T>(data: T, status = 200): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json", ...MCP_CORS_HEADERS },
	});
}

function mcpError(code: string, message: string, status: number): Response {
	return new Response(JSON.stringify({ error: code, error_description: message }), {
		status,
		headers: { "Content-Type": "application/json", ...MCP_CORS_HEADERS },
	});
}

function mcpNoStore<T>(data: T, status = 200): Response {
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

// ─── URL Parsing Helpers ─────────────────────────────────────────────────────

function getSearchParam(url: URL, key: string): string | null {
	return url.searchParams.get(key);
}

async function parseJsonBody(
	request: Request,
): Promise<{ success: true; data: unknown } | { success: false; response: Response }> {
	try {
		const data = (await request.json()) as unknown;
		return { success: true, data };
	} catch {
		return { success: false, response: badRequest("Invalid JSON body") };
	}
}

// ─── Route Handlers ──────────────────────────────────────────────────────────

async function handleAgentList(request: Request, kavach: TheAuth): Promise<Response> {
	const url = new URL(request.url);
	const userId = getSearchParam(url, "userId");
	const statusRaw = getSearchParam(url, "status");
	const typeRaw = getSearchParam(url, "type");

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
		return ok(agents);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to list agents";
		return internalError(message);
	}
}

async function handleAgentCreate(request: Request, kavach: TheAuth): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = CreateAgentSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	try {
		const input: CreateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		const agent = await kavach.agent.create(input);
		return created(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to create agent";
		return internalError(message);
	}
}

async function handleAgentGet(id: string, kavach: TheAuth): Promise<Response> {
	try {
		const agent = await kavach.agent.get(id);
		if (!agent) return notFound(`Agent "${id}" not found`);
		return ok(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to get agent";
		return internalError(message);
	}
}

async function handleAgentUpdate(id: string, request: Request, kavach: TheAuth): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = UpdateAgentSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	try {
		const input: UpdateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[] | undefined,
		};
		const agent = await kavach.agent.update(id, input);
		return ok(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to update agent";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

async function handleAgentRevoke(id: string, kavach: TheAuth): Promise<Response> {
	try {
		await kavach.agent.revoke(id);
		return new Response(null, { status: 204 });
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to revoke agent";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

async function handleAgentRotate(id: string, kavach: TheAuth): Promise<Response> {
	try {
		const agent = await kavach.agent.rotate(id);
		return ok(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to rotate agent token";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

function extractRequestContext(request: Request): { ip?: string; userAgent?: string } {
	const ip =
		request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		request.headers.get("x-real-ip") ??
		undefined;
	const userAgent = request.headers.get("user-agent") ?? undefined;
	return { ip, userAgent };
}

async function handleAuthorize(request: Request, kavach: TheAuth): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = AuthorizeSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	try {
		const context = extractRequestContext(request);
		const result = await kavach.authorize(
			parsed.data.agentId,
			{
				action: parsed.data.action,
				resource: parsed.data.resource,
				arguments: parsed.data.arguments,
			},
			context,
		);
		const status = result.allowed ? 200 : 403;
		return new Response(JSON.stringify({ data: result }), {
			status,
			headers: { "Content-Type": "application/json" },
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Authorization check failed";
		return internalError(message);
	}
}

async function handleAuthorizeByToken(request: Request, kavach: TheAuth): Promise<Response> {
	const authHeader = request.headers.get("Authorization");
	if (!authHeader?.startsWith("Bearer ")) {
		return unauthorized("Missing or invalid Authorization header");
	}
	const token = authHeader.slice(7);

	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = AuthorizeByTokenSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	try {
		const context = extractRequestContext(request);
		const result = await kavach.authorizeByToken(
			token,
			{
				action: parsed.data.action,
				resource: parsed.data.resource,
				arguments: parsed.data.arguments,
			},
			context,
		);
		const status = result.allowed ? 200 : 403;
		return new Response(JSON.stringify({ data: result }), {
			status,
			headers: { "Content-Type": "application/json" },
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : "Authorization check failed";
		return internalError(message);
	}
}

async function handleDelegationCreate(request: Request, kavach: TheAuth): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = DelegateSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	try {
		const input: DelegateInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		const chain = await kavach.delegate(input);
		return created(chain);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to create delegation";
		if (message.includes("not found")) return notFound(message);
		if (message.includes("exceeds") || message.includes("depth")) return badRequest(message);
		return internalError(message);
	}
}

async function handleDelegationRevoke(id: string, kavach: TheAuth): Promise<Response> {
	try {
		await kavach.delegation.revoke(id);
		return new Response(null, { status: 204 });
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to revoke delegation";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

async function handleDelegationList(agentId: string, kavach: TheAuth): Promise<Response> {
	try {
		const chains = await kavach.delegation.listChains(agentId);
		return ok(chains);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to list delegation chains";
		return internalError(message);
	}
}

function buildAuditFilter(url: URL): AuditFilter {
	const filter: AuditFilter = {};

	const agentId = getSearchParam(url, "agentId");
	const userId = getSearchParam(url, "userId");
	const since = getSearchParam(url, "since");
	const until = getSearchParam(url, "until");
	const actions = getSearchParam(url, "actions");
	const resultRaw = getSearchParam(url, "result");
	const limit = getSearchParam(url, "limit");
	const offset = getSearchParam(url, "offset");

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

	return filter;
}

async function handleAuditQuery(request: Request, kavach: TheAuth): Promise<Response> {
	const url = new URL(request.url);
	const filter = buildAuditFilter(url);

	try {
		const entries = await kavach.audit.query(filter);
		return ok(entries);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to query audit logs";
		return internalError(message);
	}
}

async function handleAuditExport(request: Request, kavach: TheAuth): Promise<Response> {
	const url = new URL(request.url);
	const format = getSearchParam(url, "format") ?? "json";
	if (format !== "json" && format !== "csv") {
		return badRequest('format must be "json" or "csv"');
	}

	const since = getSearchParam(url, "since");
	const until = getSearchParam(url, "until");

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
		return internalError(message);
	}
}

async function handleDashboardStats(kavach: TheAuth): Promise<Response> {
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
		return ok(stats);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to fetch dashboard stats";
		return internalError(message);
	}
}

// ─── Route Dispatcher ────────────────────────────────────────────────────────

/**
 * Dispatches an incoming Web API Request to the correct TheAuth handler based
 * on the request's pathname (relative to the catch-all segment base).
 *
 * The `basePath` is the URL prefix before the `[...kavach]` segment, e.g.
 * `/api/kavach`. Segments after that prefix are used to match routes.
 */
async function dispatch(
	request: Request,
	kavach: TheAuth,
	mcp: McpAuthModule | undefined,
	basePath: string,
): Promise<Response> {
	const url = new URL(request.url);
	// Normalise pathname relative to the adapter base
	const raw = url.pathname;
	const relative = raw.startsWith(basePath) ? raw.slice(basePath.length) : raw;
	// Ensure leading slash
	const pathname = relative.startsWith("/") ? relative : `/${relative}`;
	const method = request.method.toUpperCase();

	// MCP OPTIONS preflight
	if (method === "OPTIONS") {
		if (pathname.startsWith("/mcp/") || pathname.startsWith("/.well-known/")) {
			return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
		}
	}

	// ── MCP / well-known ────────────────────────────────────────────

	if (pathname === "/.well-known/oauth-authorization-server" && method === "GET") {
		if (!mcp) return notFound("MCP module not configured");
		const metadata = mcp.getMetadata();
		return mcpOk(metadata);
	}

	if (pathname === "/.well-known/oauth-protected-resource" && method === "GET") {
		if (!mcp) return notFound("MCP module not configured");
		const metadata = mcp.getProtectedResourceMetadata();
		return mcpOk(metadata);
	}

	if (pathname === "/mcp/register" && method === "POST") {
		if (!mcp) return notFound("MCP module not configured");
		let body: unknown;
		try {
			body = (await request.json()) as unknown;
		} catch {
			return mcpError("invalid_request", "Invalid JSON body", 400);
		}
		try {
			const result = await mcp.registerClient(body as Parameters<typeof mcp.registerClient>[0]);
			if (!result.success) {
				return mcpError("invalid_client_metadata", result.error.message, 400);
			}
			return mcpNoStore(result.data, 201);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Registration failed";
			return mcpError("server_error", message, 500);
		}
	}

	if (pathname === "/mcp/authorize" && method === "GET") {
		if (!mcp) return notFound("MCP module not configured");
		try {
			const result = await mcp.authorize(request);
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
						return Response.redirect(loginUrl.toString(), 302);
					}
				}
				return mcpError(result.error.code.toLowerCase(), result.error.message, 400);
			}
			return Response.redirect(result.data.redirectUri, 302);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Authorization failed";
			return mcpError("server_error", message, 500);
		}
	}

	if (pathname === "/mcp/token" && method === "POST") {
		if (!mcp) return notFound("MCP module not configured");
		try {
			const result = await mcp.token(request);
			if (!result.success) {
				const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
				return mcpNoStore(
					{
						error: result.error.code.toLowerCase(),
						error_description: result.error.message,
					},
					status,
				);
			}
			return mcpNoStore(result.data);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Token exchange failed";
			return mcpNoStore({ error: "server_error", error_description: message }, 500);
		}
	}

	// ── Agents ──────────────────────────────────────────────────────

	if (pathname === "/agents") {
		if (method === "GET") return handleAgentList(request, kavach);
		if (method === "POST") return handleAgentCreate(request, kavach);
		return methodNotAllowed();
	}

	// /agents/:id/rotate
	const rotateMatch = /^\/agents\/([^/]+)\/rotate$/.exec(pathname);
	if (rotateMatch) {
		const id = rotateMatch[1];
		if (!id) return badRequest("Missing agent id");
		if (method === "POST") return handleAgentRotate(id, kavach);
		return methodNotAllowed();
	}

	// /agents/:id
	const agentMatch = /^\/agents\/([^/]+)$/.exec(pathname);
	if (agentMatch) {
		const id = agentMatch[1];
		if (!id) return badRequest("Missing agent id");
		if (method === "GET") return handleAgentGet(id, kavach);
		if (method === "PATCH") return handleAgentUpdate(id, request, kavach);
		if (method === "DELETE") return handleAgentRevoke(id, kavach);
		return methodNotAllowed();
	}

	// ── Authorization ───────────────────────────────────────────────

	if (pathname === "/authorize") {
		if (method === "POST") return handleAuthorize(request, kavach);
		return methodNotAllowed();
	}

	if (pathname === "/authorize/token") {
		if (method === "POST") return handleAuthorizeByToken(request, kavach);
		return methodNotAllowed();
	}

	// ── Delegations ─────────────────────────────────────────────────

	if (pathname === "/delegations") {
		if (method === "POST") return handleDelegationCreate(request, kavach);
		return methodNotAllowed();
	}

	// /delegations/:id
	const delegationMatch = /^\/delegations\/([^/]+)$/.exec(pathname);
	if (delegationMatch) {
		const id = delegationMatch[1];
		if (!id) return badRequest("Missing delegation id");
		if (method === "DELETE") return handleDelegationRevoke(id, kavach);
		if (method === "GET") return handleDelegationList(id, kavach);
		return methodNotAllowed();
	}

	// ── Audit ───────────────────────────────────────────────────────

	if (pathname === "/audit/export") {
		if (method === "GET") return handleAuditExport(request, kavach);
		return methodNotAllowed();
	}

	if (pathname === "/audit") {
		if (method === "GET") return handleAuditQuery(request, kavach);
		return methodNotAllowed();
	}

	// ── Dashboard ───────────────────────────────────────────────────

	if (pathname === "/dashboard/stats") {
		if (method === "GET") return handleDashboardStats(kavach);
		return methodNotAllowed();
	}

	if (pathname === "/dashboard/agents") {
		if (method === "GET") return handleAgentList(request, kavach);
		return methodNotAllowed();
	}

	if (pathname === "/dashboard/audit") {
		if (method === "GET") return handleAuditQuery(request, kavach);
		return methodNotAllowed();
	}

	// ── Plugin Endpoints ────────────────────────────────────────────

	const pluginResponse = await kavach.plugins.handleRequest(request, basePath);
	if (pluginResponse !== null) {
		return pluginResponse;
	}

	return notFound("Route not found");
}

// ─── Adapter Factory ─────────────────────────────────────────────────────────

export interface TheAuthNextjsOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `[...auth]` catch-all segment.
	 * Defaults to `/api/kavach`.
	 *
	 * @example `/api/auth`
	 */
	basePath?: string;
}

/** @deprecated Use `TheAuthNextjsOptions` instead. Will be removed in a future major version. */
export type AuthNextjsOptions = TheAuthNextjsOptions;

/** @deprecated Use `TheAuthNextjsOptions` instead. Will be removed in a future major version. */
export type KavachNextjsOptions = TheAuthNextjsOptions;

export interface TheAuthNextjsHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/** @deprecated Use `TheAuthNextjsHandlers` instead. Will be removed in a future major version. */
export type AuthNextjsHandlers = TheAuthNextjsHandlers;

/** @deprecated Use `TheAuthNextjsHandlers` instead. Will be removed in a future major version. */
export type KavachNextjsHandlers = TheAuthNextjsHandlers;

/**
 * Create Next.js App Router route handlers for all TheAuth REST API routes.
 *
 * Mount in `app/api/kavach/[...kavach]/route.ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthNextjs } from '@glinr/theauth-nextjs';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'kavach.db' } });
 * const handlers = theAuthNextjs(auth);
 *
 * export const GET = handlers.GET;
 * export const POST = handlers.POST;
 * export const PATCH = handlers.PATCH;
 * export const DELETE = handlers.DELETE;
 * export const OPTIONS = handlers.OPTIONS;
 * ```
 *
 * With MCP OAuth 2.1:
 * ```typescript
 * import { createMcpModule } from '@glinr/theauth/mcp';
 * const mcp = createMcpModule({ ... });
 * const handlers = theAuthNextjs(auth, { mcp });
 * ```
 */
export function theAuthNextjs(
	auth: TheAuth,
	options?: TheAuthNextjsOptions,
): TheAuthNextjsHandlers {
	const mcp = options?.mcp;
	const basePath = options?.basePath ?? "/api/kavach";

	const handler = (request: Request): Promise<Response> => dispatch(request, auth, mcp, basePath);

	return {
		GET: handler,
		POST: handler,
		PATCH: handler,
		DELETE: handler,
		OPTIONS: handler,
	};
}

/** @deprecated Use `theAuthNextjs` instead. Will be removed in a future major version. */
export const authNextjs = theAuthNextjs;

/** @deprecated Use `theAuthNextjs` instead. Will be removed in a future major version. */
export const kavachNextjs = theAuthNextjs;
