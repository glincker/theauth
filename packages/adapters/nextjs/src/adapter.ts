import type {
	AdapterGuard,
	AdapterScope,
	AdapterSecurityOptions,
	AgentFilter,
	AuditFilter,
	CreateAgentInput,
	DelegateInput,
	Permission,
	ScopeDenial,
	TheAuth,
	UpdateAgentInput,
} from "@glinr/theauth";
import { createAdapterGuard, isProtectedAdapterPath } from "@glinr/theauth";
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

/**
 * Return the machine-readable code of a typed core DelegationError, else null.
 * Structural check so adapters do not need a runtime import of core.
 */
function delegationErrorCode(err: unknown): string | null {
	if (err instanceof Error && err.name === "DelegationError") {
		const code = (err as Error & { code?: unknown }).code;
		if (typeof code === "string") return code;
	}
	return null;
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

function refuse(denial: ScopeDenial): Response {
	return errorResponse(denial.code, denial.message, denial.status);
}

function noScope(): Response {
	return refuse({ status: 403, code: "FORBIDDEN", message: "Caller scope is unavailable" });
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

async function handleAgentList(
	request: Request,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
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

	const scoped = scope.scopeAgentFilter(filter);
	if (!scoped.ok) return refuse(scoped.denial);

	try {
		const agents = await theauth.agent.list(scoped.value);
		return ok(agents);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to list agents";
		return internalError(message);
	}
}

async function handleAgentCreate(
	request: Request,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = CreateAgentSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	const createDenial = scope.checkAgentCreate(parsed.data.ownerId);
	if (createDenial) return refuse(createDenial);

	try {
		const input: CreateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		const agent = await theauth.agent.create(input);
		return created(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to create agent";
		return internalError(message);
	}
}

async function handleAgentGet(
	id: string,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const denial = await scope.checkAgent(id);
	if (denial) return refuse(denial);
	try {
		const agent = await theauth.agent.get(id);
		if (!agent) return notFound(`Agent "${id}" not found`);
		return ok(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to get agent";
		return internalError(message);
	}
}

async function handleAgentUpdate(
	id: string,
	request: Request,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const denial = await scope.checkAgent(id);
	if (denial) return refuse(denial);

	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = UpdateAgentSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	try {
		const input: UpdateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[] | undefined,
		};
		const agent = await theauth.agent.update(id, input);
		return ok(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to update agent";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

async function handleAgentRevoke(
	id: string,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const denial = await scope.checkAgent(id);
	if (denial) return refuse(denial);
	try {
		await theauth.agent.revoke(id);
		return new Response(null, { status: 204 });
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to revoke agent";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

async function handleAgentRotate(
	id: string,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const denial = await scope.checkAgent(id);
	if (denial) return refuse(denial);
	try {
		const agent = await theauth.agent.rotate(id);
		return ok(agent);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to rotate agent token";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

function extractRequestContext(
	request: Request,
	guard: AdapterGuard,
): { ip?: string; userAgent?: string } {
	const ip = guard.clientIp(request) ?? undefined;
	const userAgent = request.headers.get("user-agent") ?? undefined;
	return { ip, userAgent };
}

async function handleAuthorize(
	request: Request,
	theauth: TheAuth,
	guard: AdapterGuard,
	scope: AdapterScope,
): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = AuthorizeSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	const agentDenial = await scope.checkAgent(parsed.data.agentId);
	if (agentDenial) return refuse(agentDenial);

	try {
		const context = extractRequestContext(request, guard);
		const result = await theauth.authorize(
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

async function handleAuthorizeByToken(
	request: Request,
	theauth: TheAuth,
	guard: AdapterGuard,
): Promise<Response> {
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
		const context = extractRequestContext(request, guard);
		const result = await theauth.authorizeByToken(
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

async function handleDelegationCreate(
	request: Request,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const bodyResult = await parseJsonBody(request);
	if (!bodyResult.success) return bodyResult.response;

	const parsed = DelegateSchema.safeParse(bodyResult.data);
	if (!parsed.success) return validationError(parsed.error.issues);

	const fromDenial = await scope.checkAgent(parsed.data.fromAgent);
	if (fromDenial) return refuse(fromDenial);

	try {
		const input: DelegateInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		const chain = await theauth.delegate(input);
		return created(chain);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to create delegation";
		if (message.includes("not found")) return notFound(message);
		const delegationCode = delegationErrorCode(err);
		if (delegationCode) return errorResponse(delegationCode, message, 400);
		return internalError(message);
	}
}

async function handleDelegationRevoke(
	id: string,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const denial = await scope.checkChain(id);
	if (denial) return refuse(denial);
	try {
		await theauth.delegation.revoke(id);
		return new Response(null, { status: 204 });
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to revoke delegation";
		if (message.includes("not found")) return notFound(message);
		return internalError(message);
	}
}

async function handleDelegationList(
	agentId: string,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const denial = await scope.checkAgent(agentId);
	if (denial) return refuse(denial);
	try {
		const chains = await theauth.delegation.listChains(agentId);
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

async function handleAuditQuery(
	request: Request,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const url = new URL(request.url);
	const filter = buildAuditFilter(url);

	const scoped = scope.scopeAuditFilter(filter);
	if (!scoped.ok) return refuse(scoped.denial);

	try {
		const entries = await theauth.audit.query(scoped.value);
		return ok(entries);
	} catch (err) {
		const message = err instanceof Error ? err.message : "Failed to query audit logs";
		return internalError(message);
	}
}

async function handleAuditExport(
	request: Request,
	theauth: TheAuth,
	scope: AdapterScope,
): Promise<Response> {
	const url = new URL(request.url);
	const format = getSearchParam(url, "format") ?? "json";
	if (format !== "json" && format !== "csv") {
		return badRequest('format must be "json" or "csv"');
	}

	const since = getSearchParam(url, "since");
	const until = getSearchParam(url, "until");

	const options: { format: "json" | "csv"; since?: Date; until?: Date; userId?: string } = {
		format,
	};
	const userId = getSearchParam(url, "userId");
	if (userId) options.userId = userId;
	if (since) {
		const d = new Date(since);
		if (!Number.isNaN(d.getTime())) options.since = d;
	}
	if (until) {
		const d = new Date(until);
		if (!Number.isNaN(d.getTime())) options.until = d;
	}

	const scopedExport = scope.scopeAuditExport(options);
	if (!scopedExport.ok) return refuse(scopedExport.denial);

	try {
		const exported = await theauth.audit.export(scopedExport.value);
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

async function handleDashboardStats(theauth: TheAuth, scope: AdapterScope): Promise<Response> {
	// Default guard: aggregate only the caller's own agents and audit rows.
	const statsOwner = scope.statsOwnerId();
	try {
		const [agents, recentAudit] = await Promise.all([
			theauth.agent.list(statsOwner ? { userId: statsOwner } : undefined),
			theauth.audit.query({
				since: new Date(Date.now() - 24 * 60 * 60 * 1000),
				limit: 1000,
				...(statsOwner ? { userId: statsOwner } : {}),
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
 * The `basePath` is the URL prefix before the `[...theauth]` segment, e.g.
 * `/api/theauth`. Segments after that prefix are used to match routes.
 */
async function dispatch(
	request: Request,
	theauth: TheAuth,
	mcp: McpAuthModule | undefined,
	basePath: string,
	guard: AdapterGuard,
): Promise<Response> {
	const url = new URL(request.url);
	// Normalise pathname relative to the adapter base
	const raw = url.pathname;
	const relative = raw.startsWith(basePath) ? raw.slice(basePath.length) : raw;
	// Ensure leading slash
	const pathname = relative.startsWith("/") ? relative : `/${relative}`;
	const method = request.method.toUpperCase();

	// Management routes (agents, delegations, audit, dashboard, authorize)
	// require an authenticated caller.
	let scope: AdapterScope | null = null;
	// The guard resolves the caller once and returns what they may touch. With
	// `allowUnauthenticated` it still returns a scope (unrestricted).
	if (isProtectedAdapterPath(pathname)) {
		const resolved = await guard.resolve(request);
		if (!resolved.ok) return resolved.response;
		scope = resolved.scope;
	}

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
		if (!scope) return noScope();
		if (method === "GET") return handleAgentList(request, theauth, scope);
		if (method === "POST") return handleAgentCreate(request, theauth, scope);
		return methodNotAllowed();
	}

	// /agents/:id/rotate
	const rotateMatch = /^\/agents\/([^/]+)\/rotate$/.exec(pathname);
	if (rotateMatch) {
		const id = rotateMatch[1];
		if (!id) return badRequest("Missing agent id");
		if (!scope) return noScope();
		if (method === "POST") return handleAgentRotate(id, theauth, scope);
		return methodNotAllowed();
	}

	// /agents/:id
	const agentMatch = /^\/agents\/([^/]+)$/.exec(pathname);
	if (agentMatch) {
		const id = agentMatch[1];
		if (!id) return badRequest("Missing agent id");
		if (!scope) return noScope();
		if (method === "GET") return handleAgentGet(id, theauth, scope);
		if (method === "PATCH") return handleAgentUpdate(id, request, theauth, scope);
		if (method === "DELETE") return handleAgentRevoke(id, theauth, scope);
		return methodNotAllowed();
	}

	// ── Authorization ───────────────────────────────────────────────

	if (pathname === "/authorize") {
		if (!scope) return noScope();
		if (method === "POST") return handleAuthorize(request, theauth, guard, scope);
		return methodNotAllowed();
	}

	if (pathname === "/authorize/token") {
		if (method === "POST") return handleAuthorizeByToken(request, theauth, guard);
		return methodNotAllowed();
	}

	// ── Delegations ─────────────────────────────────────────────────

	if (pathname === "/delegations") {
		if (!scope) return noScope();
		if (method === "POST") return handleDelegationCreate(request, theauth, scope);
		return methodNotAllowed();
	}

	// /delegations/:id
	const delegationMatch = /^\/delegations\/([^/]+)$/.exec(pathname);
	if (delegationMatch) {
		const id = delegationMatch[1];
		if (!id) return badRequest("Missing delegation id");
		if (!scope) return noScope();
		if (method === "DELETE") return handleDelegationRevoke(id, theauth, scope);
		if (method === "GET") return handleDelegationList(id, theauth, scope);
		return methodNotAllowed();
	}

	// ── Audit ───────────────────────────────────────────────────────

	if (pathname === "/audit/export") {
		if (!scope) return noScope();
		if (method === "GET") return handleAuditExport(request, theauth, scope);
		return methodNotAllowed();
	}

	if (pathname === "/audit") {
		if (!scope) return noScope();
		if (method === "GET") return handleAuditQuery(request, theauth, scope);
		return methodNotAllowed();
	}

	// ── Dashboard ───────────────────────────────────────────────────

	if (pathname === "/dashboard/stats") {
		if (!scope) return noScope();
		if (method === "GET") return handleDashboardStats(theauth, scope);
		return methodNotAllowed();
	}

	if (pathname === "/dashboard/agents") {
		if (!scope) return noScope();
		if (method === "GET") return handleAgentList(request, theauth, scope);
		return methodNotAllowed();
	}

	if (pathname === "/dashboard/audit") {
		if (!scope) return noScope();
		if (method === "GET") return handleAuditQuery(request, theauth, scope);
		return methodNotAllowed();
	}

	// ── Plugin Endpoints ────────────────────────────────────────────

	const pluginResponse = await theauth.plugins.handleRequest(request, basePath);
	if (pluginResponse !== null) {
		return pluginResponse;
	}

	return notFound("Route not found");
}

// ─── Adapter Factory ─────────────────────────────────────────────────────────

export interface TheAuthNextjsOptions extends AdapterSecurityOptions {
	/**
	 * The MCP OAuth 2.1 module. When provided, MCP endpoints are enabled.
	 */
	mcp?: McpAuthModule;
	/**
	 * The URL path prefix before the `[...auth]` catch-all segment.
	 * Defaults to `/api/theauth`.
	 *
	 * @example `/api/auth`
	 */
	basePath?: string;
}

/** @deprecated Use `TheAuthNextjsOptions` instead. Will be removed in a future major version. */
export type AuthNextjsOptions = TheAuthNextjsOptions;

export interface TheAuthNextjsHandlers {
	GET: (request: Request) => Promise<Response>;
	POST: (request: Request) => Promise<Response>;
	PATCH: (request: Request) => Promise<Response>;
	DELETE: (request: Request) => Promise<Response>;
	OPTIONS: (request: Request) => Promise<Response>;
}

/** @deprecated Use `TheAuthNextjsHandlers` instead. Will be removed in a future major version. */
export type AuthNextjsHandlers = TheAuthNextjsHandlers;

/**
 * Create Next.js App Router route handlers for all TheAuth REST API routes.
 *
 * Mount in `app/api/theauth/[...theauth]/route.ts`:
 *
 * @example
 * ```typescript
 * import { createTheAuth } from '@glinr/theauth';
 * import { theAuthNextjs } from '@glinr/theauth-nextjs';
 *
 * const auth = createTheAuth({ database: { provider: 'sqlite', url: 'theauth.db' } });
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
	const basePath = options?.basePath ?? "/api/theauth";
	// Fails closed at construction when nothing can authenticate callers.
	const guard = createAdapterGuard(auth, options, "theAuthNextjs");

	const handler = (request: Request): Promise<Response> =>
		dispatch(request, auth, mcp, basePath, guard);

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
