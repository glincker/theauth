import {
	applyMountedToResourceMetadata,
	applyMountedToServerMetadata,
} from "../../mcp/metadata.js";
import type { McpClientRegistrationRequest } from "../../mcp/types.js";
import {
	BodyTooLargeError,
	mcpError,
	mcpNoStore,
	mcpOk,
	notFound,
	readBoundedText,
	readJsonBody,
} from "../respond.js";
import type { HttpRoute, RouteContext } from "../types.js";

const NOT_CONFIGURED = "MCP module not configured";
const FORM_TYPE = "application/x-www-form-urlencoded";

type BoundedBody = { ok: true; request: Request } | { ok: false; response: Response };

/**
 * Read a client authentication endpoint body with a size cap and hand the module a request it can parse again.
 * `formOnly` refuses any content type but form encoding (RFC 7662 section 2.1).
 */
async function boundedFormRequest(ctx: RouteContext, formOnly: boolean): Promise<BoundedBody> {
	const { request, maxBodyBytes } = ctx;
	const refuse = (error: string, message: string, status: number): BoundedBody => ({
		ok: false,
		response: mcpNoStore({ error, error_description: message }, status),
	});
	const contentType = request.headers.get("content-type") ?? "";
	if (formOnly && !contentType.toLowerCase().includes(FORM_TYPE)) {
		return refuse("invalid_request", `Content-Type must be ${FORM_TYPE}`, 400);
	}
	let text: string;
	try {
		text = await readBoundedText(request, maxBodyBytes);
	} catch (err) {
		if (err instanceof BodyTooLargeError) {
			return refuse("invalid_request", "Request body is too large", 413);
		}
		return refuse("invalid_request", "Malformed request body", 400);
	}
	const headers = new Headers(request.headers);
	headers.delete("content-length");
	return { ok: true, request: new Request(request.url, { method: "POST", headers, body: text }) };
}

/** Fixed-text 500: the original error goes to the observability logger, never to the caller. */
function serverError(ctx: RouteContext, route: string, err: unknown, message: string): Response {
	ctx.auth.observability.logger.error(`mcp ${route} failed`, {
		source: "http",
		route,
		error: err instanceof Error ? err.message : String(err),
	});
	return mcpError("server_error", message, 500);
}

/** 401 for a failed client authentication, with the challenge RFC 6749 section 5.2 asks for. */
function clientAuthFailure(result: { error: { code: string; message: string } }): Response {
	const res = mcpNoStore(
		{ error: result.error.code.toLowerCase(), error_description: result.error.message },
		401,
	);
	res.headers.set("WWW-Authenticate", 'Basic realm="theauth", charset="UTF-8"');
	return res;
}

function serverMetadata(ctx: RouteContext): Response {
	if (!ctx.mcp) return notFound(NOT_CONFIGURED);
	return mcpOk(applyMountedToServerMetadata(ctx.mcp.getMetadata(), ctx.mounted));
}

function resourceMetadata(ctx: RouteContext): Response {
	if (!ctx.mcp) return notFound(NOT_CONFIGURED);
	return mcpOk(applyMountedToResourceMetadata(ctx.mcp.getProtectedResourceMetadata(), ctx.mounted));
}

async function register(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	// Registration turned off on the module (`registration.enabled: false`): the metadata no
	// longer advertises the endpoint, so the route does not exist either.
	if (mcp.getMetadata().registration_endpoint === undefined) {
		return notFound("Dynamic client registration is disabled");
	}
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) {
		const tooLarge = body.response.status === 413;
		return mcpError(
			"invalid_request",
			tooLarge ? "Request body is too large" : "Invalid JSON body",
			tooLarge ? 413 : 400,
		);
	}
	try {
		const result = await mcp.registerClient(body.data as McpClientRegistrationRequest);
		if (!result.success) return mcpError("invalid_client_metadata", result.error.message, 400);
		return mcpNoStore(result.data, 201);
	} catch (err) {
		return serverError(ctx, "register", err, "Registration failed");
	}
}

async function authorize(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	try {
		const result = await mcp.authorize(ctx.request);
		if (!result.success) {
			if (result.error.code === "LOGIN_REQUIRED") {
				const details = result.error.details as
					| { loginPage?: string; returnTo?: string }
					| undefined;
				if (details?.loginPage) {
					const loginUrl = new URL(details.loginPage);
					if (details.returnTo) loginUrl.searchParams.set("returnTo", details.returnTo);
					return Response.redirect(loginUrl.toString(), 302);
				}
			}
			return mcpError(result.error.code.toLowerCase(), result.error.message, 400);
		}
		return Response.redirect(result.data.redirectUri, 302);
	} catch (err) {
		return serverError(ctx, "authorize", err, "Authorization failed");
	}
}

function withNonce(res: Response, details: Record<string, unknown> | undefined): Response {
	const nonce = details?.dpopNonce;
	if (typeof nonce === "string") res.headers.set("DPoP-Nonce", nonce);
	return res;
}

async function token(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	const bounded = await boundedFormRequest(ctx, false);
	if (!bounded.ok) return bounded.response;
	try {
		const result = await mcp.token(bounded.request);
		if (!result.success) {
			const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
			return withNonce(
				mcpNoStore(
					{ error: result.error.code.toLowerCase(), error_description: result.error.message },
					status,
				),
				result.error.details,
			);
		}
		return mcpNoStore(result.data);
	} catch (err) {
		const res = serverError(ctx, "token", err, "Token exchange failed");
		res.headers.set("Cache-Control", "no-store");
		res.headers.set("Pragma", "no-cache");
		return res;
	}
}

/** RFC 7009: success is an empty 200, unknown tokens included. */
async function revoke(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	try {
		const body = await boundedFormRequest(ctx, false);
		if (!body.ok) return body.response;
		const result = await mcp.revoke(body.request);
		if (!result.success) {
			if (result.error.code === "INVALID_CLIENT") return clientAuthFailure(result);
			if (result.error.code === "SERVER_ERROR") {
				// RFC 7009 section 2.2.1: an unavailable server answers 503 with Retry-After.
				const wait = Number(result.error.details?.retryAfter);
				const res = mcpNoStore(
					{ error: "temporarily_unavailable", error_description: result.error.message },
					503,
				);
				res.headers.set("Retry-After", String(Number.isFinite(wait) && wait > 0 ? wait : 5));
				return res;
			}
			return withNonce(
				mcpNoStore(
					{ error: result.error.code.toLowerCase(), error_description: result.error.message },
					400,
				),
				result.error.details,
			);
		}
		return mcpNoStore({});
	} catch {
		return mcpNoStore({ error: "server_error", error_description: "Revocation failed" }, 500);
	}
}

/** RFC 7662: always `Cache-Control: no-store`. A disabled endpoint does not exist (404, and the metadata does not list it). */
async function introspect(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	if (!mcp.introspect || mcp.getMetadata().introspection_endpoint === undefined) {
		return notFound("Token introspection is not enabled");
	}
	try {
		const body = await boundedFormRequest(ctx, true);
		if (!body.ok) return body.response;
		const result = await mcp.introspect(body.request);
		if (!result.success) {
			const code = result.error.code;
			if (code === "INVALID_CLIENT") return clientAuthFailure(result);
			if (code === "RATE_LIMITED") {
				const wait = Number(result.error.details?.retryAfter);
				const res = mcpNoStore(
					{ error: "slow_down", error_description: result.error.message },
					429,
				);
				res.headers.set("Retry-After", String(Number.isFinite(wait) && wait > 0 ? wait : 60));
				return res;
			}
			if (code === "SERVER_ERROR") {
				return mcpNoStore(
					{ error: "temporarily_unavailable", error_description: result.error.message },
					503,
				);
			}
			return mcpNoStore(
				{ error: code.toLowerCase(), error_description: result.error.message },
				400,
			);
		}
		return mcpNoStore(result.data);
	} catch {
		return mcpNoStore({ error: "server_error", error_description: "Introspection failed" }, 500);
	}
}

async function jwks(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	try {
		return mcpOk(await mcp.getJwks(), 200, { "Cache-Control": "public, max-age=300" });
	} catch (err) {
		return serverError(ctx, "jwks", err, "JWKS unavailable");
	}
}

export const mcpRoutes: HttpRoute[] = [
	{
		method: "GET",
		path: "/.well-known/oauth-authorization-server",
		auth: "public",
		group: "mcp",
		summary: "OAuth authorization server metadata (RFC 8414)",
		handle: async (ctx) => serverMetadata(ctx),
	},
	{
		method: "GET",
		path: "/.well-known/oauth-protected-resource",
		auth: "public",
		group: "mcp",
		summary: "Protected resource metadata (RFC 9728)",
		handle: async (ctx) => resourceMetadata(ctx),
	},
	{
		method: "POST",
		path: "/mcp/register",
		auth: "public",
		group: "mcp",
		mcpRoute: "register",
		summary: "Dynamic client registration (RFC 7591)",
		handle: register,
	},
	{
		method: "GET",
		path: "/mcp/authorize",
		auth: "public",
		group: "mcp",
		mcpRoute: "authorize",
		summary: "Authorization endpoint (redirects to login or the client)",
		handle: authorize,
	},
	{
		method: "POST",
		path: "/mcp/token",
		auth: "client",
		group: "mcp",
		mcpRoute: "token",
		summary: "Token endpoint",
		handle: token,
	},
	{
		method: "POST",
		path: "/mcp/revoke",
		auth: "client",
		group: "mcp",
		mcpRoute: "revoke",
		summary: "Token revocation (RFC 7009)",
		handle: revoke,
	},
	{
		method: "POST",
		path: "/mcp/introspect",
		auth: "client",
		group: "mcp",
		mcpRoute: "introspect",
		summary: "Token introspection (RFC 7662)",
		handle: introspect,
	},
	{
		method: "GET",
		path: "/mcp/jwks",
		auth: "public",
		group: "mcp",
		mcpRoute: "jwks",
		summary: "Public signing keys (JWKS)",
		handle: jwks,
	},
];
