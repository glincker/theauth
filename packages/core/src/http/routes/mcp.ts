import {
	applyMountedToResourceMetadata,
	applyMountedToServerMetadata,
} from "../../mcp/metadata.js";
import type { McpClientRegistrationRequest } from "../../mcp/types.js";
import {
	MCP_CORS_HEADERS,
	mcpError,
	mcpNoStore,
	mcpOk,
	notFound,
	readJsonBody,
} from "../respond.js";
import type { HttpRoute, RouteContext } from "../types.js";

const NOT_CONFIGURED = "MCP module not configured";

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
		return mcpError(
			"server_error",
			err instanceof Error ? err.message : "Registration failed",
			500,
		);
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
		return mcpError(
			"server_error",
			err instanceof Error ? err.message : "Authorization failed",
			500,
		);
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
	try {
		const result = await mcp.token(ctx.request);
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
		return mcpNoStore(
			{
				error: "server_error",
				error_description: err instanceof Error ? err.message : "Token exchange failed",
			},
			500,
		);
	}
}

/** RFC 7009: success is an empty 200, unknown tokens included. */
async function revoke(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	try {
		const result = await mcp.revoke(ctx.request);
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
		return mcpNoStore({});
	} catch (err) {
		return mcpNoStore(
			{
				error: "server_error",
				error_description: err instanceof Error ? err.message : "Revocation failed",
			},
			500,
		);
	}
}

async function jwks(ctx: RouteContext): Promise<Response> {
	const mcp = ctx.mcp;
	if (!mcp) return notFound(NOT_CONFIGURED);
	try {
		return mcpOk(await mcp.getJwks(), 200, { "Cache-Control": "public, max-age=300" });
	} catch (err) {
		return mcpError("server_error", err instanceof Error ? err.message : "JWKS unavailable", 500);
	}
}

export function mcpPreflight(): Response {
	return new Response(null, { status: 204, headers: MCP_CORS_HEADERS });
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
		method: "GET",
		path: "/mcp/jwks",
		auth: "public",
		group: "mcp",
		mcpRoute: "jwks",
		summary: "Public signing keys (JWKS)",
		handle: jwks,
	},
];
