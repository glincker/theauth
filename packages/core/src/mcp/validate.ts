import { jwtVerify } from "jose";
import type { McpAuthContext, McpSession, McpTokenPayload, Result } from "./types.js";
import { extractBearerToken } from "./utils.js";

/**
 * Derive the HMAC verification key from the config's signing secret.
 */
async function getVerificationKey(secret: string): Promise<CryptoKey> {
	const encoder = new TextEncoder();
	return globalThis.crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["verify"],
	);
}

/**
 * Validate an MCP access token (JWT).
 *
 * Performs:
 * 1. JWT signature verification (HS256)
 * 2. Expiry check
 * 3. Issuer validation
 * 4. Audience validation (token must be bound to the expected resource)
 * 5. Scope validation (optional - checks all required scopes are present)
 *
 * Target: < 5ms with cached keys (per CLAUDE.md performance rule).
 */
export async function validateAccessToken(
	ctx: McpAuthContext,
	token: string,
	options?: {
		requiredScopes?: string[];
		expectedAudience?: string;
	},
): Promise<Result<McpSession>> {
	const secret = ctx.config.signingSecret;
	if (!secret) {
		return {
			success: false,
			error: {
				code: "SERVER_ERROR",
				message: "MCP signingSecret is not configured",
			},
		};
	}

	// ── Verify JWT ──────────────────────────────────────────────────
	let payload: McpTokenPayload;
	try {
		const key = await getVerificationKey(secret);
		const result = await jwtVerify(token, key, {
			issuer: ctx.config.issuer,
			algorithms: ["HS256"],
			...(options?.expectedAudience ? { audience: options.expectedAudience } : {}),
		});
		payload = result.payload as unknown as McpTokenPayload;
	} catch (err) {
		const message = err instanceof Error ? err.message : "Token verification failed";

		// Map jose errors to meaningful error codes
		let code = "INVALID_TOKEN";
		if (message.includes("expired")) {
			code = "TOKEN_EXPIRED";
		} else if (message.includes("audience")) {
			code = "INVALID_AUDIENCE";
		} else if (message.includes("issuer")) {
			code = "INVALID_ISSUER";
		}

		return {
			success: false,
			error: { code, message },
		};
	}

	// ── Validate required fields exist ──────────────────────────────
	if (!payload.sub || !payload.client_id || !payload.jti) {
		return {
			success: false,
			error: {
				code: "INVALID_TOKEN",
				message: "Token is missing required claims (sub, client_id, jti)",
			},
		};
	}

	// ── Audience validation (mandatory per MCP spec) ────────────────
	// If no explicit audience was provided to check, we still verify
	// the token has an audience claim.
	const audience = payload.aud;
	if (!audience) {
		return {
			success: false,
			error: {
				code: "INVALID_AUDIENCE",
				message: "Token has no audience claim. Tokens must be bound to a resource.",
			},
		};
	}

	// ── Scope validation ────────────────────────────────────────────
	const tokenScopes = payload.scope ? payload.scope.split(" ") : [];
	const requiredScopes = options?.requiredScopes ?? [];

	for (const required of requiredScopes) {
		if (!tokenScopes.includes(required)) {
			return {
				success: false,
				error: {
					code: "INSUFFICIENT_SCOPE",
					message: `Token is missing required scope: ${required}`,
					details: {
						required: requiredScopes,
						present: tokenScopes,
					},
				},
			};
		}
	}

	// ── Determine resource from audience ────────────────────────────
	const resource = Array.isArray(audience) ? (audience[0] ?? null) : audience;

	// ── Build session ───────────────────────────────────────────────
	const session: McpSession = {
		userId: payload.sub,
		clientId: payload.client_id,
		scopes: tokenScopes,
		resource,
		expiresAt: new Date(payload.exp * 1000),
		tokenId: payload.jti,
	};

	return { success: true, data: session };
}

/**
 * MCP auth middleware.
 *
 * Extracts the Bearer token from the Authorization header, validates it,
 * and returns the session.  This is the primary entry point for protecting
 * MCP resource server endpoints.
 *
 * Pattern inspired by better-auth's `withMcpAuth()`, adapted to TheAuth's
 * functional Result-based API.
 *
 * Usage:
 * ```typescript
 * const result = await withMcpAuth(ctx, request, { requiredScopes: ['read'] });
 * if (!result.success) {
 *   return new Response(JSON.stringify(result.error), { status: 401 });
 * }
 * const session = result.data;
 * ```
 */
export async function withMcpAuth(
	ctx: McpAuthContext,
	request: Request,
	options?: {
		requiredScopes?: string[];
		expectedAudience?: string;
	},
): Promise<Result<McpSession>> {
	const token = extractBearerToken(request);

	if (!token) {
		const resourceMetadataUrl = `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;

		return {
			success: false,
			error: {
				code: "UNAUTHORIZED",
				message: "Bearer token required",
				details: {
					"www-authenticate": `Bearer resource_metadata="${resourceMetadataUrl}"`,
				},
			},
		};
	}

	return validateAccessToken(ctx, token, options);
}

/**
 * Build a 401 Unauthorized response in the JSON-RPC format expected
 * by MCP clients.
 *
 * Includes the WWW-Authenticate header pointing to the protected
 * resource metadata document, as required by the MCP spec.
 */
export function buildUnauthorizedResponse(
	ctx: McpAuthContext,
	error: { code: string; message: string },
): Response {
	const resourceMetadataUrl = `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;

	const wwwAuthenticate = `Bearer resource_metadata="${resourceMetadataUrl}"`;

	return new Response(
		JSON.stringify({
			jsonrpc: "2.0",
			error: {
				code: -32000,
				message: error.message,
				"www-authenticate": wwwAuthenticate,
			},
			id: null,
		}),
		{
			status: 401,
			headers: {
				"Content-Type": "application/json",
				"WWW-Authenticate": wwwAuthenticate,
				"Access-Control-Expose-Headers": "WWW-Authenticate",
			},
		},
	);
}
