import { resolveClient } from "./client-metadata.js";
import type { McpAuthContext, McpAuthorizationCode, McpAuthorizeResult, Result } from "./types.js";
import { McpAuthorizeRequestSchema } from "./types.js";
import { generateAuthorizationCode } from "./utils.js";

/**
 * Handle the OAuth 2.1 authorization endpoint.
 *
 * GET /mcp/authorize
 *
 * Validates the request parameters, checks the client, enforces PKCE S256,
 * validates Resource Indicators (RFC 8707), and issues an authorization code.
 *
 * The caller is responsible for authenticating the user before calling this
 * function.  The `ctx.resolveUserId(request)` hook must return a non-null
 * user ID for the currently authenticated user.
 */
export async function handleAuthorize(
	ctx: McpAuthContext,
	request: Request,
): Promise<Result<McpAuthorizeResult>> {
	// ── Parse query parameters ──────────────────────────────────────
	const url = new URL(request.url);
	const params: Record<string, string> = {};
	for (const [key, value] of url.searchParams.entries()) {
		params[key] = value;
	}

	const parsed = McpAuthorizeRequestSchema.safeParse(params);
	if (!parsed.success) {
		return {
			success: false,
			error: {
				code: "INVALID_REQUEST",
				message: "Invalid authorization request parameters",
				details: { issues: parsed.error.flatten().fieldErrors },
			},
		};
	}

	const {
		client_id: clientId,
		redirect_uri: redirectUri,
		scope: scopeParam,
		state,
		code_challenge: codeChallenge,
		code_challenge_method: codeChallengeMethod,
		resource,
	} = parsed.data;

	// ── Validate client ─────────────────────────────────────────────
	const client = await resolveClient(ctx, clientId);
	if (!client) {
		return {
			success: false,
			error: {
				code: "INVALID_CLIENT",
				message: `Unknown client_id: ${clientId}`,
			},
		};
	}

	if (client.disabled) {
		return {
			success: false,
			error: {
				code: "INVALID_CLIENT",
				message: "Client is disabled",
			},
		};
	}

	// ── Validate redirect_uri ───────────────────────────────────────
	if (!client.redirectUris.includes(redirectUri)) {
		return {
			success: false,
			error: {
				code: "INVALID_REDIRECT_URI",
				message: "redirect_uri does not match any registered redirect URI",
			},
		};
	}

	// ── PKCE validation: S256 only ──────────────────────────────────
	if (codeChallengeMethod !== "S256") {
		return {
			success: false,
			error: {
				code: "INVALID_REQUEST",
				message: "Only S256 code_challenge_method is supported",
			},
		};
	}

	// ── Validate resource parameter (RFC 8707) ──────────────────────
	{
		const allowedResources = ctx.config.allowedResources;
		if (allowedResources && allowedResources.length > 0) {
			if (!allowedResources.includes(resource)) {
				return {
					success: false,
					error: {
						code: "INVALID_TARGET",
						message: `Resource '${resource}' is not a recognized MCP server`,
					},
				};
			}
		}
	}

	// ── Validate scopes ─────────────────────────────────────────────
	const requestedScopes = scopeParam ? scopeParam.split(" ").filter(Boolean) : [];
	const supportedScopes = new Set(ctx.config.scopes ?? []);
	const defaultScopes = new Set(["openid", "profile", "email", "offline_access"]);
	const allSupported = new Set([...supportedScopes, ...defaultScopes]);

	for (const scope of requestedScopes) {
		if (!allSupported.has(scope)) {
			return {
				success: false,
				error: {
					code: "INVALID_SCOPE",
					message: `Unsupported scope: ${scope}`,
				},
			};
		}
	}

	const effectiveScopes = requestedScopes.length > 0 ? requestedScopes : ["openid"];

	// ── Resolve authenticated user ──────────────────────────────────
	const userId = await ctx.resolveUserId(request);
	if (!userId) {
		return {
			success: false,
			error: {
				code: "LOGIN_REQUIRED",
				message: "User must be authenticated before authorization",
				details: {
					loginPage: ctx.config.loginPage,
					// Pass all original query params so the login page can redirect back
					returnTo: request.url,
				},
			},
		};
	}

	// ── Consent page redirect ───────────────────────────────────────
	// When a consent page is configured, redirect the user to it instead
	// of issuing an authorization code immediately.  The consent page
	// collects explicit user approval and then calls approveConsent().
	if (ctx.config.consentPage) {
		const consentUrl = new URL(ctx.config.consentPage);
		consentUrl.searchParams.set("client_id", clientId);
		consentUrl.searchParams.set("redirect_uri", redirectUri);
		consentUrl.searchParams.set("scope", effectiveScopes.join(" "));
		if (state) {
			consentUrl.searchParams.set("state", state);
		}
		consentUrl.searchParams.set("code_challenge", codeChallenge);
		consentUrl.searchParams.set("code_challenge_method", codeChallengeMethod);
		consentUrl.searchParams.set("resource", resource);
		return {
			success: true,
			data: {
				redirectUri: consentUrl.toString(),
				code: "",
				state: state ?? null,
			},
		};
	}

	// ── Generate authorization code ─────────────────────────────────
	const code = generateAuthorizationCode();
	const now = new Date();
	const expiresAt = new Date(now.getTime() + ctx.config.codeTtl * 1000);

	const authCode: McpAuthorizationCode = {
		code,
		clientId,
		userId,
		redirectUri,
		scope: effectiveScopes,
		codeChallenge,
		codeChallengeMethod: "S256",
		resource,
		expiresAt,
		createdAt: now,
	};

	await ctx.storeAuthorizationCode(authCode);

	// ── Build redirect ──────────────────────────────────────────────
	const redirectUrl = new URL(redirectUri);
	redirectUrl.searchParams.set("code", code);
	if (state) {
		redirectUrl.searchParams.set("state", state);
	}
	// RFC 9207: tell the client which authorization server answered.
	redirectUrl.searchParams.set("iss", ctx.config.issuer);

	return {
		success: true,
		data: {
			redirectUri: redirectUrl.toString(),
			code,
			state: state ?? null,
		},
	};
}
