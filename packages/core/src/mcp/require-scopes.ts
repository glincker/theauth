import { buildStepUpResponse } from "./step-up.js";
import type { McpAuthContext, McpSession } from "./types.js";
import { extractBearerToken } from "./utils.js";
import { buildUnauthorizedResponse, validateAccessToken } from "./validate.js";

// ─── Scope challenge helper ───────────────────────────────────────────────────

/**
 * Validate the Bearer token on a request and assert that it carries all of
 * the `requiredScopes`.
 *
 * Encapsulates the three-branch decision MCP resource servers need to make:
 *
 *  1. No token (or malformed token)  → 401 Unauthorized
 *  2. Valid token, missing scopes    → 403 with step-up challenge
 *  3. Valid token, all scopes present → session returned to the caller
 *
 * Usage:
 * ```typescript
 * const check = await requireScopes(ctx, request, ['mcp:write']);
 * if (!check.authorized) return check.response;
 * // check.session is available here
 * ```
 */
export async function requireScopes(
	ctx: McpAuthContext,
	request: Request,
	requiredScopes: string[],
): Promise<{ authorized: true; session: McpSession } | { authorized: false; response: Response }> {
	// ── Step 1: Extract Bearer token ────────────────────────────────
	const token = extractBearerToken(request);

	if (!token) {
		return {
			authorized: false,
			response: buildUnauthorizedResponse(ctx, {
				code: "UNAUTHORIZED",
				message: "Bearer token required",
			}),
		};
	}

	// ── Step 2: Validate the token (without scope enforcement yet) ──
	// We validate first without requiredScopes so we can distinguish
	// "bad token" (401) from "valid token but wrong scopes" (403).
	const tokenResult = await validateAccessToken(ctx, token, {
		expectedAudience: ctx.config.resource,
	});

	if (!tokenResult.success) {
		return {
			authorized: false,
			response: buildUnauthorizedResponse(ctx, {
				code: tokenResult.error.code,
				message: tokenResult.error.message,
			}),
		};
	}

	const session = tokenResult.data;

	// ── Step 3: Check required scopes ───────────────────────────────
	if (requiredScopes.length > 0) {
		const missingScopes = requiredScopes.filter((s) => !session.scopes.includes(s));

		if (missingScopes.length > 0) {
			return {
				authorized: false,
				response: buildStepUpResponse(ctx, {
					currentScopes: session.scopes,
					requiredScopes,
					resource: session.resource ?? undefined,
				}),
			};
		}
	}

	// ── Step 4: All checks passed ────────────────────────────────────
	return { authorized: true, session };
}
