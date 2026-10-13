import { authenticateClient } from "./client-auth.js";
import { resolveClient } from "./client-metadata.js";
import { supportedScopes } from "./lenient.js";
import type { McpAuthContext, McpClient, Result } from "./types.js";

/** How the client proved itself on this request. */
export interface GrantClientAuth {
	clientSecret: string | null;
	/** True when a `private_key_jwt` assertion was already verified. */
	assertionVerified: boolean;
}

/**
 * Look up the client, refuse a disabled one, and authenticate it (secret or an
 * already verified `private_key_jwt` assertion). Shared by every grant.
 */
export async function resolveAuthenticatedClient(
	ctx: McpAuthContext,
	clientId: string,
	auth: GrantClientAuth,
): Promise<Result<McpClient>> {
	const client = await resolveClient(ctx, clientId);
	if (!client) {
		return { success: false, error: { code: "INVALID_CLIENT", message: "Unknown client_id" } };
	}
	if (client.disabled) {
		return { success: false, error: { code: "INVALID_CLIENT", message: "Client is disabled" } };
	}
	const authenticated = await authenticateClient(
		ctx,
		client,
		auth.clientSecret,
		auth.assertionVerified,
	);
	if (!authenticated.success) return authenticated;
	return { success: true, data: client };
}

/**
 * Resolve and authenticate the client of a non-interactive grant, then check
 * it is registered for `grantType`. Authentication comes first so a probe
 * cannot learn which grants an unauthenticated client holds.
 */
export async function authenticateGrantClient(
	ctx: McpAuthContext,
	clientId: string,
	grantType: string,
	auth: GrantClientAuth,
): Promise<Result<McpClient>> {
	const resolved = await resolveAuthenticatedClient(ctx, clientId, auth);
	if (!resolved.success) return resolved;
	if (!resolved.data.grantTypes.includes(grantType)) {
		return {
			success: false,
			error: {
				code: "UNAUTHORIZED_CLIENT",
				message: "Client is not registered for this grant type",
			},
		};
	}
	return resolved;
}

/**
 * Narrow scopes: the result is the requested set (or all of `allowed` when
 * none were requested), and never contains anything outside `allowed`.
 * With `lenientClients.dropUnknownScopes`, scopes the server does not support
 * at all are dropped first; the request only fails if none remain.
 */
export function narrowScopes(
	ctx: McpAuthContext,
	requestedParam: string | undefined,
	allowed: string[],
): Result<string[]> {
	let requested = requestedParam ? requestedParam.split(" ").filter(Boolean) : [];
	if (requested.length === 0) return { success: true, data: allowed };
	if (ctx.config.lenientClients?.dropUnknownScopes === true) {
		const supported = supportedScopes(ctx);
		requested = requested.filter((s) => supported.has(s));
		if (requested.length === 0) {
			return {
				success: false,
				error: { code: "INVALID_SCOPE", message: "None of the requested scopes are supported" },
			};
		}
	}
	const outside = requested.filter((s) => !allowed.includes(s));
	if (outside.length > 0) {
		return {
			success: false,
			error: {
				code: "INVALID_SCOPE",
				message: `Scope not permitted for this grant: ${outside.join(" ")}`,
			},
		};
	}
	return { success: true, data: [...new Set(requested)] };
}
