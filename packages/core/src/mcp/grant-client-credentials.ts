import type { GrantClientAuth } from "./grant-common.js";
import { authenticateGrantClient, narrowScopes } from "./grant-common.js";
import { GRANT_TYPE_CLIENT_CREDENTIALS } from "./grant-types.js";
import { resolveResource, supportedScopes } from "./lenient.js";
import { issueGrantToken } from "./token-issue.js";
import type { McpAuthContext, McpTokenResponse, Result } from "./types.js";

/**
 * client_credentials grant (RFC 6749 section 4.4) for confidential clients.
 * The client acts as itself: the token `sub` is the principal returned by `clientCredentials.resolvePrincipal`, never a user. Scopes are bounded by the principal (or the client's registered scope), `offline_access` is never granted and no refresh token is issued.
 */
export async function handleClientCredentialsGrant(
	ctx: McpAuthContext,
	data: { client_id: string; scope?: string | undefined; resource?: string | undefined },
	auth: GrantClientAuth,
	dpopJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	const config = ctx.config.clientCredentials;
	if (!config?.enabled) {
		return {
			success: false,
			error: { code: "UNSUPPORTED_GRANT_TYPE", message: "client_credentials is not enabled" },
		};
	}

	const authenticated = await authenticateGrantClient(
		ctx,
		data.client_id,
		GRANT_TYPE_CLIENT_CREDENTIALS,
		auth,
	);
	if (!authenticated.success) return authenticated;
	const client = authenticated.data;
	if (client.clientType !== "confidential") {
		return {
			success: false,
			error: {
				code: "UNAUTHORIZED_CLIENT",
				message: "client_credentials requires a confidential client",
			},
		};
	}

	const principal = await config.resolvePrincipal(client);
	if (!principal) {
		return {
			success: false,
			error: {
				code: "UNAUTHORIZED_CLIENT",
				message: "Client has no principal for client_credentials",
			},
		};
	}

	const bound = principal.scopes ?? (client.scope ? client.scope.split(" ").filter(Boolean) : null);
	if (!bound) {
		return {
			success: false,
			error: { code: "INVALID_SCOPE", message: "Client has no scopes it may request" },
		};
	}
	const supported = supportedScopes(ctx);
	const allowed = bound.filter((s) => s !== "offline_access" && supported.has(s));
	const scopes = narrowScopes(ctx, data.scope, allowed);
	if (!scopes.success) return scopes;
	if (scopes.data.length === 0) {
		return {
			success: false,
			error: { code: "INVALID_SCOPE", message: "No grantable scopes for this client" },
		};
	}

	const resource = resolveResource(ctx, data.resource);
	if (!resource.success) return resource;

	const agent = {
		...(principal.agentId !== undefined ? { agentId: principal.agentId } : {}),
		...(principal.agentType !== undefined ? { agentType: principal.agentType } : {}),
		...(principal.trustTier !== undefined ? { trustTier: principal.trustTier } : {}),
	};
	const response = await issueGrantToken(ctx, {
		userId: principal.subject,
		clientId: client.clientId,
		scopes: scopes.data,
		resource: resource.data,
		dpopJkt,
		options: { agent },
	});
	return { success: true, data: response };
}
