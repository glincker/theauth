/** Shared fixture for the introspection and revocation endpoint tests: MCP contexts on one TheAuth database, no server.ts wiring needed. */

import { attachBindingStore } from "../src/mcp/binding.js";
import { attachFreshnessDeps } from "../src/mcp/freshness.js";
import { handleIntrospection } from "../src/mcp/introspect.js";
import { getAuthorizationServerMetadata } from "../src/mcp/metadata.js";
import { handleRevocation } from "../src/mcp/revocation.js";
import type { McpDelegationBinding } from "../src/mcp/revocation-types.js";
import { createMcpStores } from "../src/mcp/stores-db.js";
import { createDbBindingStore } from "../src/mcp/stores-db-binding.js";
import { createDbRevocationStore } from "../src/mcp/stores-db-revocation.js";
import type { IssueAccessTokenOptions } from "../src/mcp/token-issue.js";
import { issueAccessTokenJwt } from "../src/mcp/token-issue.js";
import type { McpAuthContext, McpAuthModule, McpClient, McpConfig } from "../src/mcp/types.js";
import { hashClientSecret } from "../src/mcp/utils.js";
import type { DbHarness } from "./mcp-db-harness.js";
import { bootDb, mcpConfig } from "./mcp-db-harness.js";
import { BASE_URL, basicAuth } from "./mcp-test-harness.js";

export const RS_AUDIENCE = "https://mcp.theauth.test";
export const INTROSPECT_URL = `${BASE_URL}/mcp/introspect`;
export const REVOKE_URL = `${BASE_URL}/mcp/revoke`;
export const SECRETS: Record<string, string> = {
	app: "app-secret",
	rs: "rs-secret",
	other: "o-secret",
};

export interface EndpointWorld {
	d: DbHarness;
	/** A new instance: own freshness state and replay cache, same database. */
	instance: (extra?: Partial<McpConfig>) => McpAuthContext;
	ctx: McpAuthContext;
	/** Issue a token for the bound client `app` (or another client). */
	issue: (opts?: {
		clientId?: string;
		binding?: McpDelegationBinding | null;
		ttlSeconds?: number;
		dpopJkt?: string | null;
		agentId?: string;
		resource?: string;
	}) => Promise<{ jwt: string; jti: string }>;
	addClient: (clientId: string, opts?: { agentId?: string; public?: boolean }) => Promise<void>;
	/** A module-shaped view of `ctx` for the HTTP handler. */
	module: (ctx?: McpAuthContext) => McpAuthModule;
}

export function formRequest(
	url: string,
	body: Record<string, string>,
	headers: Record<string, string> = {},
): Request {
	return new Request(url, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
		body: new URLSearchParams(body).toString(),
	});
}

export function introspectAs(
	ctx: McpAuthContext,
	clientId: string,
	token: string,
	extra: Record<string, string> = {},
) {
	return handleIntrospection(
		ctx,
		formRequest(INTROSPECT_URL, { token, ...extra }, basicAuth(clientId, SECRETS[clientId] ?? "x")),
	);
}

export function revokeAs(ctx: McpAuthContext, clientId: string, token: string, hint?: string) {
	return handleRevocation(
		ctx,
		formRequest(
			REVOKE_URL,
			{ token, ...(hint ? { token_type_hint: hint } : {}) },
			basicAuth(clientId, SECRETS[clientId] ?? "x"),
		),
	);
}

export async function bootEndpoints(extra: Partial<McpConfig> = {}): Promise<EndpointWorld> {
	const d = await bootDb();
	const revocations = createDbRevocationStore(d.auth.db);
	const bindings = createDbBindingStore(d.auth.db);
	const stores = createMcpStores(d.auth.db, { refreshTokenTtl: 86400 });

	const instance = (more: Partial<McpConfig> = {}): McpAuthContext => {
		const ctx: McpAuthContext = {
			config: {
				...mcpConfig(),
				issuer: mcpConfig().issuer,
				baseUrl: BASE_URL,
				accessTokenTtl: 3600,
				refreshTokenTtl: 86400,
				refreshTokenAbsoluteTtl: 864000,
				codeTtl: 600,
				jtiDenylist: revocations,
				introspection: {
					enabled: true,
					resourceServers: [{ clientId: "rs", audiences: [RS_AUDIENCE] }],
				},
				...extra,
				...more,
			},
			storeClient: stores.storeClient,
			findClient: stores.findClient,
			storeAuthorizationCode: stores.storeAuthorizationCode,
			consumeAuthorizationCode: stores.consumeAuthorizationCode,
			storeToken: stores.storeToken,
			findTokenByRefreshToken: stores.findTokenByRefreshToken,
			revokeToken: stores.revokeToken,
			revokeTokenFamily: stores.revokeTokenFamily,
			updateClientSecret: stores.updateClientSecret,
			tokenFamilies: stores.tokenFamilies,
			resolveUserId: async () => d.userId,
		};
		attachBindingStore(ctx, bindings);
		attachFreshnessDeps(ctx, { revocations, bindings });
		return ctx;
	};
	const ctx = instance();

	const addClient = async (
		clientId: string,
		opts: { agentId?: string; public?: boolean } = {},
	): Promise<void> => {
		const now = new Date();
		const client: McpClient = {
			clientId,
			clientSecret: opts.public ? null : await hashClientSecret(SECRETS[clientId] ?? "x"),
			clientName: null,
			clientUri: null,
			logoUri: null,
			redirectUris: [],
			grantTypes: ["authorization_code", "refresh_token"],
			responseTypes: ["code"],
			tokenEndpointAuthMethod: opts.public ? "none" : "client_secret_basic",
			scope: null,
			contacts: null,
			tosUri: null,
			policyUri: null,
			softwareId: null,
			softwareVersion: null,
			clientType: opts.public ? "public" : "confidential",
			disabled: false,
			userId: null,
			agentId: opts.agentId ?? null,
			createdAt: now,
			updatedAt: now,
		};
		await ctx.storeClient(client);
	};

	const issue: EndpointWorld["issue"] = async (opts = {}) => {
		const options: IssueAccessTokenOptions = {
			...(opts.ttlSeconds !== undefined ? { ttlSeconds: opts.ttlSeconds } : {}),
			...(opts.binding !== undefined ? { binding: opts.binding } : {}),
			...(opts.agentId ? { agent: { agentId: opts.agentId } } : {}),
		};
		const out = await issueAccessTokenJwt(
			ctx,
			d.userId,
			opts.clientId ?? "app",
			["mcp:read", "mcp:write"],
			opts.resource ?? RS_AUDIENCE,
			opts.dpopJkt ?? null,
			options,
		);
		return { jwt: out.jwt, jti: out.jti };
	};

	const module = (target: McpAuthContext = ctx): McpAuthModule => ({
		...d.mcp,
		getMetadata: () => getAuthorizationServerMetadata(target),
		introspect: (request) => handleIntrospection(target, request),
		revoke: (request) => handleRevocation(target, request),
	});

	await addClient("app");
	await addClient("rs");
	await addClient("other");
	return { d, instance, ctx, issue, addClient, module };
}
