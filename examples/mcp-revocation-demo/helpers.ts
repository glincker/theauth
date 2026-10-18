/**
 * Plumbing for demo.ts: one theAuth instance, three MCP modules that differ only in freshness
 * mode, and a function that mints a delegated token for a fresh owner, assistant and sub-agent.
 *
 * Imports point at the built package (packages/core/dist) so this directory needs no package.json
 * and no node_modules. In your own app, import from "@glinr/theauth" and "@glinr/theauth/mcp".
 */

import { createHash, randomBytes } from "node:crypto";
import { createTheAuth, recordAuditEvent } from "../../packages/core/dist/index.js";
import type { McpConfig, McpFreshnessMode } from "../../packages/core/dist/mcp/index.js";
import {
	createDbDelegationStore,
	createInMemoryJtiDenylist,
	createMcpModule,
} from "../../packages/core/dist/mcp/index.js";

export type TheAuthInstance = Awaited<ReturnType<typeof createTheAuth>>;
export type McpModule = ReturnType<typeof createMcpModule>;

export const ISSUER = "https://auth.demo.test";
export const RESOURCE = "https://reports.demo.test/mcp";
const SIGNING_SECRET = "mcp-revocation-demo-secret-at-least-32-chars-long";
const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const REDIRECT_URI = "http://127.0.0.1/callback";

/** Resource server that is entitled to introspect tokens for RESOURCE. */
export const ORDERS_API = { clientId: "orders-api", clientSecret: "orders-api-secret" };
/** A caller that is not listed in `introspection.resourceServers`. */
export const STRANGER_API = { clientId: "stranger-api", clientSecret: "stranger-api-secret" };

/** Each tool and the OAuth scope it needs. */
export const TOOL_SCOPES: Record<string, string> = {
	read_report: "mcp:read",
	delete_report: "mcp:write",
};

export function header(text: string): void {
	console.log(`\n=== ${text}`);
}

export function say(text: string): void {
	console.log(`    # ${text}`);
}

export function line(label: string, value: string): void {
	console.log(`    ${label.padEnd(20)} ${value}`);
}

export function basic(clientId: string, secret: string): string {
	return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`;
}

/** Decode a JWT payload for display. The raw token is never printed. */
export function decodePayload(token: string): Record<string, unknown> {
	const part = token.split(".")[1] ?? "";
	return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
}

function baseConfig(mode: McpFreshnessMode): McpConfig {
	return {
		enabled: true,
		issuer: ISSUER,
		baseUrl: `${ISSUER}/api/auth`,
		resource: RESOURCE,
		signingSecret: SIGNING_SECRET,
		scopes: ["mcp:read", "mcp:write"],
		accessTokenTtl: 3600,
		jtiDenylist: createInMemoryJtiDenylist(),
		tokenExchange: { enabled: true },
		// Short numbers so a cached run finishes in about a second. Defaults are 1000 and 5000.
		revocation: { mode, pollIntervalMs: 200, maxStalenessMs: 1000 },
	};
}

export interface World {
	auth: TheAuthInstance;
	/** Issues tokens, validates live, answers introspection. */
	live: McpModule;
	/** A second resource server in cached mode. It has no revocation bus, like another instance. */
	cached: McpModule;
	/** A third resource server that only checks signature and exp. */
	offline: McpModule;
	/** Which owner `resolveUserId` answers for. The demo switches it per scenario. */
	currentOwner: { id: string };
	rootAgentByOwner: Map<string, string>;
}

export async function buildWorld(): Promise<World> {
	const auth = await createTheAuth({
		// Enabling mcp here creates the OAuth tables in the database.
		mcp: baseConfig("live"),
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 20,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
	const currentOwner = { id: "" };
	const rootAgentByOwner = new Map<string, string>();

	const liveConfig: McpConfig = {
		...baseConfig("live"),
		introspection: {
			enabled: true,
			resourceServers: [{ clientId: ORDERS_API.clientId, audiences: [RESOURCE] }],
		},
		preRegisteredClients: [ORDERS_API, STRANGER_API].map((c) => ({
			...c,
			redirectUris: [REDIRECT_URI],
			clientName: c.clientId,
			scope: "mcp:read",
			grantTypes: ["authorization_code"],
		})),
		// Walk the delegation chain against live rows on every request.
		delegationStore: createDbDelegationStore(auth.db),
		resolveActorAgentId: ({ sub }) => rootAgentByOwner.get(sub),
	};
	const resolveUserId = async (): Promise<string> => currentOwner.id;
	const live = createMcpModule({ auth, config: liveConfig, resolveUserId });
	// Passing only `db` leaves out the in-process revocation bus, so this module learns about a
	// revoke the way a second server instance would: by polling the shared table.
	const cached = createMcpModule({
		auth: { db: auth.db },
		config: baseConfig("cached"),
		resolveUserId,
	});
	const offline = createMcpModule({ auth, config: baseConfig("offline"), resolveUserId });
	return { auth, live, cached, offline, currentOwner, rootAgentByOwner };
}

export interface Delegated {
	ownerId: string;
	assistantId: string;
	subAgentId: string;
	chainId: string;
	subClientId: string;
	token: string;
}

function b64url(input: Uint8Array): string {
	return Buffer.from(input).toString("base64url");
}

/**
 * Create an owner, an assistant with read and write, a sub-agent delegated read only, an MCP
 * client bound to the sub-agent, then mint a narrowed token through RFC 8693 token exchange.
 */
export async function mintDelegatedToken(world: World, ownerId: string): Promise<Delegated> {
	const { auth, live } = world;
	await auth.user.create({ id: ownerId, email: `${ownerId}@example.com`, name: ownerId });
	const assistant = await auth.agent.create({
		ownerId,
		name: `${ownerId}-assistant`,
		type: "autonomous",
		permissions: [{ resource: "mcp:reports:*", actions: ["read", "write"] }],
	});
	const subAgent = await auth.agent.create({
		ownerId,
		name: `${ownerId}-sub-agent`,
		type: "delegated",
		permissions: [],
	});
	const chain = await auth.delegate({
		fromAgent: assistant.id,
		toAgent: subAgent.id,
		permissions: [{ resource: "mcp:reports:*", actions: ["read"] }],
		expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		maxDepth: 1,
	});
	world.rootAgentByOwner.set(ownerId, assistant.id);
	world.currentOwner.id = ownerId;

	const register = async (
		name: string,
		agentId: string,
		grants: string[],
	): Promise<{ clientId: string; header: string }> => {
		const registered = await live.registerClient({
			redirect_uris: [REDIRECT_URI],
			grant_types: grants,
			token_endpoint_auth_method: "client_secret_basic",
			client_name: name,
			scope: "mcp:read mcp:write",
		});
		if (!registered.success) throw new Error(registered.error.message);
		const { client_id: clientId, client_secret: clientSecret } = registered.data;
		if (!clientSecret) throw new Error("expected a client secret");
		// Tokens issued to this client now carry agent_id, and the delegation walk resolves it.
		await live.clients.bindAgent(clientId, agentId);
		return { clientId, header: basic(clientId, clientSecret) };
	};
	const assistantApp = await register(`${ownerId} assistant app`, assistant.id, [
		"authorization_code",
	]);
	const subApp = await register(`${ownerId} sub-agent app`, subAgent.id, [TOKEN_EXCHANGE]);

	const form = (authHeader: string, params: Record<string, string>): Request =>
		new Request(`${ISSUER}/api/auth/mcp/token`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: authHeader },
			body: new URLSearchParams(params).toString(),
		});

	// The user approves the assistant app (authorization code with PKCE).
	const verifier = b64url(randomBytes(32));
	const url = new URL(`${ISSUER}/api/auth/mcp/authorize`);
	for (const [k, v] of Object.entries({
		response_type: "code",
		client_id: assistantApp.clientId,
		redirect_uri: REDIRECT_URI,
		scope: "mcp:read mcp:write",
		code_challenge: b64url(createHash("sha256").update(verifier).digest()),
		code_challenge_method: "S256",
		resource: RESOURCE,
	}))
		url.searchParams.set(k, v);
	const authorized = await live.authorize(new Request(url));
	if (!authorized.success) throw new Error(authorized.error.message);
	const granted = await live.token(
		form(assistantApp.header, {
			grant_type: "authorization_code",
			code: authorized.data.code,
			redirect_uri: REDIRECT_URI,
			client_id: assistantApp.clientId,
			code_verifier: verifier,
			resource: RESOURCE,
		}),
	);
	if (!granted.success) throw new Error(granted.error.message);

	// The sub-agent app narrows the assistant's token to mcp:read (RFC 8693). It can only narrow.
	const exchanged = await live.token(
		form(subApp.header, {
			grant_type: TOKEN_EXCHANGE,
			subject_token: granted.data.access_token,
			subject_token_type: ACCESS_TOKEN_TYPE,
			scope: "mcp:read",
			resource: RESOURCE,
		}),
	);
	if (!exchanged.success) throw new Error(exchanged.error.message);
	return {
		ownerId,
		assistantId: assistant.id,
		subAgentId: subAgent.id,
		chainId: chain.id,
		subClientId: subApp.clientId,
		token: exchanged.data.access_token,
	};
}

export interface ToolOutcome {
	status: number;
	code: string;
	detail: string;
}

/**
 * What an MCP server does per tool call: check the bearer token and the scope the tool needs, and
 * write one audit row for the outcome. The row lands under the agent the token belonged to.
 */
export async function callTool(
	world: World,
	module: McpModule,
	token: string,
	tool: string,
	assistantId: string,
): Promise<ToolOutcome> {
	const scope = TOOL_SCOPES[tool];
	if (!scope) throw new Error(`unknown tool ${tool}`);
	const request = new Request(`${RESOURCE}/tools/call`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}` },
	});
	const check = await module.requireScopes(request, [scope]);
	if (!check.authorized) {
		const agentId = check.rejected?.agentId;
		if (agentId) {
			await recordAuditEvent(world.auth.db, {
				agentId,
				action: "mcp.tools.call",
				resource: `mcp:reports:${tool}`,
				result: "denied",
				reason: `${check.error.code}: ${check.error.message}`,
				delegationChain: [assistantId, agentId],
			});
		}
		return { status: check.status, code: check.error.code, detail: check.error.message };
	}
	const agentId = check.session.agent?.id;
	if (agentId) {
		await recordAuditEvent(world.auth.db, {
			agentId,
			action: "mcp.tools.call",
			resource: `mcp:reports:${tool}`,
			result: "allowed",
			reason: `scope ${scope} granted`,
			subjectId: check.session.userId,
			actorId: check.session.clientId,
			delegationChain: [assistantId, agentId],
		});
	}
	return { status: 200, code: "OK", detail: `${tool} ran` };
}

/** RFC 7662 call as a resource server. Returns the JSON body. */
export async function introspect(
	live: McpModule,
	caller: { clientId: string; clientSecret: string },
	token: string,
): Promise<Record<string, unknown>> {
	const result = await live.introspect(
		new Request(`${ISSUER}/api/auth/mcp/introspect`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: basic(caller.clientId, caller.clientSecret),
			},
			body: new URLSearchParams({ token }).toString(),
		}),
	);
	if (!result.success) throw new Error(result.error.message);
	return result.data as unknown as Record<string, unknown>;
}
