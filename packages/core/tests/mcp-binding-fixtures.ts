/** Shared fixtures for the exchange ownership, binding coverage and revoke cascade tests (database stores, three freshness modes). */
import { expect } from "vitest";
import type { McpFreshnessMode } from "../src/mcp/revocation-types.js";
import type { McpAuthModule, McpConfig, McpTokenResponse } from "../src/mcp/types.js";
import type { TheAuth } from "../src/theauth.js";
import { finishBoot } from "./mcp-db-harness.js";
import {
	BASE_URL,
	basicAuth,
	codeFlow,
	decodePayload,
	REDIRECT,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

export const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
export const AT = "urn:ietf:params:oauth:token-type:access_token";
export const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];
export const MODES: readonly McpFreshnessMode[] = ["live", "cached", "offline"];
const HOUR = 3_600_000;

export interface ClientSpec {
	id: string;
	agentId?: string;
}

export const secretOf = (id: string): string => `${id}-secret`;

function preRegistered(specs: ClientSpec[]): NonNullable<McpConfig["preRegisteredClients"]> {
	return specs.map((s) => ({
		clientId: s.id,
		clientSecret: secretOf(s.id),
		redirectUris: [REDIRECT],
		scope: "mcp:read mcp:write offline_access",
		grantTypes: ["authorization_code", "refresh_token", TE],
		...(s.agentId ? { agentId: s.agentId } : {}),
	}));
}

/** One module per freshness mode for `userId`, all on the same database. Cached polls every 20 ms. */
export async function modules(
	auth: TheAuth,
	userId: string,
	specs: ClientSpec[],
): Promise<Record<McpFreshnessMode, McpAuthModule>> {
	const build = (mode: McpFreshnessMode) =>
		finishBoot(auth, userId, {
			tokenExchange: { enabled: true, maxChainDepth: 5 },
			preRegisteredClients: preRegistered(specs),
			accessTokenTtl: 3600,
			revocation: { mode, pollIntervalMs: 20, maxStalenessMs: 60_000 },
		}).mcp;
	const out = { live: build("live"), cached: build("cached"), offline: build("offline") };
	await new Promise((r) => setTimeout(r, 30));
	return out;
}

export async function newAgent(auth: TheAuth, ownerId: string, name: string): Promise<string> {
	return (await auth.agent.create({ ownerId, name, type: "autonomous", permissions: PERMS })).id;
}

export async function delegate(auth: TheAuth, from: string, to: string): Promise<string> {
	const chain = await auth.delegate({
		fromAgent: from,
		toAgent: to,
		permissions: PERMS,
		expiresAt: new Date(Date.now() + HOUR),
	});
	return chain.id;
}

/** Authorization code token for `clientId` (offline_access, so a refresh token comes back). */
export async function userToken(mcp: McpAuthModule, clientId: string): Promise<McpTokenResponse> {
	return codeFlow({ mcp, clients: new Map(), codes: new Map(), tokens: new Map() }, clientId, {
		secret: secretOf(clientId),
		scope: "mcp:read offline_access",
	});
}

export async function exchange(
	mcp: McpAuthModule,
	clientId: string,
	subjectToken: string,
	actorToken?: string,
) {
	return mcp.token(
		tokenRequest(
			{
				grant_type: TE,
				subject_token: subjectToken,
				subject_token_type: AT,
				...(actorToken ? { actor_token: actorToken, actor_token_type: AT } : {}),
				client_id: clientId,
			},
			basicAuth(clientId, secretOf(clientId)),
		),
	);
}

export async function exchangeOk(
	mcp: McpAuthModule,
	clientId: string,
	subjectToken: string,
	actorToken?: string,
): Promise<string> {
	const res = await exchange(mcp, clientId, subjectToken, actorToken);
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data.access_token;
}

export interface CallOutcome {
	status: number;
	agent: string | null;
}

/** One protected call. Returns the status and the agent the resource server saw. */
export async function call(mcp: McpAuthModule, token: string): Promise<CallOutcome> {
	let agent: string | null = null;
	const guarded = mcp.requireMcpAuth(async (_r, p) => {
		agent = p.agent?.id ?? null;
		return new Response("ok");
	});
	const res = await guarded(
		new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } }),
	);
	return { status: res.status, agent };
}

/** Live re-check of a token that validated, the way a long running handler calls `session.revalidate()`. */
export async function revalidate(mcp: McpAuthModule, token: string): Promise<boolean> {
	const session = await mcp.validateToken(token);
	if (!session.success) return false;
	const again = await session.data.revalidate?.();
	return again?.success === true;
}

/**
 * The token is dead in `mode`. Live: next call 401. Cached: 401 within the poll window.
 * Offline: the call may still pass until `exp` (documented), and the next live revalidate fails.
 */
export async function expectDead(
	mods: Record<McpFreshnessMode, McpAuthModule>,
	mode: McpFreshnessMode,
	token: string,
): Promise<void> {
	const mcp = mods[mode];
	if (mode === "offline") {
		expect(await revalidate(mcp, token)).toBe(false);
		return;
	}
	if (mode === "cached") await new Promise((r) => setTimeout(r, 60));
	expect((await call(mcp, token)).status).toBe(401);
}

export async function rfc7009Revoke(
	mcp: McpAuthModule,
	clientId: string,
	token: string,
	hint: "access_token" | "refresh_token",
): Promise<void> {
	const res = await mcp.revoke(
		new Request(`${BASE_URL}/mcp/revoke`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				...basicAuth(clientId, secretOf(clientId)),
			},
			body: new URLSearchParams({ token, token_type_hint: hint }).toString(),
		}),
	);
	expect(res.success).toBe(true);
}

export interface Dlg {
	v: number;
	agt: string[];
	lnk: string[];
}

export const dlgOf = (token: string): Dlg | undefined =>
	decodePayload(token).theauth_dlg as Dlg | undefined;
export const agentIdOf = (token: string): unknown => decodePayload(token).agent_id;
