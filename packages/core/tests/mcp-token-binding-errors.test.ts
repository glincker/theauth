/** Token endpoint behavior when a token cannot be bound: invalid_grant (400), never a 500; code ordering; capped expires_in. */
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { oauthAuthorizationCodes } from "../src/db/schema.js";
import type { McpAuthModule, McpConfig, McpTokenResponse, Result } from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import type { DbHarness } from "./mcp-db-harness.js";
import { bootDb, finishBoot } from "./mcp-db-harness.js";
import type { KeyMaterial } from "./mcp-test-harness.js";
import {
	BASE_URL,
	basicAuth,
	decodePayload,
	ISSUER,
	newKeys,
	REDIRECT,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const JB = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const IDP = "https://idp.corp.example.com";
const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];
const SECRET = "client-secret";
const NAMES = ["code", "refresh", "cc", "jb", "short"] as const;
type Name = (typeof NAMES)[number];

interface World {
	d: DbHarness;
	mcp: McpAuthModule;
	agents: Record<Name, string>;
	keys: KeyMaterial;
}

async function world(): Promise<World> {
	const base = await bootDb();
	const agents = {} as Record<Name, string>;
	for (const name of NAMES) {
		const created = await base.auth.agent.create({
			ownerId: base.userId,
			name,
			type: "autonomous",
			permissions: PERMS,
			...(name === "short" ? { expiresAt: new Date(Date.now() + 120_000) } : {}),
		});
		agents[name] = created.id;
	}
	const keys = await newKeys();
	const bound = (id: Name, grantTypes: string[]) => ({
		clientId: id,
		clientSecret: SECRET,
		redirectUris: [REDIRECT],
		scope: "mcp:read offline_access",
		grantTypes,
		agentId: agents[id],
	});
	const config: Partial<McpConfig> = {
		preRegisteredClients: [
			bound("code", ["authorization_code", "refresh_token"]),
			bound("refresh", ["authorization_code", "refresh_token"]),
			bound("short", ["authorization_code", "refresh_token", "client_credentials"]),
			bound("cc", ["client_credentials"]),
			bound("jb", [JB]),
		],
		clientCredentials: {
			enabled: true,
			resolvePrincipal: async (c) => ({
				subject: base.userId,
				...(c.agentId ? { agentId: c.agentId } : {}),
				scopes: ["mcp:read"],
			}),
		},
		jwtBearer: {
			enabled: true,
			trustedIssuers: [{ issuer: IDP, jwks: { keys: [keys.jwk] } }],
			mapSubject: async () => base.userId,
		},
	};
	const d = finishBoot(base.auth, base.userId, config);
	await new Promise((r) => setTimeout(r, 30));
	return { d, mcp: d.mcp, agents, keys };
}

function ok(res: Result<McpTokenResponse>): McpTokenResponse {
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data;
}

function expectInvalidGrant(res: Result<McpTokenResponse>): void {
	expect(res.success).toBe(false);
	if (!res.success) expect(res.error.code).toBe("INVALID_GRANT");
}

/** Authorize for `clientId`; returns what the token request needs. */
async function authorize(w: World, clientId: Name, scope = "mcp:read offline_access") {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const params = {
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		scope,
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
	};
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
	const res = await w.mcp.authorize(new Request(url));
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	const code = new URL(res.data.redirectUri).searchParams.get("code") ?? "";
	return { code, verifier };
}

function redeemCode(w: World, clientId: Name, code: string, verifier: string) {
	return w.mcp.token(
		tokenRequest(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				client_id: clientId,
				code_verifier: verifier,
				resource: RESOURCE,
			},
			basicAuth(clientId, SECRET),
		),
	);
}

async function codeGrant(w: World, clientId: Name): Promise<McpTokenResponse> {
	const { code, verifier } = await authorize(w, clientId);
	return ok(await redeemCode(w, clientId, code, verifier));
}

function refresh(w: World, clientId: Name, token: string) {
	return w.mcp.token(
		tokenRequest(
			{ grant_type: "refresh_token", refresh_token: token, client_id: clientId },
			basicAuth(clientId, SECRET),
		),
	);
}

function clientCredentials(w: World, clientId: Name) {
	return w.mcp.token(
		tokenRequest(
			{ grant_type: "client_credentials", client_id: clientId, resource: RESOURCE },
			basicAuth(clientId, SECRET),
		),
	);
}

async function jagFor(w: World, clientId: Name): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({
		iss: IDP,
		sub: "alice@corp.test",
		aud: ISSUER,
		client_id: clientId,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + 60,
		scope: "mcp:read",
	})
		.setProtectedHeader({ alg: "ES256", typ: "oauth-id-jag+jwt", kid: w.keys.jwk.kid ?? "k1" })
		.sign(w.keys.privateKey);
}

function jwtBearer(w: World, clientId: Name, assertion: string) {
	return w.mcp.token(
		tokenRequest({ grant_type: JB, assertion, resource: RESOURCE }, basicAuth(clientId, SECRET)),
	);
}

describe("a token whose agent is gone is invalid_grant, not a 500", () => {
	it("authorization_code: refused before the code is consumed, so the code survives", async () => {
		const w = await world();
		const { code, verifier } = await authorize(w, "code");
		const before = await w.d.auth.db.select().from(oauthAuthorizationCodes);
		expect(before).toHaveLength(1);
		await w.d.auth.agent.revoke(w.agents.code);
		expectInvalidGrant(await redeemCode(w, "code", code, verifier));
		// Not consumed: the refusal is decided before the single use code is spent.
		expect(await w.d.auth.db.select().from(oauthAuthorizationCodes)).toHaveLength(1);
		expectInvalidGrant(await redeemCode(w, "code", code, verifier));
	});

	it("authorization_code: a healthy agent still redeems exactly once", async () => {
		const w = await world();
		const { code, verifier } = await authorize(w, "code");
		ok(await redeemCode(w, "code", code, verifier));
		expectInvalidGrant(await redeemCode(w, "code", code, verifier));
		expect(await w.d.auth.db.select().from(oauthAuthorizationCodes)).toHaveLength(0);
	});

	it("refresh_token", async () => {
		const w = await world();
		const first = await codeGrant(w, "refresh");
		await w.d.auth.agent.revoke(w.agents.refresh);
		expectInvalidGrant(await refresh(w, "refresh", first.refresh_token ?? ""));
	});

	it("client_credentials", async () => {
		const w = await world();
		ok(await clientCredentials(w, "cc"));
		await w.d.auth.agent.revoke(w.agents.cc);
		expectInvalidGrant(await clientCredentials(w, "cc"));
	});

	it("jwt-bearer", async () => {
		const w = await world();
		ok(await jwtBearer(w, "jb", await jagFor(w, "jb")));
		await w.d.auth.agent.revoke(w.agents.jb);
		expectInvalidGrant(await jwtBearer(w, "jb", await jagFor(w, "jb")));
	});
});

describe("expires_in is the lifetime actually signed", () => {
	const remaining = (token: string): number => {
		const p = decodePayload(token);
		return (p.exp as number) - Math.floor(Date.now() / 1000);
	};

	it("authorization_code and refresh report the agent expiry cap, not the configured TTL", async () => {
		const w = await world();
		const first = await codeGrant(w, "short");
		expect(first.expires_in).toBeLessThanOrEqual(120);
		expect(first.expires_in).toBeGreaterThan(100);
		expect(Math.abs(first.expires_in - remaining(first.access_token))).toBeLessThanOrEqual(2);
		const second = ok(await refresh(w, "short", first.refresh_token ?? ""));
		expect(second.expires_in).toBeLessThanOrEqual(120);
		expect(Math.abs(second.expires_in - remaining(second.access_token))).toBeLessThanOrEqual(2);
	});

	it("client_credentials reports the cap too", async () => {
		const w = await world();
		const res = ok(await clientCredentials(w, "short"));
		expect(res.expires_in).toBeLessThanOrEqual(120);
		expect(Math.abs(res.expires_in - remaining(res.access_token))).toBeLessThanOrEqual(2);
	});

	it("an uncapped token still reports the configured TTL", async () => {
		const w = await world();
		const res = await codeGrant(w, "code");
		expect(res.expires_in).toBe(3600);
	});
});
