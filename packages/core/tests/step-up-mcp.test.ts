/**
 * Step-up on the MCP OAuth server (RFC 9470): `acr_values` and `max_age` on authorize, the `acr`, `amr`
 * and `auth_time` claims in tokens (kept through refresh), introspection, and the resource side
 * challenge `insufficient_user_authentication` from requireMcpAuth and requireScopes.
 */

import { describe, expect, it } from "vitest";
import { loginRedirectUrl } from "../src/mcp/login-redirect.js";
import { createMcpModule } from "../src/mcp/server.js";
import type { McpAuthModule, McpTokenResponse } from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import type { AuthAssertion } from "../src/session/auth-context.js";
import { ACR, resolveAuthContext } from "../src/session/auth-context.js";
import { bootDb, mcpConfig } from "./mcp-db-harness.js";
import { basicAuth, decodePayload, REDIRECT, RESOURCE, tokenRequest } from "./mcp-test-harness.js";

const nowS = () => Math.floor(Date.now() / 1000);
const password = (ago = 5): AuthAssertion =>
	resolveAuthContext([{ method: "password", at: nowS() - ago }], nowS());
const passkey = (ago = 5): AuthAssertion =>
	resolveAuthContext([{ method: "passkey", at: nowS() - ago }], nowS());

interface World {
	mcp: McpAuthModule;
	clientId: string;
	secret: string;
	userId: string;
	/** What the signed-in user's session says. Tests change it. */
	session: { current: AuthAssertion | null };
}

async function boot(withResolver = true): Promise<World> {
	const d = await bootDb();
	const session: World["session"] = { current: password() };
	const mcp = createMcpModule({
		auth: d.auth,
		config: mcpConfig({
			introspection: { enabled: true },
			loginPage: "https://app.theauth.test/login",
		}),
		resolveUserId: async () => d.userId,
		...(withResolver ? { resolveAuthContext: async () => session.current } : {}),
	});
	const reg = await mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "client_secret_basic",
		grant_types: ["authorization_code", "refresh_token"],
	});
	if (!reg.success) throw new Error(reg.error.message);
	return {
		mcp,
		clientId: reg.data.client_id,
		secret: reg.data.client_secret ?? "",
		userId: d.userId,
		session,
	};
}

function authorizeUrl(w: World, extra: Record<string, string>, verifier: string): Promise<Request> {
	return computeS256Challenge(verifier).then((challenge) => {
		const url = new URL("https://auth.theauth.test/api/auth/mcp/authorize");
		const params: Record<string, string> = {
			response_type: "code",
			client_id: w.clientId,
			redirect_uri: REDIRECT,
			scope: "mcp:read offline_access",
			state: "s1",
			code_challenge: challenge,
			code_challenge_method: "S256",
			resource: RESOURCE,
			...extra,
		};
		for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
		return new Request(url);
	});
}

async function authorize(w: World, extra: Record<string, string> = {}) {
	const verifier = generateSecureToken(43);
	const result = await w.mcp.authorize(await authorizeUrl(w, extra, verifier));
	return { result, verifier };
}

async function fullFlow(w: World, extra: Record<string, string> = {}): Promise<McpTokenResponse> {
	const { result, verifier } = await authorize(w, extra);
	if (!result.success) throw new Error(`${result.error.code}: ${result.error.message}`);
	const code = new URL(result.data.redirectUri).searchParams.get("code") ?? "";
	const tokens = await w.mcp.token(
		tokenRequest(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				client_id: w.clientId,
				code_verifier: verifier,
				resource: RESOURCE,
			},
			basicAuth(w.clientId, w.secret),
		),
	);
	if (!tokens.success) throw new Error(`${tokens.error.code}: ${tokens.error.message}`);
	return tokens.data;
}

describe("authorize with acr_values and max_age", () => {
	it("answers unmet_authentication_requirements when the server cannot judge a login", async () => {
		const w = await boot(false);
		const { result } = await authorize(w, { acr_values: ACR.mfa });
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("UNMET_AUTHENTICATION_REQUIREMENTS");
		const maxAge = await authorize(w, { max_age: "60" });
		expect(maxAge.result.success).toBe(false);
	});

	it("leaves requests without the parameters alone when no resolver is set", async () => {
		const w = await boot(false);
		const { result } = await authorize(w);
		expect(result.success).toBe(true);
	});

	it("sends the user back to login with prompt=login when the session falls short", async () => {
		const w = await boot();
		const { result } = await authorize(w, { acr_values: ACR.mfa, max_age: "300" });
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("LOGIN_REQUIRED");
		const details = result.error.details as {
			acrValues?: string;
			maxAge?: number;
			prompt?: string;
			returnTo?: string;
			loginPage?: string;
		};
		expect(details).toMatchObject({ acrValues: ACR.mfa, maxAge: 300, prompt: "login" });
		const redirect = new URL(loginRedirectUrl(details) ?? "");
		expect(redirect.origin + redirect.pathname).toBe("https://app.theauth.test/login");
		expect(redirect.searchParams.get("acr_values")).toBe(ACR.mfa);
		expect(redirect.searchParams.get("max_age")).toBe("300");
		expect(redirect.searchParams.get("prompt")).toBe("login");
		expect(redirect.searchParams.get("returnTo")).toContain("/mcp/authorize");
	});

	it("raises a tiny max_age to 30 seconds so the login round trip cannot loop", async () => {
		const w = await boot();
		w.session.current = password(2);
		const { result } = await authorize(w, { max_age: "0" });
		expect(result.success).toBe(true);
		w.session.current = password(120);
		const stale = await authorize(w, { max_age: "0" });
		expect(stale.result.success).toBe(false);
		if (!stale.result.success) {
			expect((stale.result.error.details as { maxAge?: number }).maxAge).toBe(30);
		}
	});

	it("answers unmet_authentication_requirements for classes it does not know", async () => {
		const w = await boot();
		const { result } = await authorize(w, { acr_values: "urn:example:gold" });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error.code).toBe("UNMET_AUTHENTICATION_REQUIREMENTS");
	});

	it("rejects a malformed max_age", async () => {
		const w = await boot();
		const { result } = await authorize(w, { max_age: "-5" });
		expect(result.success).toBe(false);
		if (!result.success) expect(result.error.code).toBe("INVALID_REQUEST");
	});

	it("issues a code and then tokens carrying acr, amr and auth_time when the session qualifies", async () => {
		const w = await boot();
		w.session.current = passkey(7);
		const tokens = await fullFlow(w, { acr_values: ACR.phishingResistant, max_age: "300" });
		const claims = decodePayload(tokens.access_token);
		expect(claims.acr).toBe(ACR.phishingResistant);
		expect(claims.amr).toEqual(["mfa", "swk", "user"]);
		expect(claims.auth_time).toBe(w.session.current.authTime);
	});

	it("puts the evidence in tokens even when the client asked for nothing", async () => {
		const w = await boot();
		const tokens = await fullFlow(w);
		const claims = decodePayload(tokens.access_token);
		expect(claims.acr).toBe(ACR.singleFactor);
		expect(claims.amr).toEqual(["pwd"]);
	});

	it("keeps the original auth_time and acr through a refresh", async () => {
		const w = await boot();
		w.session.current = passkey(60);
		const first = await fullFlow(w);
		const refreshed = await w.mcp.token(
			tokenRequest(
				{
					grant_type: "refresh_token",
					refresh_token: first.refresh_token ?? "",
					client_id: w.clientId,
				},
				basicAuth(w.clientId, w.secret),
			),
		);
		expect(refreshed.success).toBe(true);
		if (!refreshed.success) return;
		const a = decodePayload(first.access_token);
		const b = decodePayload(refreshed.data.access_token);
		expect(b.auth_time).toBe(a.auth_time);
		expect(b.acr).toBe(ACR.phishingResistant);
		expect(b.amr).toEqual(a.amr);
	});

	it("reports the claims from introspection (RFC 9470 section 6.2)", async () => {
		const w = await boot();
		w.session.current = passkey(9);
		const tokens = await fullFlow(w);
		const res = await w.mcp.introspect(
			tokenRequest({ token: tokens.access_token }, basicAuth(w.clientId, w.secret)),
		);
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data).toMatchObject({
			active: true,
			acr: ACR.phishingResistant,
			amr: ["mfa", "swk", "user"],
			auth_time: w.session.current.authTime,
		});
	});

	it("advertises acr_values_supported only when it can honor them", async () => {
		expect((await boot()).mcp.getMetadata().acr_values_supported).toContain(ACR.mfa);
		expect((await boot(false)).mcp.getMetadata().acr_values_supported).toBeUndefined();
	});

	it("passes evidence from approveConsent into the code and on to the token", async () => {
		const w = await boot();
		const verifier = generateSecureToken(43);
		const approved = await w.mcp.approveConsent({
			userId: w.userId,
			clientId: w.clientId,
			scope: "mcp:read",
			redirectUri: REDIRECT,
			codeChallenge: await computeS256Challenge(verifier),
			codeChallengeMethod: "S256",
			resource: RESOURCE,
			auth: { acr: ACR.mfa, amr: ["mfa", "otp", "pwd"], authTime: nowS() - 3 },
		});
		expect(approved.success).toBe(true);
		if (!approved.success) return;
		const code = new URL(approved.data.redirectUri).searchParams.get("code") ?? "";
		const tokens = await w.mcp.token(
			tokenRequest(
				{
					grant_type: "authorization_code",
					code,
					redirect_uri: REDIRECT,
					client_id: w.clientId,
					code_verifier: verifier,
					resource: RESOURCE,
				},
				basicAuth(w.clientId, w.secret),
			),
		);
		expect(tokens.success).toBe(true);
		if (!tokens.success) return;
		expect(decodePayload(tokens.data.access_token).acr).toBe(ACR.mfa);
	});
});

describe("resource side: requireMcpAuth and requireScopes", () => {
	async function tokenFor(w: World, assertion: AuthAssertion | null): Promise<string> {
		w.session.current = assertion;
		return (await fullFlow(w)).access_token;
	}

	const call = (token: string) =>
		new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } });

	it("answers 401 insufficient_user_authentication with acr_values and max_age", async () => {
		const w = await boot();
		const token = await tokenFor(w, password());
		const guarded = w.mcp.requireMcpAuth(async () => new Response("ok"), {
			requireAcr: ACR.phishingResistant,
			maxAge: 300,
			expectedAudience: RESOURCE,
		});
		const res = await guarded(call(token));
		expect(res.status).toBe(401);
		const header = res.headers.get("www-authenticate") ?? "";
		expect(header).toContain('error="insufficient_user_authentication"');
		expect(header).toContain(`acr_values="${ACR.phishingResistant}"`);
		expect(header).toContain('max_age="300"');
		expect(header).toContain("resource_metadata=");
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("insufficient_user_authentication");
	});

	it("runs the handler with principal.auth when the login qualifies", async () => {
		const w = await boot();
		const token = await tokenFor(w, passkey());
		let seen: unknown;
		const guarded = w.mcp.requireMcpAuth(
			async (_req, principal) => {
				seen = principal.auth;
				return new Response("ok");
			},
			{ requireAcr: ACR.mfa, maxAge: 300, expectedAudience: RESOURCE },
		);
		expect((await guarded(call(token))).status).toBe(200);
		expect(seen).toMatchObject({ acr: ACR.phishingResistant });
	});

	it("refuses a token whose login is too old", async () => {
		const w = await boot();
		const token = await tokenFor(w, passkey(4000));
		const guarded = w.mcp.requireMcpAuth(async () => new Response("ok"), {
			maxAge: 300,
			expectedAudience: RESOURCE,
		});
		const res = await guarded(call(token));
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toContain('max_age="300"');
	});

	it("does not touch routes that ask for nothing", async () => {
		const w = await boot();
		const token = await tokenFor(w, null);
		const guarded = w.mcp.requireMcpAuth(async () => new Response("ok"), {
			expectedAudience: RESOURCE,
		});
		expect((await guarded(call(token))).status).toBe(200);
	});

	it("refuses a token with no acr claim when an acr is required", async () => {
		const w = await boot();
		const token = await tokenFor(w, null);
		const guarded = w.mcp.requireMcpAuth(async () => new Response("ok"), {
			requireAcr: ACR.singleFactor,
			expectedAudience: RESOURCE,
		});
		expect((await guarded(call(token))).status).toBe(401);
	});

	it("applies the same rule through requireScopes", async () => {
		const w = await boot();
		const weak = await tokenFor(w, password());
		const denied = await w.mcp.requireScopes(call(weak), ["mcp:read"], { acr: ACR.mfa });
		expect(denied.authorized).toBe(false);
		if (!denied.authorized) {
			expect(denied.status).toBe(401);
			expect(denied.error.code).toBe("INSUFFICIENT_USER_AUTHENTICATION");
			expect(denied.response.headers.get("www-authenticate")).toContain(
				"insufficient_user_authentication",
			);
		}
		const strong = await tokenFor(w, passkey());
		const allowed = await w.mcp.requireScopes(call(strong), ["mcp:read"], { acr: ACR.mfa });
		expect(allowed.authorized).toBe(true);
	});
});
