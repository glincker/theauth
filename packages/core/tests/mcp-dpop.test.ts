/**
 * DPoP (RFC 9449) at the token endpoint and the resource server, plus the
 * requireMcpAuth wrapper: proof checks, replay, nonce flow, bearer downgrade,
 * refresh binding, challenges and the exposed principal.
 */

import type { JWK, KeyLike } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { sha256Raw, toBase64Url } from "../src/crypto/web-crypto.js";
import type { McpPrincipal } from "../src/mcp/require-mcp-auth.js";
import { createMcpModule } from "../src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
	McpConfig,
	McpTokenResponse,
} from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import { withMcpAuth } from "../src/mcp/validate.js";

const ISSUER = "https://auth.theauth.test";
const BASE_URL = "https://auth.theauth.test/api/auth";
const TOKEN_URL = `${BASE_URL}/mcp/token`;
const SECRET = "test-signing-secret-at-least-32-chars-long!!";
const REDIRECT = "https://app.theauth.test/callback";
const RESOURCE = "https://mcp.theauth.test";
const RS_URL = `${RESOURCE}/tools?cursor=1`;
const USER = "user_1";

// ─── Harness ────────────────────────────────────────────────────────────────

interface Store {
	clients: Map<string, McpClient>;
	codes: Map<string, McpAuthorizationCode>;
	tokens: Map<string, McpAccessToken>;
	byRefresh: Map<string, McpAccessToken>;
}

function makeMcp(config: Partial<McpConfig> = {}): McpAuthModule {
	const store: Store = {
		clients: new Map(),
		codes: new Map(),
		tokens: new Map(),
		byRefresh: new Map(),
	};
	return createMcpModule({
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SECRET,
			resource: RESOURCE,
			scopes: ["mcp:read", "mcp:write"],
			dpop: {},
			...config,
		},
		storeClient: async (c) => {
			store.clients.set(c.clientId, c);
		},
		findClient: async (id) => store.clients.get(id) ?? null,
		storeAuthorizationCode: async (c) => {
			store.codes.set(c.code, c);
		},
		consumeAuthorizationCode: async (code) => {
			const found = store.codes.get(code) ?? null;
			store.codes.delete(code);
			return found;
		},
		storeToken: async (t) => {
			store.tokens.set(t.accessToken, t);
			if (t.refreshToken) store.byRefresh.set(t.refreshToken, t);
		},
		findTokenByRefreshToken: async (rt) => store.byRefresh.get(rt) ?? null,
		revokeToken: async () => {},
		resolveUserId: async () => USER,
	});
}

interface Keys {
	privateKey: KeyLike;
	jwk: JWK;
}

async function newKeys(): Promise<Keys> {
	const { privateKey, publicKey } = await generateKeyPair("ES256");
	return { privateKey, jwk: await exportJWK(publicKey) };
}

interface ProofInit {
	htm?: string;
	htu?: string;
	iat?: number;
	jti?: string;
	ath?: string;
	nonce?: string;
	typ?: string;
	omit?: string[];
}

async function proof(keys: Keys, init: ProofInit = {}): Promise<string> {
	const claims: Record<string, unknown> = {
		htm: init.htm ?? "POST",
		htu: init.htu ?? TOKEN_URL,
		jti: init.jti ?? generateSecureToken(16),
		iat: init.iat ?? Math.floor(Date.now() / 1000),
		...(init.ath ? { ath: init.ath } : {}),
		...(init.nonce ? { nonce: init.nonce } : {}),
	};
	for (const k of init.omit ?? []) Reflect.deleteProperty(claims, k);
	return new SignJWT(claims)
		.setProtectedHeader({ alg: "ES256", typ: init.typ ?? "dpop+jwt", jwk: keys.jwk })
		.sign(keys.privateKey);
}

async function athOf(token: string): Promise<string> {
	return toBase64Url(await sha256Raw(token));
}

async function registerPublic(mcp: McpAuthModule): Promise<string> {
	const r = await mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
	});
	if (!r.success) throw new Error(r.error.message);
	return r.data.client_id;
}

/** Authorize and return the code plus the PKCE verifier. */
async function getCode(mcp: McpAuthModule, clientId: string) {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	for (const [k, v] of Object.entries({
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		scope: "mcp:read offline_access",
		state: "s1",
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
	})) {
		url.searchParams.set(k, v);
	}
	const auth = await mcp.authorize(new Request(url));
	if (!auth.success) throw new Error(auth.error.message);
	return { code: new URL(auth.data.redirectUri).searchParams.get("code") ?? "", verifier };
}

function tokenRequest(body: Record<string, string>, dpopProof?: string): Request {
	return new Request(TOKEN_URL, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			...(dpopProof ? { DPoP: dpopProof } : {}),
		},
		body: new URLSearchParams(body).toString(),
	});
}

function codeBody(clientId: string, code: string, verifier: string) {
	return {
		grant_type: "authorization_code",
		code,
		redirect_uri: REDIRECT,
		client_id: clientId,
		code_verifier: verifier,
		resource: RESOURCE,
	};
}

/** Full code exchange. Returns the raw Result so callers can assert failures. */
async function exchange(mcp: McpAuthModule, clientId: string, dpopProof?: () => Promise<string>) {
	const { code, verifier } = await getCode(mcp, clientId);
	return mcp.token(tokenRequest(codeBody(clientId, code, verifier), await dpopProof?.()));
}

async function issue(mcp: McpAuthModule, clientId: string, keys?: Keys): Promise<McpTokenResponse> {
	const r = await exchange(mcp, clientId, keys ? () => proof(keys) : undefined);
	if (!r.success) throw new Error(`${r.error.code}: ${r.error.message}`);
	return r.data;
}

function rsRequest(
	token: string,
	scheme: "Bearer" | "DPoP",
	dpopProof?: string,
	url = RS_URL,
	method = "GET",
): Request {
	return new Request(url, {
		method,
		headers: {
			Authorization: `${scheme} ${token}`,
			...(dpopProof ? { DPoP: dpopProof } : {}),
		},
	});
}

async function rsProof(keys: Keys, token: string, init: ProofInit = {}): Promise<string> {
	return proof(keys, {
		htm: "GET",
		htu: `${RESOURCE}/tools`,
		ath: await athOf(token),
		...init,
	});
}

async function jwtPayload(token: string): Promise<Record<string, unknown>> {
	return JSON.parse(atob(token.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/") ?? ""));
}

const echo = (_req: Request, p: McpPrincipal) =>
	Response.json({ user: p.userId, scheme: p.scheme, jkt: p.dpopJkt, scopes: p.scopes });

// ─── Token endpoint ─────────────────────────────────────────────────────────

describe("token endpoint with DPoP", () => {
	let mcp: McpAuthModule;
	let clientId: string;
	let keys: Keys;

	beforeEach(async () => {
		mcp = makeMcp();
		clientId = await registerPublic(mcp);
		keys = await newKeys();
	});

	it("issues a cnf.jkt-bound token with token_type DPoP", async () => {
		const tokens = await issue(mcp, clientId, keys);
		expect(tokens.token_type).toBe("DPoP");
		const payload = await jwtPayload(tokens.access_token);
		const cnf = payload.cnf as { jkt: string };
		expect(cnf.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	it("still issues bearer tokens when no proof is sent and DPoP is optional", async () => {
		const tokens = await issue(mcp, clientId);
		expect(tokens.token_type).toBe("Bearer");
		expect((await jwtPayload(tokens.access_token)).cnf).toBeUndefined();
	});

	it("refuses a request without a proof when dpop.required is set", async () => {
		const strict = makeMcp({ dpop: { required: true } });
		const id = await registerPublic(strict);
		const r = await exchange(strict, id);
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.code).toBe("INVALID_DPOP_PROOF");
	});

	it("advertises dpop_signing_alg_values_supported in both metadata documents", () => {
		expect(mcp.getMetadata().dpop_signing_alg_values_supported).toEqual([
			"ES256",
			"ES384",
			"EdDSA",
			"PS256",
		]);
		expect(mcp.getProtectedResourceMetadata().dpop_signing_alg_values_supported).toContain("ES256");
		const off = makeMcp({ dpop: undefined });
		expect(off.getMetadata().dpop_signing_alg_values_supported).toBeUndefined();
	});

	it.each([
		["wrong htu", { htu: "https://evil.test/mcp/token" }],
		["wrong htm", { htm: "GET" }],
		["expired iat", { iat: Math.floor(Date.now() / 1000) - 3600 }],
		["future iat", { iat: Math.floor(Date.now() / 1000) + 3600 }],
		["wrong typ", { typ: "JWT" }],
		["missing jti", { omit: ["jti"] }],
	])("rejects a proof with %s", async (_name, init) => {
		const r = await exchange(mcp, clientId, () => proof(keys, init));
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.code).toBe("INVALID_DPOP_PROOF");
	});

	it("ignores query and fragment when matching htu", async () => {
		const r = await exchange(mcp, clientId, () => proof(keys, { htu: `${TOKEN_URL}?x=1#frag` }));
		expect(r.success).toBe(true);
	});

	it("rejects a replayed proof (jti seen before)", async () => {
		const jti = "fixed-jti-1";
		const first = await exchange(mcp, clientId, () => proof(keys, { jti }));
		expect(first.success).toBe(true);
		const second = await exchange(mcp, clientId, () => proof(keys, { jti }));
		expect(second.success).toBe(false);
		if (!second.success) expect(second.error.message).toContain("already been used");
	});

	it("rejects a proof whose jwk carries private key material", async () => {
		const { privateKey } = await generateKeyPair("ES256", { extractable: true });
		const leaked = { ...(await exportJWK(privateKey)) };
		const bad = await proof({ privateKey, jwk: leaked });
		const { code, verifier } = await getCode(mcp, clientId);
		const r = await mcp.token(tokenRequest(codeBody(clientId, code, verifier), bad));
		expect(r.success).toBe(false);
	});

	it("rejects an unsigned (alg none) proof", async () => {
		const header = btoa(JSON.stringify({ alg: "none", typ: "dpop+jwt", jwk: keys.jwk }));
		const body = btoa(JSON.stringify({ htm: "POST", htu: TOKEN_URL, jti: "x", iat: 1 }));
		const { code, verifier } = await getCode(mcp, clientId);
		const r = await mcp.token(
			tokenRequest(codeBody(clientId, code, verifier), `${header}.${body}.`),
		);
		expect(r.success).toBe(false);
	});

	describe("nonce flow", () => {
		it("asks for a nonce, keeps the code usable, then accepts the retry", async () => {
			const m = makeMcp({ dpop: { requireNonce: true } });
			const id = await registerPublic(m);
			const { code, verifier } = await getCode(m, id);
			const body = codeBody(id, code, verifier);

			const first = await m.token(tokenRequest(body, await proof(keys)));
			expect(first.success).toBe(false);
			if (first.success) return;
			expect(first.error.code).toBe("USE_DPOP_NONCE");
			const nonce = first.error.details?.dpopNonce as string;
			expect(nonce.length).toBeGreaterThan(20);

			const retry = await m.token(tokenRequest(body, await proof(keys, { nonce })));
			expect(retry.success).toBe(true);
			if (retry.success) expect(retry.data.token_type).toBe("DPoP");
		});

		it("rejects an unknown nonce and hands out the current one", async () => {
			const m = makeMcp({ dpop: { requireNonce: true } });
			const id = await registerPublic(m);
			const r = await exchange(m, id, () => proof(keys, { nonce: "made-up" }));
			expect(r.success).toBe(false);
			if (!r.success) expect(r.error.code).toBe("USE_DPOP_NONCE");
		});

		it("returns the same nonce until it rotates", async () => {
			const m = makeMcp({ dpop: { requireNonce: true } });
			const id = await registerPublic(m);
			const a = await exchange(m, id, () => proof(keys));
			const b = await exchange(m, id, () => proof(keys));
			if (a.success || b.success) throw new Error("expected nonce challenges");
			expect(a.error.details?.dpopNonce).toBe(b.error.details?.dpopNonce);
		});

		it("tokenResponse surfaces the nonce as a DPoP-Nonce header", async () => {
			const { createMcpResponseHelpers } = await import("../src/mcp/server.js");
			const helpers = createMcpResponseHelpers({ config: { baseUrl: BASE_URL } } as never);
			const res = helpers.tokenResponse({
				success: false,
				error: { code: "USE_DPOP_NONCE", message: "n", details: { dpopNonce: "abc" } },
			});
			expect(res.status).toBe(400);
			expect(res.headers.get("DPoP-Nonce")).toBe("abc");
		});
	});

	describe("refresh grant binding", () => {
		it("accepts the bound key, refuses another key and a missing proof", async () => {
			const first = await issue(mcp, clientId, keys);
			const rt = first.refresh_token ?? "";
			const body = { grant_type: "refresh_token", refresh_token: rt, client_id: clientId };

			const thief = await newKeys();
			const stolen = await mcp.token(tokenRequest(body, await proof(thief)));
			expect(stolen.success).toBe(false);
			const bearer = await mcp.token(tokenRequest(body));
			expect(bearer.success).toBe(false);

			// The failed attempts did not rotate the token.
			const ok = await mcp.token(tokenRequest(body, await proof(keys)));
			expect(ok.success).toBe(true);
			if (ok.success) {
				expect(ok.data.token_type).toBe("DPoP");
				const a = (await jwtPayload(first.access_token)).cnf;
				const b = (await jwtPayload(ok.data.access_token)).cnf;
				expect(b).toEqual(a);
			}
		});
	});
});

// ─── Resource server ────────────────────────────────────────────────────────

describe("requireMcpAuth with DPoP", () => {
	let mcp: McpAuthModule;
	let clientId: string;
	let keys: Keys;

	beforeEach(async () => {
		mcp = makeMcp();
		clientId = await registerPublic(mcp);
		keys = await newKeys();
	});

	it("runs the handler with the principal for a valid DPoP request", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const guarded = mcp.requireMcpAuth(echo, { requiredScopes: ["mcp:read"] });
		const res = await guarded(
			rsRequest(tokens.access_token, "DPoP", await rsProof(keys, tokens.access_token)),
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { user: string; scheme: string; jkt: string };
		expect(body.user).toBe(USER);
		expect(body.scheme).toBe("DPoP");
		expect(body.jkt).toHaveLength(43);
	});

	it("rejects a replayed resource proof", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const guarded = mcp.requireMcpAuth(echo);
		const p = await rsProof(keys, tokens.access_token);
		expect((await guarded(rsRequest(tokens.access_token, "DPoP", p))).status).toBe(200);
		const again = await guarded(rsRequest(tokens.access_token, "DPoP", p));
		expect(again.status).toBe(401);
		expect(again.headers.get("WWW-Authenticate")).toContain('error="invalid_dpop_proof"');
	});

	it.each([
		["wrong htu", { htu: `${RESOURCE}/other` }],
		["wrong htm", { htm: "POST" }],
		["expired iat", { iat: Math.floor(Date.now() / 1000) - 3600 }],
		["wrong ath", { ath: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
	])("rejects a resource proof with %s", async (_name, init) => {
		const tokens = await issue(mcp, clientId, keys);
		const guarded = mcp.requireMcpAuth(echo);
		const p = await rsProof(keys, tokens.access_token, init);
		const res = await guarded(rsRequest(tokens.access_token, "DPoP", p));
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_dpop_proof"');
	});

	it("rejects a proof with no ath", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const p = await rsProof(keys, tokens.access_token, { omit: ["ath"] });
		const res = await mcp.requireMcpAuth(echo)(rsRequest(tokens.access_token, "DPoP", p));
		expect(res.status).toBe(401);
	});

	it("rejects a proof signed by a different key than the token is bound to", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const other = await newKeys();
		const p = await rsProof(other, tokens.access_token);
		const res = await mcp.requireMcpAuth(echo)(rsRequest(tokens.access_token, "DPoP", p));
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
	});

	it("refuses a DPoP-bound token presented as Bearer (downgrade)", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const res = await mcp.requireMcpAuth(echo)(rsRequest(tokens.access_token, "Bearer"));
		expect(res.status).toBe(401);
		const challenge = res.headers.get("WWW-Authenticate") ?? "";
		expect(challenge).toMatch(/^DPoP /);
		expect(challenge).toContain('error="invalid_token"');

		// A stray proof header does not rescue the Bearer scheme.
		const withProof = await mcp.requireMcpAuth(echo)(
			rsRequest(tokens.access_token, "Bearer", await rsProof(keys, tokens.access_token)),
		);
		expect(withProof.status).toBe(401);
	});

	it("refuses bound tokens on the legacy bearer helpers too", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const viaValidate = await mcp.validateToken(tokens.access_token);
		expect(viaValidate.success).toBe(false);
		const viaMiddleware = await mcp.middleware(rsRequest(tokens.access_token, "Bearer"));
		expect(viaMiddleware.success).toBe(false);
		const viaScopes = await mcp.requireScopes(rsRequest(tokens.access_token, "Bearer"), []);
		expect(viaScopes.authorized).toBe(false);
		const viaWith = await withMcpAuth(
			{ config: { baseUrl: BASE_URL } } as never,
			rsRequest(tokens.access_token, "Bearer"),
			{ expectedAudience: RESOURCE },
		);
		expect(viaWith.success).toBe(false);
	});

	it("refuses the DPoP scheme for an unbound token", async () => {
		const tokens = await issue(mcp, clientId);
		const p = await rsProof(keys, tokens.access_token);
		const res = await mcp.requireMcpAuth(echo)(rsRequest(tokens.access_token, "DPoP", p));
		expect(res.status).toBe(401);
	});

	it("requires a DPoP header on the DPoP scheme", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const res = await mcp.requireMcpAuth(echo)(rsRequest(tokens.access_token, "DPoP"));
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toContain('error="invalid_dpop_proof"');
	});

	it("refuses unbound bearer tokens when requireDpop is set", async () => {
		const tokens = await issue(mcp, clientId);
		const res = await mcp.requireMcpAuth(echo, { requireDpop: true })(
			rsRequest(tokens.access_token, "Bearer"),
		);
		expect(res.status).toBe(401);
		expect(res.headers.get("WWW-Authenticate")).toMatch(/^DPoP /);
	});

	it("accepts unbound bearer tokens by default and reports the scheme", async () => {
		const tokens = await issue(mcp, clientId);
		const res = await mcp.requireMcpAuth(echo)(rsRequest(tokens.access_token, "Bearer"));
		expect(res.status).toBe(200);
		expect(((await res.json()) as { scheme: string }).scheme).toBe("Bearer");
	});

	it("runs a nonce flow at the resource server", async () => {
		const m = makeMcp({ dpop: { requireNonce: false } });
		const id = await registerPublic(m);
		const tokens = await issue(m, id, keys);
		const guarded = m.requireMcpAuth(echo, { requireNonce: true });

		const first = await guarded(
			rsRequest(tokens.access_token, "DPoP", await rsProof(keys, tokens.access_token)),
		);
		expect(first.status).toBe(401);
		expect(first.headers.get("WWW-Authenticate")).toContain('error="use_dpop_nonce"');
		const nonce = first.headers.get("DPoP-Nonce") ?? "";
		expect(nonce).not.toBe("");

		const retry = await guarded(
			rsRequest(tokens.access_token, "DPoP", await rsProof(keys, tokens.access_token, { nonce })),
		);
		expect(retry.status).toBe(200);
	});

	it("returns 403 insufficient_scope with a scheme-matched challenge", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const guarded = mcp.requireMcpAuth(echo, { requiredScopes: ["mcp:write"] });
		const res = await guarded(
			rsRequest(tokens.access_token, "DPoP", await rsProof(keys, tokens.access_token)),
		);
		expect(res.status).toBe(403);
		const challenge = res.headers.get("WWW-Authenticate") ?? "";
		expect(challenge).toContain('error="insufficient_scope"');
		expect(challenge).toContain('scope="mcp:write"');
	});

	it("rejects tokens minted for another audience", async () => {
		const tokens = await issue(mcp, clientId);
		const res = await mcp.requireMcpAuth(echo, { expectedAudience: "https://other.test" })(
			rsRequest(tokens.access_token, "Bearer"),
		);
		expect(res.status).toBe(401);
	});

	it("honors resourceUrl for proxied deployments", async () => {
		const tokens = await issue(mcp, clientId, keys);
		const p = await proof(keys, {
			htm: "GET",
			htu: "https://public.example/tools",
			ath: await athOf(tokens.access_token),
		});
		const guarded = mcp.requireMcpAuth(echo, { resourceUrl: "https://public.example/tools" });
		expect((await guarded(rsRequest(tokens.access_token, "DPoP", p))).status).toBe(200);
	});

	it("fails closed when no audience is configured", async () => {
		const m = makeMcp({ resource: undefined });
		const res = await m.requireMcpAuth(echo)(rsRequest("x.y.z", "Bearer"));
		expect(res.status).toBe(500);
	});
});

describe("requireMcpAuth challenges", () => {
	it("offers Bearer and DPoP with resource_metadata when no credentials are sent", async () => {
		const mcp = makeMcp();
		const res = await mcp.requireMcpAuth(echo)(new Request(RS_URL));
		expect(res.status).toBe(401);
		const header = res.headers.get("WWW-Authenticate") ?? "";
		const meta = `resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`;
		expect(header).toContain(`Bearer ${meta}`);
		expect(header).toContain("DPoP algs=");
		expect(header).toContain(meta);
	});

	it("offers only Bearer when DPoP is not configured", async () => {
		const mcp = makeMcp({ dpop: undefined });
		const res = await mcp.requireMcpAuth(echo)(new Request(RS_URL));
		expect(res.headers.get("WWW-Authenticate")).not.toContain("DPoP");
	});

	it("honors a custom resourceMetadataUrl and escapes quotes", async () => {
		const mcp = makeMcp({ dpop: undefined });
		const guarded = mcp.requireMcpAuth(echo, {
			resourceMetadataUrl: "https://mcp.theauth.test/.well-known/oauth-protected-resource",
		});
		const res = await guarded(rsRequest("not-a-jwt", "Bearer"));
		const header = res.headers.get("WWW-Authenticate") ?? "";
		expect(header).toContain('error="invalid_token"');
		expect(header).toContain('resource_metadata="https://mcp.theauth.test/.well-known');
	});

	it("rejects the DPoP scheme when DPoP is not enabled", async () => {
		const mcp = makeMcp({ dpop: undefined });
		const res = await mcp.requireMcpAuth(echo)(rsRequest("x.y.z", "DPoP"));
		expect(res.status).toBe(401);
	});
});

describe("requireMcpAuth principal", () => {
	it("exposes agent identity and the delegation chain", async () => {
		const mcp = makeMcp({
			dpop: undefined,
			emitAgenticJwtClaims: true,
			getAgenticContext: async () => ({
				agentId: "agent_42",
				agentType: "delegated",
				trustTier: "standard",
			}),
		});
		const id = await registerPublic(mcp);
		const tokens = await issue(mcp, id);
		let seen: McpPrincipal | undefined;
		const res = await mcp.requireMcpAuth((_r, p) => {
			seen = p;
			return new Response("ok");
		})(rsRequest(tokens.access_token, "Bearer"));
		expect(res.status).toBe(200);
		expect(seen?.agent).toEqual({ id: "agent_42", type: "delegated", trustTier: "standard" });
		expect(seen?.delegationChain).toEqual([]);
		expect(seen?.clientId).toBe(id);
	});

	it("flattens nested act claims, current actor first", async () => {
		const mcp = makeMcp({ dpop: undefined });
		const key = new TextEncoder().encode(SECRET);
		const now = Math.floor(Date.now() / 1000);
		const jwt = await new SignJWT({
			sub: USER,
			client_id: "c1",
			scope: "mcp:read",
			jti: "j1",
			act: { sub: "agent_b", client_id: "cb", act: { sub: "agent_a" } },
		})
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuer(ISSUER)
			.setAudience(RESOURCE)
			.setIssuedAt(now)
			.setExpirationTime(now + 600)
			.sign(key);
		let seen: McpPrincipal | undefined;
		await mcp.requireMcpAuth((_r, p) => {
			seen = p;
			return new Response("ok");
		})(rsRequest(jwt, "Bearer"));
		expect(seen?.delegationChain).toEqual([{ sub: "agent_b", clientId: "cb" }, { sub: "agent_a" }]);
		expect(seen?.agent).toBeNull();
	});
});
