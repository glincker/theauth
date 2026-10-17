/** Shared fixtures for the MCP grant tests (client_credentials, token exchange, jwt-bearer, lenient clients, CIMD). In-memory storage, real module instances. */
import type { JWK } from "jose";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createInMemoryJtiDenylist } from "../src/mcp/memory-stores.js";
import { createMcpModule } from "../src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
	McpConfig,
	McpTokenResponse,
} from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken, hashClientSecret } from "../src/mcp/utils.js";

export const ISSUER = "https://auth.theauth.test";
export const BASE_URL = "https://auth.theauth.test/api/auth";
export const TOKEN_URL = `${BASE_URL}/mcp/token`;
export const SECRET = "test-signing-secret-at-least-32-chars-long!!";
export const REDIRECT = "https://app.theauth.test/callback";
export const RESOURCE = "https://mcp.theauth.test";
export const RESOURCE_B = "https://other.theauth.test";
export const USER = "user_1";

export interface Harness {
	mcp: McpAuthModule;
	clients: Map<string, McpClient>;
	codes: Map<string, McpAuthorizationCode>;
	tokens: Map<string, McpAccessToken>;
}

export function makeHarness(config: Partial<McpConfig> = {}): Harness {
	const clients = new Map<string, McpClient>();
	const codes = new Map<string, McpAuthorizationCode>();
	const tokens = new Map<string, McpAccessToken>();
	const byRefresh = new Map<string, McpAccessToken>();
	const mcp = createMcpModule({
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SECRET,
			resource: RESOURCE,
			scopes: ["mcp:read", "mcp:write", "mcp:admin"],
			jtiDenylist: createInMemoryJtiDenylist(),
			...config,
		},
		storeClient: async (c) => {
			clients.set(c.clientId, c);
		},
		findClient: async (id) => clients.get(id) ?? null,
		storeAuthorizationCode: async (c) => {
			codes.set(c.code, c);
		},
		consumeAuthorizationCode: async (code) => {
			const found = codes.get(code) ?? null;
			codes.delete(code);
			return found;
		},
		storeToken: async (t) => {
			tokens.set(t.accessToken, t);
			if (t.refreshToken) byRefresh.set(t.refreshToken, t);
		},
		findTokenByRefreshToken: async (rt) => byRefresh.get(rt) ?? null,
		revokeToken: async () => {},
		resolveUserId: async () => USER,
	});
	return { mcp, clients, codes, tokens };
}

export interface ClientInit {
	clientId: string;
	secret?: string;
	grantTypes?: string[];
	redirectUris?: string[];
	scope?: string | null;
	authMethod?: string;
	jwks?: { keys: JWK[] };
	jwksUri?: string;
}

/** Insert a client straight into the store. */
export async function addClient(h: Harness, init: ClientInit): Promise<McpClient> {
	const now = new Date();
	const confidential = init.secret !== undefined || init.authMethod === "private_key_jwt";
	const client: McpClient = {
		clientId: init.clientId,
		clientSecret: init.secret === undefined ? null : await hashClientSecret(init.secret),
		clientName: null,
		clientUri: null,
		logoUri: null,
		redirectUris: init.redirectUris ?? [REDIRECT],
		grantTypes: init.grantTypes ?? ["authorization_code", "refresh_token"],
		responseTypes: ["code"],
		tokenEndpointAuthMethod:
			init.authMethod ?? (init.secret === undefined ? "none" : "client_secret_basic"),
		scope: init.scope === undefined ? null : init.scope,
		contacts: null,
		tosUri: null,
		policyUri: null,
		softwareId: null,
		softwareVersion: null,
		clientType: confidential ? "confidential" : "public",
		disabled: false,
		userId: null,
		...(init.jwks ? { jwks: init.jwks } : {}),
		...(init.jwksUri ? { jwksUri: init.jwksUri } : {}),
		createdAt: now,
		updatedAt: now,
	};
	h.clients.set(client.clientId, client);
	return client;
}

export function tokenRequest(
	body: Record<string, string>,
	headers: Record<string, string> = {},
): Request {
	return new Request(TOKEN_URL, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
		body: new URLSearchParams(body).toString(),
	});
}

export function basicAuth(id: string, secret: string): Record<string, string> {
	return { Authorization: `Basic ${btoa(`${id}:${secret}`)}` };
}

export function decodePayload(token: string): Record<string, unknown> {
	const part = token.split(".")[1] ?? "";
	return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
}

export interface KeyMaterial {
	privateKey: CryptoKey;
	jwk: JWK;
}

export async function newKeys(alg = "ES256", kid = "k1"): Promise<KeyMaterial> {
	const { privateKey, publicKey } = await generateKeyPair(alg);
	return { privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg, use: "sig" } };
}

export async function dpopProof(keys: KeyMaterial, url = TOKEN_URL): Promise<string> {
	const { kid: _kid, alg: _alg, use: _use, ...publicJwk } = keys.jwk;
	return new SignJWT({
		htm: "POST",
		htu: url,
		jti: generateSecureToken(16),
		iat: Math.floor(Date.now() / 1000),
	})
		.setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
		.sign(keys.privateKey);
}

/** Authorization code flow for a registered client. Returns the token response. */
export async function codeFlow(
	h: Harness,
	clientId: string,
	opts: { scope?: string; secret?: string; dpop?: KeyMaterial } = {},
): Promise<McpTokenResponse> {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const params: Record<string, string> = {
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		scope: opts.scope ?? "mcp:read mcp:write",
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
	};
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
	const auth = await h.mcp.authorize(new Request(url));
	if (!auth.success) throw new Error(`${auth.error.code}: ${auth.error.message}`);
	const code = new URL(auth.data.redirectUri).searchParams.get("code") ?? "";
	const headers: Record<string, string> = opts.dpop ? { DPoP: await dpopProof(opts.dpop) } : {};
	if (opts.secret) Object.assign(headers, basicAuth(clientId, opts.secret));
	const res = await h.mcp.token(
		tokenRequest(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				client_id: clientId,
				code_verifier: verifier,
				resource: RESOURCE,
			},
			headers,
		),
	);
	if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
	return res.data;
}

export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface AssertionInit {
	aud?: string;
	jti?: string;
	iss?: string;
	sub?: string;
	/** Seconds from now. Default 60. */
	expiresIn?: number;
	alg?: string;
}

/** Build a private_key_jwt `client_assertion` for `clientId`. */
export async function clientAssertion(
	keys: KeyMaterial,
	clientId: string,
	init: AssertionInit = {},
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ jti: init.jti ?? generateSecureToken(16) })
		.setProtectedHeader({ alg: init.alg ?? "ES256", kid: keys.jwk.kid ?? "k1" })
		.setIssuer(init.iss ?? clientId)
		.setSubject(init.sub ?? clientId)
		.setAudience(init.aud ?? TOKEN_URL)
		.setIssuedAt(now)
		.setExpirationTime(now + (init.expiresIn ?? 60))
		.sign(keys.privateKey);
}
