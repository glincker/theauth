import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OAuthProvider, OAuthTokens, OAuthUserInfo } from "../src/auth/oauth/types.js";
import { createOAuthProxyModule, OAuthProxyError } from "../src/auth/oauth-proxy.js";

function makeProvider(overrides: Partial<OAuthProvider> = {}): OAuthProvider {
	return {
		id: "test-provider",
		name: "Test Provider",
		authorizationUrl: "https://provider.example.com/auth",
		tokenUrl: "https://provider.example.com/token",
		userInfoUrl: "https://provider.example.com/userinfo",
		scopes: ["openid", "email"],

		async getAuthorizationUrl(state: string, _codeVerifier: string, redirectUri: string) {
			return `https://provider.example.com/auth?state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
		},

		async exchangeCode(
			_code: string,
			_codeVerifier: string,
			_redirectUri: string,
		): Promise<OAuthTokens> {
			return {
				accessToken: "access-token-123",
				refreshToken: "refresh-token-456",
				expiresIn: 3600,
				tokenType: "Bearer",
				raw: { id_token: "id-token-789" },
			};
		},

		async getUserInfo(_accessToken: string): Promise<OAuthUserInfo> {
			return {
				id: "user-abc",
				email: "user@example.com",
				name: "Test User",
				raw: {},
			};
		},

		...overrides,
	};
}

const BASE_URL = "https://auth.example.com";
const ALLOWED_URI = "myapp://callback";
const ALLOWED_SCHEME = "com.example://";

function makeModule(
	allowedRedirectUris: string[] = [ALLOWED_URI],
	providerOverrides: Partial<OAuthProvider> = {},
) {
	return createOAuthProxyModule(
		{ allowedRedirectUris },
		{ google: makeProvider(providerOverrides) },
		BASE_URL,
	);
}

describe("startFlow", () => {
	it("returns authUrl and proxyState for an allowed redirect_uri", async () => {
		const mod = makeModule();
		const result = await mod.startFlow("google", ALLOWED_URI);

		expect(result.authUrl).toContain("https://provider.example.com/auth");
		expect(result.authUrl).toContain(encodeURIComponent(`${BASE_URL}/auth/oauth-proxy/callback`));
		expect(typeof result.proxyState).toBe("string");
		expect(result.proxyState.length).toBeGreaterThan(10);
	});

	it("rejects an unknown redirect_uri", async () => {
		const mod = makeModule();

		await expect(mod.startFlow("google", "evil://steal-tokens")).rejects.toThrow(OAuthProxyError);

		await expect(mod.startFlow("google", "evil://steal-tokens")).rejects.toMatchObject({
			code: "redirect_uri_not_allowed",
		});
	});

	it("rejects an unknown provider", async () => {
		const mod = makeModule();

		await expect(mod.startFlow("github", ALLOWED_URI)).rejects.toThrow(OAuthProxyError);

		await expect(mod.startFlow("github", ALLOWED_URI)).rejects.toMatchObject({
			code: "unknown_provider",
		});
	});

	it("allows a redirect_uri that matches an allowed scheme prefix", async () => {
		const mod = makeModule([ALLOWED_SCHEME]);
		const result = await mod.startFlow("google", "com.example://auth/callback");

		expect(result.proxyState).toBeTruthy();
	});

	it("rejects a redirect_uri that only partially matches an allowed entry (not scheme prefix)", async () => {
		const mod = makeModule(["myapp://callback"]);

		// Same prefix but not in allowlist as a scheme entry
		await expect(mod.startFlow("google", "myapp://callback/evil")).rejects.toThrow(OAuthProxyError);
	});

	it("forwards caller state in the flow", async () => {
		const mod = makeModule();
		const { proxyState } = await mod.startFlow("google", ALLOWED_URI, "caller-state-xyz");

		// The state is opaque to the caller; just confirm we get one back.
		expect(proxyState).toBeTruthy();
	});
});

describe("handleCallback", () => {
	it("exchanges the code and returns a redirect URL with tokens", async () => {
		const mod = makeModule();
		const { proxyState } = await mod.startFlow("google", ALLOWED_URI);

		const { redirectUrl, tokens } = await mod.handleCallback("auth-code-abc", proxyState);

		expect(redirectUrl).toContain(ALLOWED_URI);
		expect(redirectUrl).toContain("access_token=access-token-123");
		expect(redirectUrl).toContain("refresh_token=refresh-token-456");
		expect(redirectUrl).toContain("expires_in=3600");
		expect(redirectUrl).toContain("id_token=id-token-789");

		expect(tokens.accessToken).toBe("access-token-123");
		expect(tokens.refreshToken).toBe("refresh-token-456");
		expect(tokens.idToken).toBe("id-token-789");
		expect(tokens.expiresIn).toBe(3600);
	});

	it("includes caller state in the redirect URL when provided", async () => {
		const mod = makeModule();
		const { proxyState } = await mod.startFlow("google", ALLOWED_URI, "my-caller-state");

		const { redirectUrl } = await mod.handleCallback("code", proxyState);

		expect(redirectUrl).toContain("state=my-caller-state");
	});

	it("rejects an unknown proxyState", async () => {
		const mod = makeModule();

		await expect(mod.handleCallback("code", "unknown-state-value")).rejects.toThrow(
			OAuthProxyError,
		);

		await expect(mod.handleCallback("code", "unknown-state-value")).rejects.toMatchObject({
			code: "invalid_state",
		});
	});

	it("rejects a replayed proxyState (consumed on first use)", async () => {
		const mod = makeModule();
		const { proxyState } = await mod.startFlow("google", ALLOWED_URI);

		await mod.handleCallback("code", proxyState);

		await expect(mod.handleCallback("code", proxyState)).rejects.toMatchObject({
			code: "invalid_state",
		});
	});

	it("forwards provider exchange errors", async () => {
		const provider = makeProvider({
			async exchangeCode() {
				throw new Error("Provider token exchange failed: invalid_grant");
			},
		});
		const mod = createOAuthProxyModule(
			{ allowedRedirectUris: [ALLOWED_URI] },
			{ google: provider },
			BASE_URL,
		);

		const { proxyState } = await mod.startFlow("google", ALLOWED_URI);

		await expect(mod.handleCallback("bad-code", proxyState)).rejects.toThrow(
			"Provider token exchange failed",
		);
	});
});

describe("state TTL", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("rejects a proxyState after TTL has elapsed", async () => {
		const mod = createOAuthProxyModule(
			{ allowedRedirectUris: [ALLOWED_URI], stateTtlSeconds: 60 },
			{ google: makeProvider() },
			BASE_URL,
		);

		const { proxyState } = await mod.startFlow("google", ALLOWED_URI);

		// Advance time beyond TTL.
		vi.advanceTimersByTime(61 * 1000);

		await expect(mod.handleCallback("code", proxyState)).rejects.toMatchObject({
			code: "state_expired",
		});
	});

	it("accepts a proxyState before TTL has elapsed", async () => {
		const mod = createOAuthProxyModule(
			{ allowedRedirectUris: [ALLOWED_URI], stateTtlSeconds: 60 },
			{ google: makeProvider() },
			BASE_URL,
		);

		const { proxyState } = await mod.startFlow("google", ALLOWED_URI);

		// Advance time but stay within TTL.
		vi.advanceTimersByTime(30 * 1000);

		const { tokens } = await mod.handleCallback("code", proxyState);
		expect(tokens.accessToken).toBe("access-token-123");
	});
});

describe("PKCE passthrough", () => {
	it("passes the server-generated code verifier to the provider on exchange", async () => {
		let capturedVerifier: string | undefined;

		const provider = makeProvider({
			async exchangeCode(_code, codeVerifier, _redirectUri) {
				capturedVerifier = codeVerifier;
				return {
					accessToken: "at",
					tokenType: "Bearer",
					raw: {},
				};
			},
		});

		const mod = createOAuthProxyModule(
			{ allowedRedirectUris: [ALLOWED_URI] },
			{ google: provider },
			BASE_URL,
		);

		const { proxyState } = await mod.startFlow("google", ALLOWED_URI);
		await mod.handleCallback("code", proxyState);

		expect(capturedVerifier).toBeTruthy();
		expect(typeof capturedVerifier).toBe("string");
	});

	it("uses different code verifiers for different proxy flows", async () => {
		const verifiers: string[] = [];

		const provider = makeProvider({
			async exchangeCode(_code, codeVerifier) {
				verifiers.push(codeVerifier);
				return { accessToken: "at", tokenType: "Bearer", raw: {} };
			},
		});

		const mod = createOAuthProxyModule(
			{ allowedRedirectUris: [ALLOWED_URI] },
			{ google: provider },
			BASE_URL,
		);

		const flow1 = await mod.startFlow("google", ALLOWED_URI);
		const flow2 = await mod.startFlow("google", ALLOWED_URI);

		await mod.handleCallback("code1", flow1.proxyState);
		await mod.handleCallback("code2", flow2.proxyState);

		expect(verifiers).toHaveLength(2);
		expect(verifiers[0]).not.toBe(verifiers[1]);
	});
});

// handleRequest, HTTP routing

describe("handleRequest", () => {
	it("GET /auth/oauth-proxy/start returns JSON with authUrl and proxyState", async () => {
		const mod = makeModule();
		const url = `http://localhost/auth/oauth-proxy/start?provider=google&redirect_uri=${encodeURIComponent(ALLOWED_URI)}`;
		const response = await mod.handleRequest(new Request(url));

		expect(response).not.toBeNull();
		expect(response?.status).toBe(200);

		const body = (await response?.json()) as { authUrl: string; proxyState: string };
		expect(body.authUrl).toContain("provider.example.com");
		expect(body.proxyState).toBeTruthy();
	});

	it("GET /auth/oauth-proxy/start returns 400 for unknown redirect_uri", async () => {
		const mod = makeModule();
		const url = `http://localhost/auth/oauth-proxy/start?provider=google&redirect_uri=${encodeURIComponent("evil://steal")}`;
		const response = await mod.handleRequest(new Request(url));

		expect(response?.status).toBe(400);
	});

	it("GET /auth/oauth-proxy/start returns 400 when provider is missing", async () => {
		const mod = makeModule();
		const url = `http://localhost/auth/oauth-proxy/start?redirect_uri=${encodeURIComponent(ALLOWED_URI)}`;
		const response = await mod.handleRequest(new Request(url));

		expect(response?.status).toBe(400);
	});

	it("GET /auth/oauth-proxy/callback performs a 302 redirect to mobile app", async () => {
		const mod = makeModule();
		const startUrl = `http://localhost/auth/oauth-proxy/start?provider=google&redirect_uri=${encodeURIComponent(ALLOWED_URI)}`;
		const startRes = await mod.handleRequest(new Request(startUrl));
		const { proxyState } = (await startRes?.json()) as { authUrl: string; proxyState: string };

		const callbackUrl = `http://localhost/auth/oauth-proxy/callback?code=auth-code&state=${encodeURIComponent(proxyState)}`;
		const callbackRes = await mod.handleRequest(new Request(callbackUrl));

		expect(callbackRes?.status).toBe(302);
		const location = callbackRes?.headers.get("location");
		expect(location).toContain(ALLOWED_URI);
		expect(location).toContain("access_token=");
	});

	it("GET /auth/oauth-proxy/callback returns 400 for invalid state", async () => {
		const mod = makeModule();
		const callbackUrl = `http://localhost/auth/oauth-proxy/callback?code=code&state=invalid`;
		const response = await mod.handleRequest(new Request(callbackUrl));

		expect(response?.status).toBe(400);
	});

	it("returns null for non-proxy paths", async () => {
		const mod = makeModule();
		const response = await mod.handleRequest(new Request("http://localhost/auth/sign-in"));
		expect(response).toBeNull();
	});

	it("GET /auth/oauth-proxy/callback with error param redirects to mobile app with error", async () => {
		const mod = makeModule();
		const startUrl = `http://localhost/auth/oauth-proxy/start?provider=google&redirect_uri=${encodeURIComponent(ALLOWED_URI)}`;
		const startRes = await mod.handleRequest(new Request(startUrl));
		const { proxyState } = (await startRes?.json()) as { authUrl: string; proxyState: string };

		const callbackUrl = `http://localhost/auth/oauth-proxy/callback?error=access_denied&state=${encodeURIComponent(proxyState)}`;
		const response = await mod.handleRequest(new Request(callbackUrl));

		expect(response?.status).toBe(302);
		const location = response?.headers.get("location");
		expect(location).toContain(ALLOWED_URI);
		expect(location).toContain("error=access_denied");
	});
});
