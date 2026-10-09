/**
 * Contract table for the generic-factory provider presets added in the
 * feature-gap pass. Every row must satisfy the same contract with a mocked
 * fetch: PKCE authorization URL, code exchange against the right token
 * endpoint, and userinfo mapped to a stable id and email.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	authentikProvider,
	boxProvider,
	giteaProvider,
	keycloakProvider,
	oneloginProvider,
	patreonProvider,
	wordpressProvider,
	yandexProvider,
	zitadelProvider,
} from "../src/auth/oauth/providers/index.js";
import type { OAuthProvider } from "../src/auth/oauth/types.js";

interface Row {
	name: string;
	build: () => OAuthProvider;
	/** Discovery document served for the issuer, when the preset discovers. */
	discovery?: { issuer: string; auth: string; token: string; userinfo: string };
	authorizeStart: string;
	tokenUrl: string;
	userinfoUrl: string;
	/** Raw userinfo body and the expected mapped result. */
	userinfoBody: Record<string, unknown>;
	expected: { id: string; email: string; name?: string };
	authHeader: string;
}

const ID = "client-id";
const SECRET = "client-secret";

const oidcBody = { sub: "u-1", email: "a@example.com", name: "Alice" };
const oidcExpected = { id: "u-1", email: "a@example.com", name: "Alice" };

const ROWS: Row[] = [
	{
		name: "keycloak",
		build: () => keycloakProvider("https://sso.example.com/", "main", ID, SECRET),
		discovery: {
			issuer: "https://sso.example.com/realms/main",
			auth: "https://sso.example.com/realms/main/protocol/openid-connect/auth",
			token: "https://sso.example.com/realms/main/protocol/openid-connect/token",
			userinfo: "https://sso.example.com/realms/main/protocol/openid-connect/userinfo",
		},
		authorizeStart: "https://sso.example.com/realms/main/protocol/openid-connect/auth?",
		tokenUrl: "https://sso.example.com/realms/main/protocol/openid-connect/token",
		userinfoUrl: "https://sso.example.com/realms/main/protocol/openid-connect/userinfo",
		userinfoBody: oidcBody,
		expected: oidcExpected,
		authHeader: "Bearer tok",
	},
	{
		name: "authentik",
		build: () => authentikProvider("https://auth.example.com", "my-app", ID, SECRET),
		discovery: {
			issuer: "https://auth.example.com/application/o/my-app",
			auth: "https://auth.example.com/application/o/authorize/",
			token: "https://auth.example.com/application/o/token/",
			userinfo: "https://auth.example.com/application/o/userinfo/",
		},
		authorizeStart: "https://auth.example.com/application/o/authorize/?",
		tokenUrl: "https://auth.example.com/application/o/token/",
		userinfoUrl: "https://auth.example.com/application/o/userinfo/",
		userinfoBody: oidcBody,
		expected: oidcExpected,
		authHeader: "Bearer tok",
	},
	{
		name: "zitadel",
		build: () => zitadelProvider("my-instance.zitadel.cloud", ID, SECRET),
		discovery: {
			issuer: "https://my-instance.zitadel.cloud",
			auth: "https://my-instance.zitadel.cloud/oauth/v2/authorize",
			token: "https://my-instance.zitadel.cloud/oauth/v2/token",
			userinfo: "https://my-instance.zitadel.cloud/oidc/v1/userinfo",
		},
		authorizeStart: "https://my-instance.zitadel.cloud/oauth/v2/authorize?",
		tokenUrl: "https://my-instance.zitadel.cloud/oauth/v2/token",
		userinfoUrl: "https://my-instance.zitadel.cloud/oidc/v1/userinfo",
		userinfoBody: oidcBody,
		expected: oidcExpected,
		authHeader: "Bearer tok",
	},
	{
		name: "onelogin",
		build: () => oneloginProvider("acme", ID, SECRET),
		discovery: {
			issuer: "https://acme.onelogin.com/oidc/2",
			auth: "https://acme.onelogin.com/oidc/2/auth",
			token: "https://acme.onelogin.com/oidc/2/token",
			userinfo: "https://acme.onelogin.com/oidc/2/me",
		},
		authorizeStart: "https://acme.onelogin.com/oidc/2/auth?",
		tokenUrl: "https://acme.onelogin.com/oidc/2/token",
		userinfoUrl: "https://acme.onelogin.com/oidc/2/me",
		userinfoBody: oidcBody,
		expected: oidcExpected,
		authHeader: "Bearer tok",
	},
	{
		name: "gitea",
		build: () => giteaProvider("https://gitea.example.com/", ID, SECRET),
		authorizeStart: "https://gitea.example.com/login/oauth/authorize?",
		tokenUrl: "https://gitea.example.com/login/oauth/access_token",
		userinfoUrl: "https://gitea.example.com/login/oauth/userinfo",
		userinfoBody: oidcBody,
		expected: oidcExpected,
		authHeader: "Bearer tok",
	},
	{
		name: "patreon",
		build: () => patreonProvider(ID, SECRET),
		authorizeStart: "https://www.patreon.com/oauth2/authorize?",
		tokenUrl: "https://www.patreon.com/api/oauth2/token",
		userinfoUrl: "https://www.patreon.com/api/oauth2/v2/identity",
		userinfoBody: { data: { id: "p-9", attributes: { email: "p@example.com", full_name: "Pat" } } },
		expected: { id: "p-9", email: "p@example.com", name: "Pat" },
		authHeader: "Bearer tok",
	},
	{
		name: "box",
		build: () => boxProvider(ID, SECRET),
		authorizeStart: "https://account.box.com/api/oauth2/authorize?",
		tokenUrl: "https://api.box.com/oauth2/token",
		userinfoUrl: "https://api.box.com/2.0/users/me",
		userinfoBody: { id: "1234", login: "b@example.com", name: "Bo" },
		expected: { id: "1234", email: "b@example.com", name: "Bo" },
		authHeader: "Bearer tok",
	},
	{
		name: "yandex",
		build: () => yandexProvider(ID, SECRET),
		authorizeStart: "https://oauth.yandex.com/authorize?",
		tokenUrl: "https://oauth.yandex.com/token",
		userinfoUrl: "https://login.yandex.ru/info",
		userinfoBody: { id: "y-1", default_email: "y@example.com", real_name: "Yan" },
		expected: { id: "y-1", email: "y@example.com", name: "Yan" },
		authHeader: "OAuth tok",
	},
	{
		name: "wordpress",
		build: () => wordpressProvider(ID, SECRET),
		authorizeStart: "https://public-api.wordpress.com/oauth2/authorize?",
		tokenUrl: "https://public-api.wordpress.com/oauth2/token",
		userinfoUrl: "https://public-api.wordpress.com/rest/v1/me",
		userinfoBody: { ID: 77, email: "w@example.com", display_name: "Wil" },
		expected: { id: "77", email: "w@example.com", name: "Wil" },
		authHeader: "Bearer tok",
	},
];

function json(body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});
}

interface Call {
	url: string;
	init: RequestInit | undefined;
}

function mockFetch(row: Row, calls: Call[]): void {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			const url = String(input);
			calls.push({ url, init });
			if (url.endsWith("/.well-known/openid-configuration") && row.discovery) {
				return json({
					issuer: row.discovery.issuer,
					authorization_endpoint: row.discovery.auth,
					token_endpoint: row.discovery.token,
					userinfo_endpoint: row.discovery.userinfo,
				});
			}
			if (url.startsWith(row.tokenUrl)) {
				return json({ access_token: "tok", token_type: "Bearer", expires_in: 3600 });
			}
			if (url.startsWith(row.userinfoUrl)) return json(row.userinfoBody);
			return new Response("unexpected", { status: 500 });
		}),
	);
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe.each(ROWS)("provider contract: $name", (row) => {
	it("exposes a stable id and scopes", () => {
		const p = row.build();
		expect(p.id).toBe(row.name);
		expect(p.name.length).toBeGreaterThan(0);
		expect(p.scopes.length).toBeGreaterThan(0);
	});

	it("builds an authorization URL with PKCE S256, state and redirect", async () => {
		const calls: Call[] = [];
		mockFetch(row, calls);
		const url = await row.build().getAuthorizationUrl("state-1", "v".repeat(43), "https://app/cb");
		expect(url.startsWith(row.authorizeStart)).toBe(true);
		const q = new URL(url).searchParams;
		expect(q.get("client_id")).toBe(ID);
		expect(q.get("state")).toBe("state-1");
		expect(q.get("redirect_uri")).toBe("https://app/cb");
		expect(q.get("response_type")).toBe("code");
		expect(q.get("code_challenge_method")).toBe("S256");
		expect(q.get("code_challenge")).toBeTruthy();
	});

	it("exchanges the code at the token endpoint with the verifier", async () => {
		const calls: Call[] = [];
		mockFetch(row, calls);
		const tokens = await row.build().exchangeCode("code-1", "verifier-1", "https://app/cb");
		expect(tokens.accessToken).toBe("tok");
		const call = calls.find((c) => c.url === row.tokenUrl);
		expect(call?.init?.method).toBe("POST");
		const body = new URLSearchParams(String(call?.init?.body));
		expect(body.get("grant_type")).toBe("authorization_code");
		expect(body.get("code")).toBe("code-1");
		expect(body.get("code_verifier")).toBe("verifier-1");
		expect(body.get("client_secret")).toBe(SECRET);
	});

	it("maps userinfo to id and email with the right auth scheme", async () => {
		const calls: Call[] = [];
		mockFetch(row, calls);
		const info = await row.build().getUserInfo("tok");
		expect(info.id).toBe(row.expected.id);
		expect(info.email).toBe(row.expected.email);
		expect(info.name).toBe(row.expected.name);
		const call = calls.find((c) => c.url.startsWith(row.userinfoUrl));
		const headers = call?.init?.headers as Record<string, string>;
		expect(headers.Authorization).toBe(row.authHeader);
	});

	it("rejects a failed token exchange", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response("denied", { status: 400 })),
		);
		const p = row.build();
		await expect(p.exchangeCode("c", "v", "https://app/cb")).rejects.toThrow();
	});
});

describe("mapProfile", () => {
	it("throws when the mapped profile has no email", async () => {
		const row = ROWS.find((r) => r.name === "box") as Row;
		mockFetch({ ...row, userinfoBody: { id: "1" } }, []);
		await expect(row.build().getUserInfo("tok")).rejects.toThrow(/usable id or email/);
	});
});
