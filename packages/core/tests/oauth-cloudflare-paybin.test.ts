/** Cloudflare and Paybin providers against a mocked fetch (token and profile endpoints). */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	createCloudflareProvider,
	createPaybinProvider,
} from "../src/auth/oauth/providers/index.js";

const CONFIG = { clientId: "cid", clientSecret: "sec" };
const REDIRECT = "https://app.example/cb";
const VERIFIER = "v".repeat(43);

interface Call {
	url: string;
	init: RequestInit | undefined;
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function stub(responses: Record<string, unknown>): Call[] {
	const calls: Call[] = [];
	vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
		const key = String(url);
		calls.push({ url: key, init });
		const body = responses[key];
		return body === undefined ? json({ error: "unexpected" }, 500) : json(body);
	});
	return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("cloudflare provider", () => {
	const TOKEN = "https://dash.cloudflare.com/oauth2/token";
	const USER = "https://api.cloudflare.com/client/v4/user";

	it("builds the authorize URL with PKCE and the default scope", async () => {
		const url = new URL(
			await createCloudflareProvider(CONFIG).getAuthorizationUrl("st", VERIFIER, REDIRECT),
		);
		expect(`${url.origin}${url.pathname}`).toBe("https://dash.cloudflare.com/oauth2/auth");
		expect(url.searchParams.get("scope")).toBe("user-details.read");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("state")).toBe("st");
	});

	it("adds opt in scopes without dropping the default", () => {
		const p = createCloudflareProvider({ ...CONFIG, scopes: ["offline_access"] });
		expect(p.scopes).toEqual(["user-details.read", "offline_access"]);
	});

	it("exchanges the code with basic auth by default", async () => {
		const calls = stub({ [TOKEN]: { access_token: "at", refresh_token: "rt", expires_in: 3600 } });
		const tokens = await createCloudflareProvider(CONFIG).exchangeCode("code", VERIFIER, REDIRECT);
		expect(tokens.accessToken).toBe("at");
		expect(tokens.refreshToken).toBe("rt");
		const headers = calls[0]?.init?.headers as Record<string, string>;
		expect(headers.Authorization).toBe(`Basic ${btoa("cid:sec")}`);
		const form = new URLSearchParams(String(calls[0]?.init?.body));
		expect(form.get("code_verifier")).toBe(VERIFIER);
		expect(form.has("client_secret")).toBe(false);
	});

	it("posts credentials in the body for client_secret_post", async () => {
		const calls = stub({ [TOKEN]: { access_token: "at" } });
		await createCloudflareProvider({
			...CONFIG,
			tokenEndpointAuthMethod: "client_secret_post",
		}).exchangeCode("code", VERIFIER, REDIRECT);
		const form = new URLSearchParams(String(calls[0]?.init?.body));
		expect(form.get("client_secret")).toBe("sec");
		const headers = calls[0]?.init?.headers as Record<string, string>;
		expect(headers.Authorization).toBeUndefined();
	});

	it("reads the profile from the API envelope and leaves emailVerified unset", async () => {
		const calls = stub({
			[USER]: {
				success: true,
				result: { id: "u1", email: "a@b.c", first_name: "Ada", last_name: "L" },
			},
		});
		const info = await createCloudflareProvider(CONFIG).getUserInfo("at");
		expect(info).toMatchObject({ id: "u1", email: "a@b.c", name: "Ada L" });
		expect(info.emailVerified).toBeUndefined();
		const headers = calls[0]?.init?.headers as Record<string, string>;
		expect(headers.Authorization).toBe("Bearer at");
	});

	it("falls back to the email for the name and rejects a failed envelope", async () => {
		stub({ [USER]: { success: true, result: { id: "u1", email: "a@b.c" } } });
		expect((await createCloudflareProvider(CONFIG).getUserInfo("at")).name).toBe("a@b.c");
		stub({ [USER]: { success: false, errors: [{ code: 1, message: "x" }], result: null } });
		await expect(createCloudflareProvider(CONFIG).getUserInfo("at")).rejects.toThrow();
	});

	it("refreshes with basic auth", async () => {
		const calls = stub({ [TOKEN]: { access_token: "new" } });
		await createCloudflareProvider(CONFIG).refreshTokens?.("old");
		const headers = calls[0]?.init?.headers as Record<string, string>;
		expect(headers.Authorization).toBe(`Basic ${btoa("cid:sec")}`);
		expect(new URLSearchParams(String(calls[0]?.init?.body)).get("grant_type")).toBe(
			"refresh_token",
		);
	});
});

describe("paybin provider", () => {
	const TOKEN = "https://idp.paybin.io/connect/token";
	const USER = "https://idp.paybin.io/connect/userinfo";

	it("uses the Paybin endpoints, OIDC scopes and PKCE", async () => {
		const p = createPaybinProvider({ ...CONFIG, scopes: ["offline_access"] });
		expect(p.scopes).toEqual(["openid", "email", "profile", "offline_access"]);
		const url = new URL(await p.getAuthorizationUrl("st", VERIFIER, REDIRECT));
		expect(`${url.origin}${url.pathname}`).toBe("https://idp.paybin.io/connect/authorize");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
	});

	it("exchanges the code with the secret in the body", async () => {
		const calls = stub({ [TOKEN]: { access_token: "at", id_token: "x" } });
		const tokens = await createPaybinProvider(CONFIG).exchangeCode("code", VERIFIER, REDIRECT);
		expect(tokens.accessToken).toBe("at");
		const form = new URLSearchParams(String(calls[0]?.init?.body));
		expect(form.get("client_secret")).toBe("sec");
	});

	it("maps claims and honors email_verified", async () => {
		stub({
			[USER]: {
				sub: "p1",
				email: "a@b.c",
				email_verified: true,
				preferred_username: "ada",
				picture: "https://i/x.png",
			},
		});
		const info = await createPaybinProvider(CONFIG).getUserInfo("at");
		expect(info).toMatchObject({
			id: "p1",
			email: "a@b.c",
			emailVerified: true,
			name: "ada",
			avatar: "https://i/x.png",
		});
	});

	it("leaves emailVerified unset when absent and fails without an email", async () => {
		stub({ [USER]: { sub: "p1", email: "a@b.c", name: "Ada" } });
		expect((await createPaybinProvider(CONFIG).getUserInfo("at")).emailVerified).toBeUndefined();
		stub({ [USER]: { sub: "p1" } });
		await expect(createPaybinProvider(CONFIG).getUserInfo("at")).rejects.toThrow();
	});
});
