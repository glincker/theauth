/**
 * Tests for the vendor providers built on the extended generic factory:
 * Linear, Kick, Vercel, PayPal and Kakao. Every test uses a mocked fetch.
 *
 * Quirks under test:
 * - Linear: comma separated scopes, GraphQL POST userinfo.
 * - Kick: PKCE required, profile nested in a `data` array.
 * - Vercel: POST userinfo, standard OIDC claims, email_verified honored.
 * - PayPal: Basic auth at the token endpoint, no PKCE, `flowEntry=static`,
 *   email taken from the `emails` array when `email` is absent.
 * - Kakao: comma separated scopes, numeric id, email nested under kakao_account.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { genericOIDC } from "../src/auth/oauth/providers/generic.js";
import {
	cognitoProvider,
	createKakaoProvider,
	createKickProvider,
	createLinearProvider,
	createPaypalProvider,
	createVercelProvider,
	huggingfaceProvider,
} from "../src/auth/oauth/providers/index.js";
import type { OAuthProvider } from "../src/auth/oauth/types.js";

const ID = "client-id";
const SECRET = "client-secret";
const CONFIG = { clientId: ID, clientSecret: SECRET };
const REDIRECT = "https://app.example/cb";
const VERIFIER = "v".repeat(43);

interface Call {
	url: string;
	init: RequestInit | undefined;
}

type Handler = (call: Call) => Response;

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function stubFetch(handler: Handler): Call[] {
	const calls: Call[] = [];
	vi.stubGlobal(
		"fetch",
		vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
			const call = { url: String(input), init };
			calls.push(call);
			return handler(call);
		}),
	);
	return calls;
}

function headersOf(call: Call | undefined): Record<string, string> {
	return (call?.init?.headers ?? {}) as Record<string, string>;
}

function formOf(call: Call | undefined): URLSearchParams {
	return new URLSearchParams(String(call?.init?.body));
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("genericOIDC extensions", () => {
	const base = {
		id: "x",
		name: "X",
		issuer: "https://x.example",
		clientId: ID,
		clientSecret: SECRET,
		authorizationUrl: "https://x.example/authorize",
		tokenUrl: "https://x.example/token",
		userinfoUrl: "https://x.example/me",
	};

	it("keeps the defaults when no extension is set", async () => {
		const calls = stubFetch((c) =>
			c.url.endsWith("/token") ? json({ access_token: "t" }) : json({ sub: "1", email: "a@b.c" }),
		);
		const p = genericOIDC(base);
		const q = new URL(await p.getAuthorizationUrl("s", VERIFIER, REDIRECT)).searchParams;
		expect(q.get("scope")).toBe("openid email profile");
		expect(q.get("code_challenge_method")).toBe("S256");
		await p.exchangeCode("c", VERIFIER, REDIRECT);
		const token = calls[0];
		expect(headersOf(token).Authorization).toBeUndefined();
		expect(formOf(token).get("client_secret")).toBe(SECRET);
		expect(formOf(token).get("code_verifier")).toBe(VERIFIER);
		await p.getUserInfo("t");
		expect(calls[1]?.init?.method).toBeUndefined();
	});

	it("honors scopeSeparator, authorizationParams and pkce:false", async () => {
		const p = genericOIDC({
			...base,
			scopes: ["a"],
			scopeSeparator: ",",
			authorizationParams: { flowEntry: "static" },
			pkce: false,
		});
		const q = new URL(await p.getAuthorizationUrl("s", VERIFIER, REDIRECT)).searchParams;
		expect(q.get("scope")).toBe("openid,email,profile,a");
		expect(q.get("flowEntry")).toBe("static");
		expect(q.has("code_challenge")).toBe(false);
		expect(q.has("code_challenge_method")).toBe(false);
	});

	it("sends credentials in a Basic header with tokenAuth basic, on exchange and refresh", async () => {
		const calls = stubFetch(() => json({ access_token: "t", refresh_token: "r2" }));
		const p = genericOIDC({ ...base, tokenAuth: "basic", pkce: false });
		await p.exchangeCode("c", VERIFIER, REDIRECT);
		const expected = `Basic ${btoa(`${ID}:${SECRET}`)}`;
		expect(headersOf(calls[0]).Authorization).toBe(expected);
		expect(formOf(calls[0]).has("client_secret")).toBe(false);
		expect(formOf(calls[0]).has("code_verifier")).toBe(false);
		await p.refreshTokens?.("r1");
		expect(headersOf(calls[1]).Authorization).toBe(expected);
		expect(formOf(calls[1]).get("grant_type")).toBe("refresh_token");
	});

	it("posts a JSON body to userinfo when userinfoMethod and userinfoBody are set", async () => {
		const calls = stubFetch(() => json({ sub: "1", email: "a@b.c" }));
		const p = genericOIDC({
			...base,
			userinfoMethod: "POST",
			userinfoBody: '{"q":1}',
		});
		await p.getUserInfo("tok");
		expect(calls[0]?.init?.method).toBe("POST");
		expect(calls[0]?.init?.body).toBe('{"q":1}');
		expect(headersOf(calls[0])["Content-Type"]).toBe("application/json");
	});

	it("passes emailVerified through from mapProfile", async () => {
		stubFetch(() => json({ u: "9", m: "a@b.c" }));
		const p = genericOIDC({
			...base,
			mapProfile: (raw) => ({
				id: String(raw.u),
				email: String(raw.m),
				emailVerified: true,
			}),
		});
		const info = await p.getUserInfo("tok");
		expect(info.emailVerified).toBe(true);
	});

	it("leaves emailVerified unset for the standard OIDC path", async () => {
		stubFetch(() => json({ sub: "1", email: "a@b.c", email_verified: true }));
		const info = await genericOIDC(base).getUserInfo("tok");
		expect(info.emailVerified).toBeUndefined();
	});
});

interface VendorRow {
	id: string;
	build: () => OAuthProvider;
	authorizeStart: string;
	tokenUrl: string;
	userinfoUrl: string;
	defaultScopes: string[];
	scopeSeparator: string;
	pkce: boolean;
	basicAuth: boolean;
	userinfoBody: unknown;
	expected: { id: string; email: string; name?: string; avatar?: string; emailVerified?: boolean };
	userinfoMethod?: string;
}

const VENDORS: VendorRow[] = [
	{
		id: "linear",
		build: () => createLinearProvider(CONFIG),
		authorizeStart: "https://linear.app/oauth/authorize?",
		tokenUrl: "https://api.linear.app/oauth/token",
		userinfoUrl: "https://api.linear.app/graphql",
		defaultScopes: ["read"],
		scopeSeparator: ",",
		pkce: true,
		basicAuth: false,
		userinfoMethod: "POST",
		userinfoBody: { data: { viewer: { id: "lin-1", name: "Lia", email: "lia@example.com" } } },
		expected: { id: "lin-1", email: "lia@example.com", name: "Lia" },
	},
	{
		id: "kick",
		build: () => createKickProvider(CONFIG),
		authorizeStart: "https://id.kick.com/oauth/authorize?",
		tokenUrl: "https://id.kick.com/oauth/token",
		userinfoUrl: "https://api.kick.com/public/v1/users",
		defaultScopes: ["user:read"],
		scopeSeparator: " ",
		pkce: true,
		basicAuth: false,
		userinfoBody: {
			data: [
				{
					user_id: 4242,
					name: "kicker",
					email: "k@example.com",
					profile_picture: "https://img.example/k.png",
				},
			],
			message: "OK",
		},
		expected: {
			id: "4242",
			email: "k@example.com",
			name: "kicker",
			avatar: "https://img.example/k.png",
		},
	},
	{
		id: "vercel",
		build: () => createVercelProvider(CONFIG),
		authorizeStart: "https://vercel.com/oauth/authorize?",
		tokenUrl: "https://api.vercel.com/login/oauth/token",
		userinfoUrl: "https://api.vercel.com/login/oauth/userinfo",
		defaultScopes: ["openid", "email", "profile"],
		scopeSeparator: " ",
		pkce: true,
		basicAuth: false,
		userinfoMethod: "POST",
		userinfoBody: {
			sub: "345e869043f1e55f8bdc837c",
			email: "t@example.com",
			email_verified: true,
			name: "Timmy",
			preferred_username: "timmy",
			picture: "https://api.vercel.com/www/avatar/x",
		},
		expected: {
			id: "345e869043f1e55f8bdc837c",
			email: "t@example.com",
			name: "Timmy",
			avatar: "https://api.vercel.com/www/avatar/x",
			emailVerified: true,
		},
	},
	{
		id: "paypal",
		build: () => createPaypalProvider(CONFIG),
		authorizeStart: "https://www.paypal.com/connect?",
		tokenUrl: "https://api-m.paypal.com/v1/oauth2/token",
		userinfoUrl: "https://api-m.paypal.com/v1/identity/openidconnect/userinfo",
		defaultScopes: ["openid", "email", "profile"],
		scopeSeparator: " ",
		pkce: false,
		basicAuth: true,
		userinfoBody: {
			user_id: "https://www.paypal.com/webapps/auth/identity/user/abc",
			name: "Pat Payer",
			emails: [
				{ value: "other@example.com", primary: false },
				{ value: "pat@example.com", primary: true },
			],
		},
		expected: {
			id: "https://www.paypal.com/webapps/auth/identity/user/abc",
			email: "pat@example.com",
			name: "Pat Payer",
		},
	},
	{
		id: "kakao",
		build: () => createKakaoProvider(CONFIG),
		authorizeStart: "https://kauth.kakao.com/oauth/authorize?",
		tokenUrl: "https://kauth.kakao.com/oauth/token",
		userinfoUrl: "https://kapi.kakao.com/v2/user/me",
		defaultScopes: ["account_email", "profile_nickname", "profile_image"],
		scopeSeparator: ",",
		pkce: false,
		basicAuth: false,
		userinfoBody: {
			id: 4000000000123,
			kakao_account: {
				email: "ka@example.com",
				is_email_valid: true,
				is_email_verified: true,
				profile: { nickname: "Kay", profile_image_url: "https://img.example/ka.png" },
			},
		},
		expected: {
			id: "4000000000123",
			email: "ka@example.com",
			name: "Kay",
			avatar: "https://img.example/ka.png",
			emailVerified: true,
		},
	},
];

function vendorFetch(row: VendorRow, userBody: unknown = row.userinfoBody): Call[] {
	return stubFetch((c) => {
		if (c.url.startsWith(row.tokenUrl)) {
			return json({
				access_token: "tok",
				refresh_token: "ref",
				token_type: "bearer",
				expires_in: 3600,
			});
		}
		if (c.url.startsWith(row.userinfoUrl)) return json(userBody);
		return new Response("unexpected", { status: 500 });
	});
}

describe.each(VENDORS)("vendor provider: $id", (row) => {
	it("exposes id, name and default scopes", () => {
		const p = row.build();
		expect(p.id).toBe(row.id);
		expect(p.name.length).toBeGreaterThan(0);
		expect(p.scopes).toEqual(row.defaultScopes);
		expect(p.tokenUrl).toBe(row.tokenUrl);
		expect(p.userInfoUrl?.startsWith(row.userinfoUrl)).toBe(true);
	});

	it("merges caller scopes with the defaults", () => {
		const p = createProvider(row, ["extra:scope"]);
		expect(p.scopes).toEqual([...row.defaultScopes, "extra:scope"]);
	});

	it("builds the authorization URL", async () => {
		const url = await row.build().getAuthorizationUrl("state-1", VERIFIER, REDIRECT);
		expect(url.startsWith(row.authorizeStart)).toBe(true);
		const q = new URL(url).searchParams;
		expect(q.get("client_id")).toBe(ID);
		expect(q.get("state")).toBe("state-1");
		expect(q.get("redirect_uri")).toBe(REDIRECT);
		expect(q.get("response_type")).toBe("code");
		expect(q.get("scope")).toBe(row.defaultScopes.join(row.scopeSeparator));
		if (row.pkce) {
			expect(q.get("code_challenge_method")).toBe("S256");
			expect(q.get("code_challenge")).toBeTruthy();
		} else {
			expect(q.has("code_challenge")).toBe(false);
		}
	});

	it("sends client credentials the documented way on code exchange", async () => {
		const calls = vendorFetch(row);
		const tokens = await row.build().exchangeCode("code-1", VERIFIER, REDIRECT);
		expect(tokens.accessToken).toBe("tok");
		expect(tokens.refreshToken).toBe("ref");
		expect(tokens.expiresIn).toBe(3600);
		const call = calls[0];
		expect(call?.url).toBe(row.tokenUrl);
		expect(call?.init?.method).toBe("POST");
		const form = formOf(call);
		expect(form.get("grant_type")).toBe("authorization_code");
		expect(form.get("code")).toBe("code-1");
		expect(form.get("redirect_uri")).toBe(REDIRECT);
		if (row.basicAuth) {
			expect(headersOf(call).Authorization).toBe(`Basic ${btoa(`${ID}:${SECRET}`)}`);
			expect(form.has("client_secret")).toBe(false);
		} else {
			expect(headersOf(call).Authorization).toBeUndefined();
			expect(form.get("client_id")).toBe(ID);
			expect(form.get("client_secret")).toBe(SECRET);
		}
		expect(form.get("code_verifier")).toBe(row.pkce ? VERIFIER : null);
	});

	it("maps userinfo to the normalized user", async () => {
		const calls = vendorFetch(row);
		const info = await row.build().getUserInfo("tok");
		expect(info.id).toBe(row.expected.id);
		expect(info.email).toBe(row.expected.email);
		expect(info.name).toBe(row.expected.name);
		expect(info.avatar).toBe(row.expected.avatar);
		expect(info.emailVerified).toBe(row.expected.emailVerified);
		const call = calls[0];
		expect(headersOf(call).Authorization).toBe("Bearer tok");
		expect(call?.init?.method ?? "GET").toBe(row.userinfoMethod ?? "GET");
	});

	it("rejects a failed token exchange", async () => {
		stubFetch(() => new Response("denied", { status: 400 }));
		await expect(row.build().exchangeCode("c", VERIFIER, REDIRECT)).rejects.toThrow(
			/token exchange failed \(400\)/,
		);
	});

	it("rejects a failed userinfo request", async () => {
		stubFetch(() => new Response("nope", { status: 401 }));
		await expect(row.build().getUserInfo("tok")).rejects.toThrow(/userinfo fetch failed \(401\)/);
	});

	it("rejects a userinfo response with no id or email", async () => {
		vendorFetch(row, {});
		await expect(row.build().getUserInfo("tok")).rejects.toThrow();
	});

	it("refreshes tokens against the token endpoint", async () => {
		const calls = vendorFetch(row);
		const p = row.build();
		expect(p.refreshTokens).toBeTypeOf("function");
		const tokens = await p.refreshTokens?.("old-refresh");
		expect(tokens?.accessToken).toBe("tok");
		const call = calls[0];
		expect(call?.url).toBe(row.tokenUrl);
		const form = formOf(call);
		expect(form.get("grant_type")).toBe("refresh_token");
		expect(form.get("refresh_token")).toBe("old-refresh");
		if (row.basicAuth) {
			expect(headersOf(call).Authorization).toBe(`Basic ${btoa(`${ID}:${SECRET}`)}`);
		} else {
			expect(form.get("client_secret")).toBe(SECRET);
		}
	});
});

function createProvider(row: VendorRow, scopes: string[]): OAuthProvider {
	const config = { ...CONFIG, scopes };
	switch (row.id) {
		case "linear":
			return createLinearProvider(config);
		case "kick":
			return createKickProvider(config);
		case "vercel":
			return createVercelProvider(config);
		case "paypal":
			return createPaypalProvider(config);
		default:
			return createKakaoProvider(config);
	}
}

describe("linear specifics", () => {
	it("posts the viewer query as JSON", async () => {
		const row = VENDORS[0] as VendorRow;
		const calls = vendorFetch(row);
		await row.build().getUserInfo("tok");
		const call = calls[0];
		expect(headersOf(call)["Content-Type"]).toBe("application/json");
		const body = JSON.parse(String(call?.init?.body)) as { query: string };
		expect(body.query).toContain("viewer");
		expect(body.query).toContain("email");
	});

	it("surfaces GraphQL errors as a failure", async () => {
		const row = VENDORS[0] as VendorRow;
		vendorFetch(row, { errors: [{ message: "AUTHENTICATION_ERROR" }], data: null });
		await expect(row.build().getUserInfo("tok")).rejects.toThrow();
	});
});

describe("kick specifics", () => {
	it("fails when the data array is empty", async () => {
		const row = VENDORS[1] as VendorRow;
		vendorFetch(row, { data: [], message: "OK" });
		await expect(row.build().getUserInfo("tok")).rejects.toThrow();
	});
});

describe("vercel specifics", () => {
	it("does not trust an email that is not marked verified", async () => {
		const row = VENDORS[2] as VendorRow;
		vendorFetch(row, { sub: "u", email: "a@b.c" });
		const info = await row.build().getUserInfo("tok");
		expect(info.emailVerified).toBe(false);
	});
});

describe("paypal specifics", () => {
	it("uses the sandbox hosts when sandbox is set", async () => {
		const p = createPaypalProvider({ ...CONFIG, sandbox: true });
		expect(p.tokenUrl).toBe("https://api-m.sandbox.paypal.com/v1/oauth2/token");
		const url = await p.getAuthorizationUrl("s", VERIFIER, REDIRECT);
		expect(url.startsWith("https://www.sandbox.paypal.com/connect?")).toBe(true);
		expect(p.userInfoUrl).toContain("api-m.sandbox.paypal.com/v1/identity/openidconnect/userinfo");
	});

	it("sets flowEntry=static and the userinfo schema", async () => {
		const p = createPaypalProvider(CONFIG);
		const q = new URL(await p.getAuthorizationUrl("s", VERIFIER, REDIRECT)).searchParams;
		expect(q.get("flowEntry")).toBe("static");
		expect(p.userInfoUrl).toContain("schema=openid");
	});

	it("prefers the email field over the emails array", async () => {
		const row = VENDORS[3] as VendorRow;
		vendorFetch(row, { user_id: "u1", email: "direct@example.com", emails: [] });
		const info = await row.build().getUserInfo("tok");
		expect(info.email).toBe("direct@example.com");
	});

	it("never marks the email verified", async () => {
		const row = VENDORS[3] as VendorRow;
		vendorFetch(row);
		const info = await row.build().getUserInfo("tok");
		expect(info.emailVerified).toBeUndefined();
	});
});

describe("kakao specifics", () => {
	it("does not trust an unverified or invalid email", async () => {
		const row = VENDORS[4] as VendorRow;
		vendorFetch(row, {
			id: 1,
			kakao_account: { email: "ka@example.com", is_email_valid: true, is_email_verified: false },
		});
		const info = await row.build().getUserInfo("tok");
		expect(info.emailVerified).toBe(false);
	});

	it("fails when the account has no email consent", async () => {
		const row = VENDORS[4] as VendorRow;
		vendorFetch(row, { id: 1, kakao_account: { profile: { nickname: "Kay" } } });
		await expect(row.build().getUserInfo("tok")).rejects.toThrow(/usable id or email/);
	});
});

describe("presets checked against vendor documentation", () => {
	it("huggingface uses the documented endpoints and standard claims", async () => {
		const calls = stubFetch((c) =>
			c.url.startsWith("https://huggingface.co/oauth/token")
				? json({ access_token: "tok" })
				: json({ sub: "hf-1", email: "h@example.com", name: "Hugo" }),
		);
		const p = huggingfaceProvider(ID, SECRET);
		const url = await p.getAuthorizationUrl("s", VERIFIER, REDIRECT);
		expect(url.startsWith("https://huggingface.co/oauth/authorize?")).toBe(true);
		expect(new URL(url).searchParams.get("code_challenge_method")).toBe("S256");
		await p.exchangeCode("c", VERIFIER, REDIRECT);
		expect(calls[0]?.url).toBe("https://huggingface.co/oauth/token");
		const info = await p.getUserInfo("tok");
		expect(calls[1]?.url).toBe("https://huggingface.co/oauth/userinfo");
		expect(info).toMatchObject({ id: "hf-1", email: "h@example.com", name: "Hugo" });
	});

	it("cognito uses the user pool domain endpoints", async () => {
		const calls = stubFetch((c) =>
			c.url.endsWith("/oauth2/token")
				? json({ access_token: "tok", refresh_token: "r" })
				: json({ sub: "uuid-1", email: "c@example.com", email_verified: "true", username: "c" }),
		);
		const p = cognitoProvider("my-app.auth.us-east-1.amazoncognito.com", ID, SECRET);
		const url = await p.getAuthorizationUrl("s", VERIFIER, REDIRECT);
		expect(
			url.startsWith("https://my-app.auth.us-east-1.amazoncognito.com/oauth2/authorize?"),
		).toBe(true);
		await p.exchangeCode("c", VERIFIER, REDIRECT);
		expect(calls[0]?.url).toBe("https://my-app.auth.us-east-1.amazoncognito.com/oauth2/token");
		const info = await p.getUserInfo("tok");
		expect(calls[1]?.url).toBe("https://my-app.auth.us-east-1.amazoncognito.com/oauth2/userInfo");
		expect(info.id).toBe("uuid-1");
		expect(info.email).toBe("c@example.com");
	});
});
