import { describe, expect, it } from "vitest";
import { deriveCodeChallenge, generateCodeVerifier } from "../src/auth/oauth/pkce.js";
import { oauth } from "../src/auth/oauth/plugin.js";
import type { OAuthProvider, OAuthUserInfo } from "../src/auth/oauth/types.js";
import type { TwoFactorFactor } from "../src/auth/sign-in-gate.js";
import { users } from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const BASE = "https://app.example.com";
const APP = "myapp://auth/callback";
const EMAIL = "member@example.com";

const userInfo: OAuthUserInfo = {
	id: "provider-1",
	email: EMAIL,
	emailVerified: true,
	name: "Member",
};

const mockProvider: OAuthProvider = {
	id: "mock",
	name: "Mock",
	authorizationUrl: "https://mock.example/auth",
	tokenUrl: "https://mock.example/token",
	userInfoUrl: "https://mock.example/userinfo",
	scopes: ["email"],
	async getAuthorizationUrl(state) {
		return `https://mock.example/auth?state=${state}`;
	},
	async exchangeCode() {
		return { accessToken: "at", tokenType: "Bearer", raw: {} };
	},
	async getUserInfo() {
		return userInfo;
	},
};

const enabledFactor: TwoFactorFactor = {
	id: "fake",
	isEnabled: async () => true,
	verify: async () => true,
};

async function setup(opts: { mobile?: boolean; gate?: boolean } = {}) {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		baseUrl: BASE,
		auth: { session: { secret: SECRET } },
		...(opts.gate
			? { signInGate: { require2faFor: ["social" as const], factors: [enabledFactor] } }
			: {}),
		plugins: [
			oauth({
				providers: { mock: mockProvider },
				...(opts.mobile === false ? {} : { mobile: { redirectUris: [APP] } }),
			}),
		],
	});
	await theauth.db.insert(users).values({
		id: "member",
		email: EMAIL,
		emailVerified: 1,
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	const send = async (path: string, init?: RequestInit): Promise<Response> => {
		const res = await theauth.plugins.handleRequest(new Request(`${BASE}${path}`, init));
		if (!res) throw new Error(`no response for ${path}`);
		return res;
	};
	return { theauth, send };
}

async function start(send: (p: string, i?: RequestInit) => Promise<Response>, challenge: string) {
	const q = new URLSearchParams({
		mobile_redirect: APP,
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const res = await send(`/auth/oauth/authorize/mock?${q}`);
	const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
	const state = new URL(res.headers.get("location") ?? BASE).searchParams.get("state");
	return { res, cookie, state };
}

async function exchange(
	send: (p: string, i?: RequestInit) => Promise<Response>,
	code: string,
	verifier: string,
) {
	return send("/auth/oauth/mobile/exchange", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ code, code_verifier: verifier }),
	});
}

describe("native app OAuth sign-in", () => {
	it("hands the app a code, then trades it with the PKCE verifier for a session", async () => {
		const { theauth, send } = await setup();
		const verifier = generateCodeVerifier();
		const { res, cookie, state } = await start(send, await deriveCodeChallenge(verifier));
		expect(res.status).toBe(302);
		expect(cookie).toContain("theauth_mobile_oauth=");

		const cb = await send(`/auth/oauth/callback/mock?code=c&state=${state}`, {
			headers: { cookie },
		});
		expect(cb.status).toBe(302);
		const location = new URL(cb.headers.get("location") ?? "");
		expect(`${location.protocol}//${location.host}${location.pathname}`).toBe(
			"myapp://auth/callback",
		);
		expect(cb.headers.get("set-cookie") ?? "").not.toContain("theauth_session=");
		const code = location.searchParams.get("code") ?? "";
		expect(code).not.toBe("");

		const done = await exchange(send, code, verifier);
		expect(done.status).toBe(200);
		const body = (await done.json()) as { data: { token: string; user: { id: string } } };
		expect(body.data.user.id).toBe("member");
		const session = await theauth.auth.session?.validate(body.data.token);
		expect(session?.userId).toBe("member");

		const replay = await exchange(send, code, verifier);
		expect(replay.status).toBe(400);
	});

	it("refuses a wrong verifier and burns the code", async () => {
		const { send } = await setup();
		const verifier = generateCodeVerifier();
		const { cookie, state } = await start(send, await deriveCodeChallenge(verifier));
		const cb = await send(`/auth/oauth/callback/mock?code=c&state=${state}`, {
			headers: { cookie },
		});
		const code = new URL(cb.headers.get("location") ?? "").searchParams.get("code") ?? "";

		const wrong = await exchange(send, code, generateCodeVerifier());
		expect(wrong.status).toBe(400);
		const right = await exchange(send, code, verifier);
		expect(right.status).toBe(400);
	});

	it("rejects redirects outside the allowlist and missing challenges", async () => {
		const { send } = await setup();
		const challenge = await deriveCodeChallenge(generateCodeVerifier());
		const evil = new URLSearchParams({
			mobile_redirect: "evil://steal",
			code_challenge: challenge,
			code_challenge_method: "S256",
		});
		expect((await send(`/auth/oauth/authorize/mock?${evil}`)).status).toBe(400);
		const noChallenge = new URLSearchParams({ mobile_redirect: APP });
		expect((await send(`/auth/oauth/authorize/mock?${noChallenge}`)).status).toBe(400);
	});

	it("is off unless configured", async () => {
		const { send } = await setup({ mobile: false });
		const q = new URLSearchParams({
			mobile_redirect: APP,
			code_challenge: await deriveCodeChallenge(generateCodeVerifier()),
			code_challenge_method: "S256",
		});
		expect((await send(`/auth/oauth/authorize/mock?${q}`)).status).toBe(400);
	});

	it("keeps the web flow when no mobile cookie is present", async () => {
		const { send } = await setup();
		const web = await send("/auth/oauth/authorize/mock");
		const state = new URL(web.headers.get("location") ?? BASE).searchParams.get("state");
		const cb = await send(`/auth/oauth/callback/mock?code=c&state=${state}`);
		expect(cb.headers.get("set-cookie") ?? "").toContain("theauth_session=");
	});

	it("sends a gate challenge to the app instead of a code", async () => {
		const { send } = await setup({ gate: true });
		const { cookie, state } = await start(send, await deriveCodeChallenge(generateCodeVerifier()));
		const cb = await send(`/auth/oauth/callback/mock?code=c&state=${state}`, {
			headers: { cookie },
		});
		const location = cb.headers.get("location") ?? "";
		expect(location.startsWith("myapp://auth/callback#")).toBe(true);
		expect(location).toContain("gate=two_factor_required");
		expect(location).not.toContain("code=");
	});

	it("returns provider errors to the app, not as JSON in the browser", async () => {
		const { send } = await setup();
		const { cookie } = await start(send, await deriveCodeChallenge(generateCodeVerifier()));
		const cb = await send("/auth/oauth/callback/mock?code=c&state=unknown", {
			headers: { cookie },
		});
		expect(cb.status).toBe(302);
		expect(cb.headers.get("location") ?? "").toContain("myapp://auth/callback?error=");
	});
});
