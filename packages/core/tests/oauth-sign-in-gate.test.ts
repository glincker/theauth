/**
 * The OAuth callback must honor the sign-in gate: a required second factor
 * blocks session issuance and hands the challenge back in the URL fragment.
 */

import { describe, expect, it } from "vitest";
import { oauth } from "../src/auth/oauth/plugin.js";
import type { OAuthProvider, OAuthUserInfo } from "../src/auth/oauth/types.js";
import type { TwoFactorFactor } from "../src/auth/sign-in-gate.js";
import { users } from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
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
	verify: async (_userId, code) => code === "123456",
};

async function callback(require2fa: boolean): Promise<Response> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		baseUrl: "https://app.example.com",
		auth: { session: { secret: SECRET } },
		...(require2fa
			? { signInGate: { require2faFor: ["social" as const], factors: [enabledFactor] } }
			: {}),
		plugins: [oauth({ providers: { mock: mockProvider } })],
	});
	await theauth.db.insert(users).values({
		id: "member",
		email: EMAIL,
		emailVerified: 1,
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	const start = await theauth.plugins.handleRequest(
		new Request("https://app.example.com/auth/oauth/authorize/mock"),
	);
	const state = new URL(start?.headers.get("location") ?? "").searchParams.get("state");
	const res = await theauth.plugins.handleRequest(
		new Request(`https://app.example.com/auth/oauth/callback/mock?code=c&state=${state}`),
	);
	if (!res) throw new Error("no response");
	return res;
}

describe("OAuth callback and the sign-in gate", () => {
	it("issues a session when no gate is configured", async () => {
		const res = await callback(false);
		expect(res.status).toBe(302);
		expect(res.headers.get("set-cookie") ?? "").toContain("theauth_session=");
	});

	it("withholds the session and returns the challenge in the fragment when 2FA is required", async () => {
		const res = await callback(true);
		expect(res.status).toBe(302);
		expect(res.headers.get("set-cookie")).toBeNull();
		const location = new URL(res.headers.get("location") ?? "");
		expect(location.search).toBe("");
		const fragment = new URLSearchParams(location.hash.slice(1));
		expect(fragment.get("gate")).toBe("two_factor_required");
		expect(fragment.get("challenge")).toBeTruthy();
	});
});
