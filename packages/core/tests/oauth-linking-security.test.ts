import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { oauth } from "../src/auth/oauth/plugin.js";
import type { OAuthProvider, OAuthUserInfo } from "../src/auth/oauth/types.js";
import { users } from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

function provider(userInfo: OAuthUserInfo): OAuthProvider {
	return {
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
}

async function setup(userInfo: OAuthUserInfo) {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		baseUrl: "https://app.example.com",
		auth: { session: { secret: "test-session-secret-that-is-at-least-32-chars!!" } },
		plugins: [oauth({ providers: { mock: provider(userInfo) } })],
	});
	return theauth;
}

async function signIn(theauth: Awaited<ReturnType<typeof setup>>): Promise<Response> {
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

async function seedUser(
	theauth: Awaited<ReturnType<typeof setup>>,
	email: string,
	emailVerified: number,
) {
	await theauth.db.insert(users).values({
		id: "victim",
		email,
		emailVerified,
		createdAt: new Date(),
		updatedAt: new Date(),
	});
}

describe("OAuth account linking by email", () => {
	it("does not sign in to an existing account when the provider email is unverified", async () => {
		const theauth = await setup({ id: "attacker-1", email: "victim@example.com", raw: {} });
		await seedUser(theauth, "victim@example.com", 1);
		const res = await signIn(theauth);
		expect(res.status).toBe(409);
		expect(res.headers.get("set-cookie")).toBeNull();
	});

	it("does not link into an unverified local account even if the provider verifies", async () => {
		const theauth = await setup({
			id: "g-1",
			email: "victim@example.com",
			emailVerified: true,
			raw: {},
		});
		await seedUser(theauth, "victim@example.com", 0);
		const res = await signIn(theauth);
		expect(res.status).toBe(409);
	});

	it("links when both sides are verified, matching email case-insensitively", async () => {
		const theauth = await setup({
			id: "g-1",
			email: "Victim@Example.com",
			emailVerified: true,
			raw: {},
		});
		await seedUser(theauth, "victim@example.com", 1);
		const res = await signIn(theauth);
		expect(res.status).toBe(302);
		expect(res.headers.get("set-cookie")).toContain("theauth_session=");
	});

	it("creates new users unverified when the provider does not vouch for the email", async () => {
		const theauth = await setup({ id: "n-1", email: "new@example.com", raw: {} });
		await signIn(theauth);
		const rows = await theauth.db.select().from(users).where(eq(users.email, "new@example.com"));
		expect(rows[0]?.emailVerified).toBe(0);
	});

	it("a replayed or concurrent callback state is consumed once", async () => {
		const theauth = await setup({
			id: "g-2",
			email: "r@example.com",
			emailVerified: true,
			raw: {},
		});
		const start = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/authorize/mock"),
		);
		const state = new URL(start?.headers.get("location") ?? "").searchParams.get("state");
		const cb = () =>
			theauth.plugins.handleRequest(
				new Request(`https://app.example.com/auth/oauth/callback/mock?code=c&state=${state}`),
			);
		const results = await Promise.all([cb(), cb(), cb()]);
		expect(results.filter((r) => r?.status === 302)).toHaveLength(1);
	});
});

describe("OAuth link endpoint", () => {
	it("cannot rebind a provider account that belongs to another user", async () => {
		const theauth = await setup({
			id: "g-3",
			email: "owner@example.com",
			emailVerified: true,
			raw: {},
		});
		await signIn(theauth);
		const { oauthAccounts } = await import("../src/auth/oauth/schema.js");
		const before = await theauth.db.select().from(oauthAccounts);
		const owner = before[0]?.userId;
		expect(owner).toBeTruthy();
		const { createOAuthModule } = await import("../src/auth/oauth/module.js");
		const mod = createOAuthModule(theauth.db, {
			providers: { mock: provider({ id: "g-3", email: undefined, raw: {} }) },
		});
		await expect(
			mod.linkAccount(
				"attacker",
				"mock",
				{ id: "g-3", email: undefined, raw: {} },
				{
					accessToken: "x",
					tokenType: "Bearer",
					raw: {},
				},
			),
		).rejects.toThrow(/already linked/);
	});
});
