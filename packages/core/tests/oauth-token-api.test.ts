/**
 * Social token API: getAccessToken with refresh, encryption at rest,
 * listAccounts / unlinkAccount guard, and the plugin routes.
 */

import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OAuthTokenError } from "../src/auth/oauth/errors.js";
import { createOAuthModule } from "../src/auth/oauth/module.js";
import { oauth } from "../src/auth/oauth/plugin.js";
import { createGoogleProvider } from "../src/auth/oauth/providers/google.js";
import { oauthAccounts } from "../src/auth/oauth/schema.js";
import type { OAuthTokens, OAuthUserInfo } from "../src/auth/oauth/types.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

const KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"; // 32 bytes base64url
const KEY_B = "HyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4";
const T0 = 1_800_000_000_000;

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	for (const id of ["u1", "u2"]) {
		db.insert(schema.users)
			.values({
				id,
				email: `${id}@example.com`,
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
	}
	return db;
}

const INFO: OAuthUserInfo = { id: "g-123", email: "u1@example.com", raw: {} };

function tokens(over: Partial<OAuthTokens> = {}): OAuthTokens {
	return {
		accessToken: "at-1",
		refreshToken: "rt-1",
		expiresIn: 3600,
		tokenType: "Bearer",
		raw: {},
		...over,
	};
}

interface TokenEndpoint {
	calls: Array<{ url: string; body: URLSearchParams }>;
	respond: (call: number) => { status: number; body: Record<string, unknown> };
}

function mockTokenEndpoint(endpoint: TokenEndpoint) {
	return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		endpoint.calls.push({
			url: String(input),
			body: new URLSearchParams(String(init?.body ?? "")),
		});
		const r = endpoint.respond(endpoint.calls.length);
		return new Response(JSON.stringify(r.body), {
			status: r.status,
			headers: { "Content-Type": "application/json" },
		});
	});
}

describe("OAuth token API", () => {
	let db: Database;
	let clock: number;
	const google = createGoogleProvider({ clientId: "cid", clientSecret: "csecret" });

	function mod(extra: Record<string, unknown> = {}) {
		return createOAuthModule(db, {
			providers: { google },
			now: () => clock,
			...extra,
		});
	}

	beforeEach(async () => {
		db = await createTestDb();
		clock = T0;
		// linkAccount computes expiry from the real clock; tests set rows directly when timing matters.
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	async function link(m: ReturnType<typeof mod>, over: Partial<OAuthTokens> = {}) {
		const account = await m.linkAccount("u1", "google", INFO, tokens(over));
		// Pin expiry relative to the injected clock.
		await db
			.update(oauthAccounts)
			.set({ expiresAt: new Date(T0 + 3600_000) })
			.where(eq(oauthAccounts.id, account.id));
		return account;
	}

	async function row(id: string) {
		return (await db.select().from(oauthAccounts).where(eq(oauthAccounts.id, id)))[0];
	}

	describe("getAccessToken", () => {
		it("returns the stored token without hitting the provider while fresh", async () => {
			const m = mod();
			await link(m);
			const spy = vi.spyOn(globalThis, "fetch");
			const t = await m.getAccessToken({ userId: "u1", provider: "google" });
			expect(t.accessToken).toBe("at-1");
			expect(t.refreshed).toBe(false);
			expect(spy).not.toHaveBeenCalled();
		});

		it("throws no_account when nothing is linked", async () => {
			const m = mod();
			await expect(m.getAccessToken({ userId: "u1", provider: "google" })).rejects.toMatchObject({
				name: "OAuthTokenError",
				code: "no_account",
			});
		});

		it("refreshes an expired token against the provider token endpoint and persists rotation", async () => {
			const m = mod();
			const account = await link(m);
			clock = T0 + 3600_000 + 1000;
			const endpoint: TokenEndpoint = {
				calls: [],
				respond: () => ({
					status: 200,
					body: {
						access_token: "at-2",
						refresh_token: "rt-2",
						expires_in: 1800,
						token_type: "Bearer",
					},
				}),
			};
			mockTokenEndpoint(endpoint);

			const t = await m.getAccessToken({ userId: "u1", provider: "google" });
			expect(t).toMatchObject({ accessToken: "at-2", refreshed: true });
			expect(t.expiresAt?.getTime()).toBe(clock + 1800_000);
			expect(endpoint.calls).toHaveLength(1);
			expect(endpoint.calls[0]?.url).toBe("https://oauth2.googleapis.com/token");
			const body = endpoint.calls[0]?.body;
			expect(body?.get("grant_type")).toBe("refresh_token");
			expect(body?.get("refresh_token")).toBe("rt-1");
			expect(body?.get("client_id")).toBe("cid");

			const stored = await row(account.id);
			expect(stored?.accessToken).toBe("at-2");
			expect(stored?.refreshToken).toBe("rt-2");
		});

		it("keeps the old refresh token when the provider does not rotate it", async () => {
			const m = mod();
			const account = await link(m);
			clock = T0 + 4000_000;
			mockTokenEndpoint({
				calls: [],
				respond: () => ({
					status: 200,
					body: { access_token: "at-3", expires_in: 100, token_type: "Bearer" },
				}),
			});
			await m.getAccessToken({ userId: "u1", provider: "google" });
			expect((await row(account.id))?.refreshToken).toBe("rt-1");
		});

		it("single-flights concurrent refreshes", async () => {
			const m = mod();
			await link(m);
			clock = T0 + 4000_000;
			const endpoint: TokenEndpoint = {
				calls: [],
				respond: () => ({
					status: 200,
					body: { access_token: "at-sf", refresh_token: "rt-sf", expires_in: 100 },
				}),
			};
			mockTokenEndpoint(endpoint);
			const results = await Promise.all(
				Array.from({ length: 8 }, () => m.getAccessToken({ userId: "u1", provider: "google" })),
			);
			expect(endpoint.calls).toHaveLength(1);
			expect(new Set(results.map((r) => r.accessToken))).toEqual(new Set(["at-sf"]));
		});

		it("throws no_refresh_token when expired without a refresh token", async () => {
			const m = mod();
			await link(m, { refreshToken: undefined });
			clock = T0 + 4000_000;
			await expect(m.getAccessToken({ userId: "u1", provider: "google" })).rejects.toMatchObject({
				code: "no_refresh_token",
			});
		});

		it("maps invalid_grant to revoked and other failures to refresh_failed", async () => {
			const m = mod();
			await link(m);
			clock = T0 + 4000_000;
			mockTokenEndpoint({
				calls: [],
				respond: () => ({ status: 400, body: { error: "invalid_grant" } }),
			});
			await expect(m.getAccessToken({ userId: "u1", provider: "google" })).rejects.toMatchObject({
				code: "revoked",
			});
			vi.restoreAllMocks();
			mockTokenEndpoint({
				calls: [],
				respond: () => ({ status: 503, body: { error: "temporarily_unavailable" } }),
			});
			const err = await m
				.getAccessToken({ userId: "u1", provider: "google" })
				.catch((e: unknown) => e);
			expect(err).toBeInstanceOf(OAuthTokenError);
			expect((err as OAuthTokenError).code).toBe("refresh_failed");
			expect((err as OAuthTokenError).message).not.toContain("rt-1");
		});

		it("reports refresh_failed when the provider cannot refresh", async () => {
			const noRefresh = { ...google, refreshTokens: undefined };
			const m = createOAuthModule(db, { providers: { google: noRefresh }, now: () => clock });
			await link(m);
			clock = T0 + 4000_000;
			await expect(m.getAccessToken({ userId: "u1", provider: "google" })).rejects.toMatchObject({
				code: "refresh_failed",
			});
		});
	});

	describe("encryption at rest", () => {
		const enc = { keys: { k1: KEY }, activeKeyId: "k1" };

		it("fails fast with a clear error when enabled without keys", () => {
			expect(() => createOAuthModule(db, { providers: {}, tokenEncryption: {} })).toThrow(
				/tokenEncryption is enabled but no keys/,
			);
			expect(() =>
				createOAuthModule(db, {
					providers: {},
					tokenEncryption: { keys: { k1: KEY }, activeKeyId: "nope" },
				}),
			).toThrow(/activeKeyId/);
		});

		it("stores sealed tokens, returns plaintext through the API", async () => {
			const m = mod({ tokenEncryption: enc });
			const account = await link(m);
			expect(account.accessToken).toBe("at-1");
			const stored = await row(account.id);
			expect(stored?.accessToken.startsWith("enc:v1.k1.")).toBe(true);
			expect(stored?.accessToken).not.toContain("at-1");
			expect(stored?.refreshToken?.startsWith("enc:v1.k1.")).toBe(true);
			const t = await m.getAccessToken({ userId: "u1", provider: "google" });
			expect(t.accessToken).toBe("at-1");
		});

		it("reads legacy plaintext rows and re-encrypts them on the next write", async () => {
			const plain = mod();
			const account = await link(plain);
			expect((await row(account.id))?.accessToken).toBe("at-1");

			const sealed = mod({ tokenEncryption: enc });
			expect((await sealed.getAccessToken({ userId: "u1", provider: "google" })).accessToken).toBe(
				"at-1",
			);
			// Next write without a new refresh token: the old one is re-encrypted too.
			await sealed.linkAccount(
				"u1",
				"google",
				INFO,
				tokens({ accessToken: "at-9", refreshToken: undefined }),
			);
			const stored = await row(account.id);
			expect(stored?.accessToken.startsWith("enc:v1.k1.")).toBe(true);
			expect(stored?.refreshToken?.startsWith("enc:v1.k1.")).toBe(true);
			expect((await sealed.getAccessToken({ userId: "u1", provider: "google" })).accessToken).toBe(
				"at-9",
			);
		});

		it("rotates to a new active key for new writes and still reads old ones", async () => {
			const first = mod({ tokenEncryption: enc });
			const account = await link(first);
			const rotated = mod({
				tokenEncryption: { keys: { k1: KEY, k2: KEY_B }, activeKeyId: "k2" },
			});
			expect((await rotated.getAccessToken({ userId: "u1", provider: "google" })).accessToken).toBe(
				"at-1",
			);
			clock = T0 + 4000_000;
			mockTokenEndpoint({
				calls: [],
				respond: () => ({ status: 200, body: { access_token: "at-5", expires_in: 60 } }),
			});
			await rotated.getAccessToken({ userId: "u1", provider: "google" });
			expect((await row(account.id))?.accessToken.startsWith("enc:v1.k2.")).toBe(true);
		});

		it("reports decrypt_failed when the key is missing", async () => {
			const sealed = mod({ tokenEncryption: enc });
			await link(sealed);
			const wrong = mod({ tokenEncryption: { keys: { k1: KEY_B }, activeKeyId: "k1" } });
			await expect(
				wrong.getAccessToken({ userId: "u1", provider: "google" }),
			).rejects.toMatchObject({ code: "decrypt_failed" });
			const none = mod();
			await expect(none.getAccessToken({ userId: "u1", provider: "google" })).rejects.toMatchObject(
				{ code: "decrypt_failed" },
			);
		});
	});

	describe("listAccounts and unlinkAccount", () => {
		it("lists accounts without token material", async () => {
			const m = mod();
			await link(m);
			const list = await m.listAccounts("u1");
			expect(list).toHaveLength(1);
			expect(list[0]).toMatchObject({ provider: "google", hasRefreshToken: true });
			expect(JSON.stringify(list)).not.toContain("at-1");
			expect(await m.listAccounts("u2")).toEqual([]);
		});

		it("refuses to unlink the only sign-in method", async () => {
			const m = mod();
			await link(m);
			await expect(m.unlinkAccount("u1", "google")).rejects.toMatchObject({
				code: "last_credential",
			});
			expect(await m.listAccounts("u1")).toHaveLength(1);
		});

		it("unlinks when another oauth account exists", async () => {
			const m = mod();
			await link(m);
			await m.linkAccount("u1", "github", { id: "gh-1", email: undefined, raw: {} }, tokens());
			await m.unlinkAccount("u1", "google");
			expect((await m.listAccounts("u1")).map((a) => a.provider)).toEqual(["github"]);
		});

		it("unlinks when the user has a password or passkey", async () => {
			const m = mod();
			await link(m);
			db.insert(schema.usernameAccounts)
				.values({
					id: "ua1",
					userId: "u1",
					username: "alice",
					passwordHash: "x",
					createdAt: new Date(),
					updatedAt: new Date(),
				})
				.run();
			await m.unlinkAccount("u1", "google");
			expect(await m.listAccounts("u1")).toEqual([]);
		});

		it("honors hasOtherSignInMethod and reports no_account", async () => {
			const m = mod({ hasOtherSignInMethod: async () => true });
			await link(m);
			await m.unlinkAccount("u1", "google");
			await expect(m.unlinkAccount("u1", "google")).rejects.toMatchObject({ code: "no_account" });
		});

		it("does not let one user unlink another user's account", async () => {
			const m = mod({ hasOtherSignInMethod: async () => true });
			await link(m);
			await expect(m.unlinkAccount("u2", "google")).rejects.toMatchObject({ code: "no_account" });
		});
	});
});

describe("OAuth plugin account routes", () => {
	const mockProvider = {
		id: "mock",
		name: "Mock",
		authorizationUrl: "https://mock.example/auth",
		tokenUrl: "https://mock.example/token",
		userInfoUrl: undefined,
		scopes: [],
		async getAuthorizationUrl(state: string) {
			return `https://mock.example/auth?state=${state}`;
		},
		async exchangeCode() {
			return { accessToken: "at", tokenType: "Bearer", raw: {} };
		},
		async getUserInfo() {
			return { id: "m-1", email: "m@example.com", emailVerified: true, raw: {} };
		},
	};

	async function setup() {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			baseUrl: "https://app.example.com",
			auth: { session: { secret: "test-session-secret-that-is-at-least-32-chars!!" } },
			plugins: [oauth({ providers: { mock: mockProvider } })],
		});
		return theauth;
	}

	it("requires an authenticated session", async () => {
		const theauth = await setup();
		const list = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/accounts"),
		);
		expect(list?.status).toBe(401);
		const del = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/accounts/mock", { method: "DELETE" }),
		);
		expect(del?.status).toBe(401);
	});

	it("lists accounts and guards the last credential for a signed-in user", async () => {
		const theauth = await setup();
		const start = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/authorize/mock"),
		);
		const state = new URL(start?.headers.get("location") ?? "").searchParams.get("state");
		const cb = await theauth.plugins.handleRequest(
			new Request(`https://app.example.com/auth/oauth/callback/mock?code=c&state=${state}`),
		);
		const cookie = (cb?.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
		expect(cookie).toContain("theauth_session=");

		const list = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/accounts", { headers: { Cookie: cookie } }),
		);
		expect(list?.status).toBe(200);
		const body = (await list?.json()) as { accounts: Array<{ provider: string }> };
		expect(body.accounts.map((a) => a.provider)).toEqual(["mock"]);
		expect(JSON.stringify(body)).not.toContain('"at"');

		const del = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/accounts/mock", {
				method: "DELETE",
				headers: { Cookie: cookie },
			}),
		);
		expect(del?.status).toBe(409);
		expect(((await del?.json()) as { code: string }).code).toBe("last_credential");
	});
});
