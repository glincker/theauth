/** The optional `rememberMe` choice reaches the session and the cookie on the username, magic link and OAuth sign in paths. Absent, nothing changes. */

import { describe, expect, it } from "vitest";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import { oauth } from "../src/auth/oauth/plugin.js";
import type { OAuthProvider } from "../src/auth/oauth/types.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import { buildSessionSetCookie, parseRememberMe } from "../src/plugin/helpers.js";
import { createSessionManager } from "../src/session/session.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const DAY_MS = 86_400_000;

async function freshDb() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

const lifetimeDays = (expiresAt: Date) => Math.round((expiresAt.getTime() - Date.now()) / DAY_MS);

describe("parseRememberMe and buildSessionSetCookie", () => {
	it("only accepts booleans and the strings true or false", () => {
		expect(parseRememberMe(true)).toBe(true);
		expect(parseRememberMe("false")).toBe(false);
		for (const v of [undefined, null, "1", "yes", 0, {}])
			expect(parseRememberMe(v)).toBeUndefined();
	});

	it("false is a session cookie, true and unset are persistent", () => {
		const expiresAt = new Date(Date.now() + 5 * DAY_MS);
		const session = (rememberMe?: boolean) => ({
			expiresAt,
			...(rememberMe !== undefined && { rememberMe }),
		});
		const off = buildSessionSetCookie("s", "t", session(false), true);
		expect(off).not.toMatch(/Max-Age/i);
		expect(off).not.toMatch(/Expires/i);
		expect(off).toMatch(/HttpOnly/i);
		expect(off).toMatch(/Secure/i);
		for (const choice of [true, undefined]) {
			const maxAge = Number(
				/Max-Age=(\d+)/i.exec(buildSessionSetCookie("s", "t", session(choice), true))?.[1],
			);
			expect(maxAge).toBeGreaterThan(5 * 86_400 - 5);
			expect(maxAge).toBeLessThanOrEqual(5 * 86_400);
		}
	});
});

describe("username sign in", () => {
	async function boot(session: Record<string, unknown> = {}) {
		const db = await freshDb();
		const sessions = createSessionManager({ secret: SECRET, ...session }, db);
		const mod = createUsernameAuthModule({}, db, sessions);
		await mod.signUp({ username: "alice", password: "Password1!" });
		return mod;
	}

	it("rememberMe true uses the long lifetime, capped", async () => {
		const mod = await boot({ rememberMeMaxAge: 400 * 86_400, rememberMeMaxAgeCap: 60 * 86_400 });
		const out = await mod.signIn({ username: "alice", password: "Password1!", rememberMe: true });
		expect(out.session.rememberMe).toBe(true);
		expect(lifetimeDays(out.session.expiresAt)).toBe(60);
	});

	it("rememberMe false keeps the normal lifetime and says so", async () => {
		const mod = await boot();
		const out = await mod.signIn({ username: "alice", password: "Password1!", rememberMe: false });
		expect(out.session.rememberMe).toBe(false);
		expect(lifetimeDays(out.session.expiresAt)).toBe(7);
	});

	it("absent leaves the default unchanged", async () => {
		const mod = await boot();
		const out = await mod.signIn({ username: "alice", password: "Password1!" });
		expect(out.session.rememberMe).toBeUndefined();
		expect(lifetimeDays(out.session.expiresAt)).toBe(7);
	});

	it("reads rememberMe from the HTTP body", async () => {
		const mod = await boot();
		const res = await mod.handleRequest(
			new Request("https://app.example.com/auth/username/sign-in", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ username: "alice", password: "Password1!", rememberMe: false }),
			}),
		);
		const body = (await res?.json()) as { session: { rememberMe?: boolean } };
		expect(body.session.rememberMe).toBe(false);
	});
});

describe("magic link verify", () => {
	it("passes rememberMe through the query string and the module option", async () => {
		const db = await freshDb();
		const sessions = createSessionManager({ secret: SECRET }, db);
		const sent: string[] = [];
		const mod = createMagicLinkModule(
			{
				appUrl: "https://app.example.com",
				sendMagicLink: async (_e, token) => void sent.push(token),
			},
			db,
			sessions,
		);
		await mod.sendLink("a@example.com");
		await mod.sendLink("b@example.com");
		await mod.sendLink("c@example.com");
		const off = await mod.verify(sent[0] ?? "", { rememberMe: false });
		expect(off?.session.rememberMe).toBe(false);
		const viaHttp = await mod.handleRequest(
			new Request(
				`https://app.example.com/auth/magic-link/verify?token=${sent[1]}&rememberMe=true`,
			),
		);
		const body = (await viaHttp?.json()) as { session: { rememberMe?: boolean } };
		expect(body.session.rememberMe).toBe(true);
		const unset = await mod.verify(sent[2] ?? "");
		expect(unset?.session.rememberMe).toBeUndefined();
	});
});

describe("OAuth callback cookie", () => {
	const provider: OAuthProvider = {
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
			return { id: "p1", email: "member@example.com", emailVerified: true, name: "M", raw: {} };
		},
	};

	async function signIn(query: string): Promise<string> {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			baseUrl: "https://app.example.com",
			auth: { session: { secret: SECRET } },
			plugins: [oauth({ providers: { mock: provider } })],
		});
		await theauth.db.insert(users).values({
			id: "member",
			email: "member@example.com",
			emailVerified: 1,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const start = await theauth.plugins.handleRequest(
			new Request(`https://app.example.com/auth/oauth/authorize/mock${query}`),
		);
		const state = new URL(start?.headers.get("location") ?? "").searchParams.get("state");
		const carried = (start?.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ");
		const res = await theauth.plugins.handleRequest(
			new Request(`https://app.example.com/auth/oauth/callback/mock?code=c&state=${state}`, {
				headers: carried ? { cookie: carried } : {},
			}),
		);
		return (
			res?.headers.getSetCookie().find((c) => c.startsWith("theauth_session=")) ??
			"missing session cookie"
		);
	}

	it("?rememberMe=false gives a browser session cookie", async () => {
		const cookie = await signIn("?rememberMe=false");
		expect(cookie).toMatch(/^theauth_session=/);
		expect(cookie).not.toMatch(/Max-Age/i);
	});

	it("?rememberMe=true and no choice give a persistent cookie", async () => {
		for (const query of ["?rememberMe=true", ""]) {
			expect(await signIn(query)).toMatch(/Max-Age=\d+/i);
		}
	});
});
