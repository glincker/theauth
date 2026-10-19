/**
 * The session store against the real core handler, with no browser and no mocked routes:
 * sign up, verify, sign in, read the session, sign out, then forgot and reset password.
 */
import { describe, expect, it } from "vitest";
import { createTheAuthHandler } from "../../core/src/http/index.js";
import { createTheAuth } from "../../core/src/theauth.js";
import type { SessionStorageLike } from "../src/index.js";
import { createSessionStore, EMAIL_PASSWORD_ROUTES } from "../src/index.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

function memoryStorage(): SessionStorageLike {
	const m = new Map<string, string>();
	return {
		getItem: (k) => m.get(k) ?? null,
		setItem: (k, v) => void m.set(k, v),
		removeItem: (k) => void m.delete(k),
	};
}

async function server() {
	const verifications: string[] = [];
	const resets: string[] = [];
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		auth: { session: { secret: SECRET } },
		emailVerification: {
			sendVerificationEmail: async (_email, token) => {
				verifications.push(token);
			},
			verifyUrl: "https://app.example.com/verify",
		},
		passwordReset: {
			sendResetEmail: async (_email, token) => {
				resets.push(token);
			},
			resetUrl: "https://app.example.com/reset",
		},
		emailPassword: {},
	});
	const handler = createTheAuthHandler(theauth, { basePath: "/api/theauth" });
	const calls: string[] = [];
	const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(String(input), "http://localhost");
		calls.push(`${init?.method ?? "GET"} ${url.pathname}`);
		return handler(new Request(url, init));
	}) as typeof fetch;
	return { fetch: fetchImpl, verifications, resets, calls };
}

const PASSWORD = "correct horse battery";

describe("session store with the emailPassword preset", () => {
	it("exposes the routes of the core module", () => {
		expect(EMAIL_PASSWORD_ROUTES).toEqual({
			signInPath: "/auth/email/sign-in",
			signUpPath: "/auth/email/sign-up",
			identifierField: "email",
		});
	});

	it("runs sign up, verify, sign in, session read and sign out against a real handler", async () => {
		const s = await server();
		const storage = memoryStorage();
		const store = createSessionStore({ emailPassword: true, fetch: s.fetch, storage });

		const up = await store.signUp("ada@example.com", PASSWORD, "Ada");
		expect(up).toEqual({ success: true, verificationRequired: true });
		expect(store.getState().session).toBeNull();
		expect(s.verifications).toHaveLength(1);

		const early = await store.signIn("ada@example.com", PASSWORD);
		expect(early).toMatchObject({ success: false, code: "EMAIL_NOT_VERIFIED" });
		expect(store.getState().session).toBeNull();

		expect(await store.verifyEmail(s.verifications[0] ?? "")).toEqual({ success: true });
		expect(await store.verifyEmail(s.verifications[0] ?? "")).toMatchObject({ success: false });

		expect(await store.signIn("ada@example.com", "wrong password!")).toMatchObject({
			success: false,
			code: "INVALID_CREDENTIALS",
		});
		expect(await store.signIn("ada@example.com", PASSWORD)).toEqual({ success: true });
		const signedIn = store.getState().session;
		expect(signedIn?.user).toMatchObject({ email: "ada@example.com", name: "Ada" });
		expect(signedIn?.token).toBeTruthy();

		// A fresh store with the same storage reads the session from the server.
		const reopened = createSessionStore({ emailPassword: true, fetch: s.fetch, storage });
		await reopened.refresh();
		expect(reopened.getState().session?.user.email).toBe("ada@example.com");

		expect(await store.signOut()).toEqual({ success: true });
		expect(store.getState().session).toBeNull();
		await reopened.refresh();
		expect(reopened.getState().session).toBeNull();

		expect(s.calls).toContain("POST /api/theauth/auth/email/sign-up");
		expect(s.calls).toContain("POST /api/theauth/auth/email/sign-in");
		expect(s.calls).toContain("POST /api/theauth/auth/sign-out");
	});

	it("resends verification and resets a forgotten password", async () => {
		const s = await server();
		const store = createSessionStore({ emailPassword: true, fetch: s.fetch });
		await store.signUp("ada@example.com", PASSWORD);

		expect(await store.resendVerification("ada@example.com")).toEqual({ success: true });
		expect(await store.resendVerification("nobody@example.com")).toEqual({ success: true });
		expect(s.verifications).toHaveLength(2);

		expect(await store.requestPasswordReset("ada@example.com")).toEqual({ success: true });
		expect(await store.requestPasswordReset("nobody@example.com")).toEqual({ success: true });
		expect(s.resets).toHaveLength(1);
		expect(await store.resetPassword(s.resets[0] ?? "", "a brand new password")).toEqual({
			success: true,
		});
		expect(await store.signIn("ada@example.com", "a brand new password")).toEqual({
			success: true,
		});
	});

	it("keeps the username routes as the default", async () => {
		const calls: string[] = [];
		const store = createSessionStore({
			fetch: (async (input: RequestInfo | URL) => {
				calls.push(String(input));
				return new Response("{}", { status: 400 });
			}) as typeof fetch,
		});
		await store.signIn("a", "b");
		expect(calls[0]).toBe("/api/theauth/auth/username/sign-in");
	});

	it("lets explicit paths win over the preset", async () => {
		const calls: string[] = [];
		const store = createSessionStore({
			emailPassword: true,
			signInPath: "/custom/in",
			fetch: (async (input: RequestInfo | URL) => {
				calls.push(String(input));
				return new Response("{}", { status: 400 });
			}) as typeof fetch,
		});
		await store.signIn("a@b.co", "b");
		expect(calls[0]).toBe("/api/theauth/custom/in");
	});
});

describe("session store on a runtime like Lynx's PrimJS", () => {
	it("works with fetch only: no AbortController, window, localStorage or TextEncoder", async () => {
		const s = await server();
		const names = ["AbortController", "window", "localStorage", "TextEncoder", "TextDecoder"];
		const g = globalThis as unknown as Record<string, unknown>;
		const saved = names.map((n) => [n, g[n]] as const);
		const strip = () => {
			for (const n of names) Reflect.deleteProperty(g, n);
		};
		const restore = () => {
			for (const [n, v] of saved) if (v !== undefined) g[n] = v;
		};
		// The server runs in this process, so give it the full runtime for each request. The
		// store itself only ever sees the stripped one.
		const serverFetch = (async (...args: Parameters<typeof fetch>) => {
			restore();
			try {
				return await s.fetch(...args);
			} finally {
				strip();
			}
		}) as typeof fetch;
		strip();
		try {
			const store = createSessionStore({
				emailPassword: true,
				basePath: "http://localhost/api/theauth",
				fetch: serverFetch,
			});
			await store.signUp("ada@example.com", PASSWORD);
			await store.verifyEmail(s.verifications[0] ?? "");
			expect(await store.signIn("ada@example.com", PASSWORD)).toEqual({ success: true });
			await store.refresh();
			expect(store.getState().session?.user.email).toBe("ada@example.com");
			// Persistence is the host's job here: hand the session back through hydrateSession.
			const token = store.getState().session?.token;
			const next = createSessionStore({
				emailPassword: true,
				basePath: "http://localhost/api/theauth",
				fetch: serverFetch,
			});
			next.hydrateSession({ token, user: { id: store.getState().session?.user.id ?? "" } });
			await next.refresh();
			expect(next.getState().session?.user.email).toBe("ada@example.com");
			expect(await store.signOut()).toEqual({ success: true });
		} finally {
			restore();
		}
	});
});
