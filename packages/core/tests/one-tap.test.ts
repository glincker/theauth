/**
 * Tests for Google One Tap authentication.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { OneTapModule } from "../src/auth/one-tap.js";
import { createOneTapModule, OneTapVerifyError } from "../src/auth/one-tap.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

// Token-signing helpers

// We bypass the remote JWKS entirely by mocking the jose module at the
// module boundary. The mock replaces `createRemoteJWKSet` with a function
// that returns a local symmetric verifier, and `jwtVerify` delegates to
// the real jose implementation but against that local key.

import { SignJWT } from "jose";

// A static RSA-like symmetric key we use to sign test tokens.
// For speed in tests we use HS256 with a shared secret.
const TEST_SECRET = new TextEncoder().encode("test-google-hmac-secret-for-unit-tests-only-32chars");

const VALID_CLIENT_ID = "test-client-id.apps.googleusercontent.com";
const VALID_ISSUER = "https://accounts.google.com";

async function makeIdToken(overrides: {
	sub?: string;
	email?: string;
	email_verified?: boolean;
	name?: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	aud?: string;
	iss?: string;
	expiresIn?: string;
}): Promise<string> {
	const {
		sub = "google-uid-12345",
		email = "alice@example.com",
		email_verified = true,
		name = "Alice Example",
		given_name = "Alice",
		family_name = "Example",
		picture = "https://example.com/alice.jpg",
		aud = VALID_CLIENT_ID,
		iss = VALID_ISSUER,
		expiresIn = "1h",
	} = overrides;

	const jwt = new SignJWT({
		sub,
		email,
		email_verified,
		name,
		given_name,
		family_name,
		picture,
	})
		.setProtectedHeader({ alg: "HS256" })
		.setAudience(aud)
		.setIssuer(iss)
		.setIssuedAt()
		.setExpirationTime(expiresIn);

	return jwt.sign(TEST_SECRET);
}

// Mock jose's createRemoteJWKSet

// We mock the entire jose module so that createRemoteJWKSet returns a local
// verifier backed by our test secret instead of fetching Google's JWKS.
vi.mock("jose", async (importOriginal) => {
	const original = await importOriginal<typeof import("jose")>();

	return {
		...original,
		createRemoteJWKSet: vi.fn(() => {
			// Return a function that accepts a JWS header and resolves the test
			// key. jose's jwtVerify calls this function internally.
			return async () => {
				return TEST_SECRET;
			};
		}),
	};
});

// Test helpers

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeCallbackRequest(opts: {
	credential: string;
	csrfToken?: string;
	cookieCsrf?: string;
	path?: string;
	method?: string;
}): Request {
	const csrfToken = opts.csrfToken ?? "csrf-abc123";
	const cookieCsrf = opts.cookieCsrf ?? csrfToken;
	const path = opts.path ?? "/auth/one-tap/callback";

	const body = new URLSearchParams({ credential: opts.credential, g_csrf_token: csrfToken });

	return new Request(`https://app.example.com${path}`, {
		method: opts.method ?? "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			cookie: `g_csrf_token=${cookieCsrf}`,
		},
		body: body.toString(),
	});
}

// Suite: verify()

describe("OneTapModule.verify", () => {
	let db: Database;
	let mod: OneTapModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createOneTapModule({ clientId: VALID_CLIENT_ID }, db, sessionManager);
	});

	it("returns GoogleUser for a valid token", async () => {
		const token = await makeIdToken({});
		const user = await mod.verify(token);

		expect(user.sub).toBe("google-uid-12345");
		expect(user.email).toBe("alice@example.com");
		expect(user.emailVerified).toBe(true);
		expect(user.name).toBe("Alice Example");
		expect(user.givenName).toBe("Alice");
		expect(user.familyName).toBe("Example");
		expect(user.picture).toBe("https://example.com/alice.jpg");
	});

	it("rejects a token with wrong audience", async () => {
		const token = await makeIdToken({ aud: "wrong-client.apps.googleusercontent.com" });
		await expect(mod.verify(token)).rejects.toThrow(OneTapVerifyError);
	});

	it("rejects a token with wrong issuer", async () => {
		const token = await makeIdToken({ iss: "https://evil.com" });
		await expect(mod.verify(token)).rejects.toThrow(OneTapVerifyError);
	});

	it("rejects an expired token", async () => {
		const token = await makeIdToken({ expiresIn: "-1s" });
		await expect(mod.verify(token)).rejects.toThrow(OneTapVerifyError);
	});

	it("rejects a token missing the email claim", async () => {
		// Override email to empty string and sign manually so the claim is present
		// but empty — jose won't prevent that at sign time.
		const jwt = new SignJWT({ sub: "uid-123", email: "", email_verified: true, name: "No Mail" })
			.setProtectedHeader({ alg: "HS256" })
			.setAudience(VALID_CLIENT_ID)
			.setIssuer(VALID_ISSUER)
			.setIssuedAt()
			.setExpirationTime("1h");
		const token = await jwt.sign(TEST_SECRET);

		await expect(mod.verify(token)).rejects.toThrow(OneTapVerifyError);
	});

	it("handles short issuer form 'accounts.google.com'", async () => {
		const token = await makeIdToken({ iss: "accounts.google.com" });
		const user = await mod.verify(token);
		expect(user.email).toBe("alice@example.com");
	});

	it("uses email as name fallback when name claim is absent", async () => {
		const jwt = new SignJWT({
			sub: "uid-no-name",
			email: "noname@example.com",
			email_verified: true,
		})
			.setProtectedHeader({ alg: "HS256" })
			.setAudience(VALID_CLIENT_ID)
			.setIssuer(VALID_ISSUER)
			.setIssuedAt()
			.setExpirationTime("1h");
		const token = await jwt.sign(TEST_SECRET);

		const user = await mod.verify(token);
		expect(user.name).toBe("noname@example.com");
	});
});

// Suite: handleRequest() — routing + CSRF

describe("OneTapModule.handleRequest — routing and CSRF", () => {
	let db: Database;
	let mod: OneTapModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createOneTapModule({ clientId: VALID_CLIENT_ID }, db, sessionManager);
	});

	it("returns null for a GET request", async () => {
		// GET requests cannot have a body, so construct without the helper.
		const req = new Request("https://app.example.com/auth/one-tap/callback", {
			method: "GET",
		});
		const result = await mod.handleRequest(req);
		expect(result).toBeNull();
	});

	it("returns null for a POST to the wrong path", async () => {
		const token = await makeIdToken({});
		const req = makeCallbackRequest({ credential: token, path: "/auth/other" });
		const result = await mod.handleRequest(req);
		expect(result).toBeNull();
	});

	it("returns 403 when CSRF cookie is missing", async () => {
		const token = await makeIdToken({});
		const req = new Request("https://app.example.com/auth/one-tap/callback", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			// no cookie
			body: new URLSearchParams({ credential: token, g_csrf_token: "abc" }).toString(),
		});
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(403);
	});

	it("returns 403 when CSRF cookie and body token do not match", async () => {
		const token = await makeIdToken({});
		const req = makeCallbackRequest({
			credential: token,
			csrfToken: "body-token",
			cookieCsrf: "cookie-token",
		});
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(403);
	});

	it("returns 400 when credential field is missing", async () => {
		const body = new URLSearchParams({ g_csrf_token: "csrf-abc" });
		const req = new Request("https://app.example.com/auth/one-tap/callback", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				cookie: "g_csrf_token=csrf-abc",
			},
			body: body.toString(),
		});
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(400);
	});

	it("returns 401 for an invalid/expired token", async () => {
		const expiredToken = await makeIdToken({ expiresIn: "-1s" });
		const req = makeCallbackRequest({ credential: expiredToken });
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(401);
	});

	it("returns 401 for a malformed token string", async () => {
		const req = makeCallbackRequest({ credential: "not.a.jwt" });
		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(401);
	});
});

// Suite: handleRequest() — user flows

describe("OneTapModule.handleRequest — user flows", () => {
	let db: Database;
	let mod: OneTapModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createOneTapModule({ clientId: VALID_CLIENT_ID }, db, sessionManager);
	});

	it("auto-creates a new user and returns session on first sign-in", async () => {
		const token = await makeIdToken({ email: "newuser@example.com", sub: "google-new-111" });
		const req = makeCallbackRequest({ credential: token });

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(200);

		const body = (await response?.json()) as {
			user: { id: string; email: string };
			session: { token: string; expiresAt: string };
		};
		expect(body.user.email).toBe("newuser@example.com");
		expect(body.session.token).toBeTruthy();
		expect(body.session.expiresAt).toBeTruthy();

		// Verify user was persisted.
		const rows = await db.select().from(users).all();
		expect(rows.some((u) => u.email === "newuser@example.com")).toBe(true);
		const created = rows.find((u) => u.email === "newuser@example.com");
		expect(created?.externalId).toBe("google-new-111");
		expect(created?.externalProvider).toBe("google");
	});

	it("signs in an existing user without duplicating them", async () => {
		// Pre-create the user.
		const existingId = "existing-user-uuid";
		const now = new Date();
		await db.insert(users).values({
			id: existingId,
			email: "existing@example.com",
			name: "Existing User",
			createdAt: now,
			updatedAt: now,
		});

		const token = await makeIdToken({ email: "existing@example.com", sub: "google-existing-222" });
		const req = makeCallbackRequest({ credential: token });

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(200);

		const body = (await response?.json()) as {
			user: { id: string; email: string };
			session: { token: string };
		};
		expect(body.user.id).toBe(existingId);
		expect(body.user.email).toBe("existing@example.com");

		// Only one user record.
		const rows = await db.select().from(users).all();
		expect(rows.filter((u) => u.email === "existing@example.com")).toHaveLength(1);
	});

	it("returns 403 when autoCreateUser is false and user does not exist", async () => {
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const strictMod = createOneTapModule(
			{ clientId: VALID_CLIENT_ID, autoCreateUser: false },
			db,
			sessionManager,
		);

		const token = await makeIdToken({ email: "unknown@example.com" });
		const req = makeCallbackRequest({ credential: token });

		const response = await strictMod.handleRequest(req);
		expect(response?.status).toBe(403);
	});

	it("allows sign-in when autoCreateUser is false and user already exists", async () => {
		const now = new Date();
		await db.insert(users).values({
			id: "pre-existing-id",
			email: "known@example.com",
			name: "Known User",
			createdAt: now,
			updatedAt: now,
		});

		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const strictMod = createOneTapModule(
			{ clientId: VALID_CLIENT_ID, autoCreateUser: false },
			db,
			sessionManager,
		);

		const token = await makeIdToken({ email: "known@example.com" });
		const req = makeCallbackRequest({ credential: token });

		const response = await strictMod.handleRequest(req);
		expect(response?.status).toBe(200);
	});

	it("respects a custom CSRF cookie name", async () => {
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const customMod = createOneTapModule(
			{ clientId: VALID_CLIENT_ID, csrfCookieName: "my_csrf" },
			db,
			sessionManager,
		);

		const token = await makeIdToken({ email: "csrf@example.com" });

		// Use custom cookie name.
		const body = new URLSearchParams({ credential: token, my_csrf: "abc123" });
		const req = new Request("https://app.example.com/auth/one-tap/callback", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				cookie: "my_csrf=abc123",
			},
			body: body.toString(),
		});

		const response = await customMod.handleRequest(req);
		expect(response?.status).toBe(200);
	});
});
