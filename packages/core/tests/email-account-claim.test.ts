/** Pre-hijacking tests: one-tap links by email, magic link and email OTP claim a squatted account. */

import { eq } from "drizzle-orm";
import { SignJWT } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createEmailOtpModule } from "../src/auth/email-otp.js";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import { oauthAccounts } from "../src/auth/oauth/schema.js";
import { createOneTapModule } from "../src/auth/one-tap.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { sessions, usernameAccounts, users } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

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

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const APP_URL = "https://app.example.com";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

/** An account an attacker registered with the victim's address, before any mailbox proof. */
async function seedSquat(db: Database, emailVerified: 0 | 1 = 0): Promise<void> {
	const now = new Date();
	await db.insert(users).values({
		id: "squat",
		email: "victim@example.com",
		emailVerified,
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(usernameAccounts).values({
		id: "ua-1",
		userId: "squat",
		username: "attacker",
		passwordHash: "pbkdf2$stub",
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(oauthAccounts).values({
		id: "oa-1",
		userId: "squat",
		provider: "weak",
		providerAccountId: "attacker-acct",
		accessToken: "t",
		createdAt: now,
		updatedAt: now,
	});
}

function oneTapRequest(credential: string): Request {
	const body = new URLSearchParams({ credential, g_csrf_token: "c" });
	return new Request(`${APP_URL}/auth/one-tap/callback`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", cookie: "g_csrf_token=c" },
		body: body.toString(),
	});
}

describe("one-tap linking by email", () => {
	let db: Database;
	beforeEach(async () => {
		db = await createTestDb();
	});

	function mod(extra: { unsafeAllowUnverifiedEmailLinking?: boolean } = {}) {
		const sm = createSessionManager({ secret: SESSION_SECRET }, db);
		return createOneTapModule({ clientId: VALID_CLIENT_ID, ...extra }, db, sm);
	}

	it("refuses to sign in to an unverified local account", async () => {
		await seedSquat(db, 0);
		const res = await mod().handleRequest(
			oneTapRequest(await makeIdToken({ email: "victim@example.com", email_verified: true })),
		);
		expect(res?.status).toBe(409);
		expect(await db.select().from(sessions)).toHaveLength(0);
	});

	it("refuses when Google does not vouch for the address", async () => {
		await seedSquat(db, 1);
		const res = await mod().handleRequest(
			oneTapRequest(await makeIdToken({ email: "victim@example.com", email_verified: false })),
		);
		expect(res?.status).toBe(409);
	});

	it("signs in when both sides are verified", async () => {
		await seedSquat(db, 1);
		const res = await mod().handleRequest(
			oneTapRequest(await makeIdToken({ email: "victim@example.com", email_verified: true })),
		);
		expect(res?.status).toBe(200);
	});

	it("matches the stored address case-insensitively", async () => {
		await seedSquat(db, 1);
		const res = await mod().handleRequest(
			oneTapRequest(await makeIdToken({ email: "Victim@Example.com", email_verified: true })),
		);
		expect(res?.status).toBe(200);
		expect(await db.select().from(users)).toHaveLength(1);
	});

	it("stores a new user as verified only when Google says so", async () => {
		await mod().handleRequest(
			oneTapRequest(await makeIdToken({ email: "new@example.com", email_verified: false })),
		);
		const row = (await db.select().from(users).where(eq(users.email, "new@example.com")))[0];
		expect(row?.emailVerified).toBe(0);
	});

	it("stores a new user as verified when Google vouches for the address", async () => {
		await mod().handleRequest(
			oneTapRequest(await makeIdToken({ email: "new2@example.com", email_verified: true })),
		);
		const row = (await db.select().from(users).where(eq(users.email, "new2@example.com")))[0];
		expect(row?.emailVerified).toBe(1);
	});

	it("keeps the old behavior behind unsafeAllowUnverifiedEmailLinking", async () => {
		await seedSquat(db, 0);
		const res = await mod({ unsafeAllowUnverifiedEmailLinking: true }).handleRequest(
			oneTapRequest(await makeIdToken({ email: "victim@example.com", email_verified: false })),
		);
		expect(res?.status).toBe(200);
	});
});

describe("magic link on a pre-registered unverified account", () => {
	let db: Database;
	beforeEach(async () => {
		db = await createTestDb();
	});

	async function redeem(config: { keepUnverifiedCredentials?: boolean } = {}) {
		const sm = createSessionManager({ secret: SESSION_SECRET }, db);
		let sent = "";
		const m = createMagicLinkModule(
			{
				appUrl: APP_URL,
				sendMagicLink: async (_e: string, token: string) => {
					sent = token;
				},
				...config,
			},
			db,
			sm,
		);
		await m.sendLink("victim@example.com");
		return m.verify(sent);
	}

	it("marks the address verified and drops credentials the squatter planted", async () => {
		await seedSquat(db, 0);
		await db.insert(sessions).values({
			id: "old-session",
			userId: "squat",
			expiresAt: new Date(Date.now() + 3600_000),
			createdAt: new Date(),
		} as typeof sessions.$inferInsert);
		const result = await redeem();
		expect(result?.user.id).toBe("squat");
		const row = (await db.select().from(users).where(eq(users.id, "squat")))[0];
		expect(row?.emailVerified).toBe(1);
		expect(await db.select().from(usernameAccounts)).toHaveLength(0);
		expect(await db.select().from(oauthAccounts)).toHaveLength(0);
		const left = await db.select().from(sessions).where(eq(sessions.userId, "squat"));
		expect(left.map((s) => s.id)).not.toContain("old-session");
	});

	it("leaves a verified account alone", async () => {
		await seedSquat(db, 1);
		await redeem();
		expect(await db.select().from(usernameAccounts)).toHaveLength(1);
	});

	it("keeps credentials behind keepUnverifiedCredentials", async () => {
		await seedSquat(db, 0);
		await redeem({ keepUnverifiedCredentials: true });
		expect(await db.select().from(usernameAccounts)).toHaveLength(1);
	});

	it("marks a freshly created account verified", async () => {
		await redeem();
		const row = (await db.select().from(users))[0];
		expect(row?.emailVerified).toBe(1);
	});
});

describe("email OTP on a pre-registered unverified account", () => {
	let db: Database;
	beforeEach(async () => {
		db = await createTestDb();
	});

	async function redeem(config: { keepUnverifiedCredentials?: boolean } = {}) {
		const sm = createSessionManager({ secret: SESSION_SECRET }, db);
		let code = "";
		const m = createEmailOtpModule(
			{
				sendOtp: async (_e: string, c: string) => {
					code = c;
				},
				...config,
			},
			db,
			sm,
		);
		await m.sendCode("victim@example.com");
		return m.verifyCode("victim@example.com", code);
	}

	it("marks the address verified and drops credentials the squatter planted", async () => {
		await seedSquat(db, 0);
		const result = await redeem();
		expect(result?.user.id).toBe("squat");
		const row = (await db.select().from(users).where(eq(users.id, "squat")))[0];
		expect(row?.emailVerified).toBe(1);
		expect(await db.select().from(usernameAccounts)).toHaveLength(0);
		expect(await db.select().from(oauthAccounts)).toHaveLength(0);
	});

	it("keeps credentials behind keepUnverifiedCredentials", async () => {
		await seedSquat(db, 0);
		await redeem({ keepUnverifiedCredentials: true });
		expect(await db.select().from(usernameAccounts)).toHaveLength(1);
	});
});
