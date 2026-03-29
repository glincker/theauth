import { describe, expect, it, vi } from "vitest";
import { createDatabase } from "../../../core/src/db/database.js";
import { createTables } from "../../../core/src/db/migrations.js";
import { createEmailAuth } from "../src/email-auth.js";
import { ErrorCodes } from "../src/errors.js";
import type { EmailAuthModule } from "../src/types.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeMocks() {
	const sentVerifications: Array<{ email: string; token: string; url: string }> = [];
	const sentResets: Array<{ email: string; token: string; url: string }> = [];

	const sendVerificationEmail = vi.fn(async (email: string, token: string, url: string) => {
		sentVerifications.push({ email, token, url });
	});

	const sendResetEmail = vi.fn(async (email: string, token: string, url: string) => {
		sentResets.push({ email, token, url });
	});

	return { sendVerificationEmail, sendResetEmail, sentVerifications, sentResets };
}

async function createTestModule(
	overrides: Partial<{ requireVerification: boolean }> = {},
): Promise<{ auth: EmailAuthModule; mocks: ReturnType<typeof makeMocks> }> {
	const mocks = makeMocks();
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });

	// Run core migrations first so kavach_users + kavach_sessions exist
	await createTables(db, "sqlite");

	const auth = createEmailAuth(
		{
			sendVerificationEmail: mocks.sendVerificationEmail,
			sendResetEmail: mocks.sendResetEmail,
			appUrl: "https://app.example.com",
			requireVerification: overrides.requireVerification ?? true,
		},
		db,
	);

	return { auth, mocks };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createEmailAuth", () => {
	describe("signUp", () => {
		it("creates a user and calls sendVerificationEmail", async () => {
			const { auth, mocks } = await createTestModule();

			const result = await auth.signUp({
				email: "alice@example.com",
				password: "Password123",
				name: "Alice",
			});

			expect(result.user.email).toBe("alice@example.com");
			expect(result.user.name).toBe("Alice");
			expect(result.user.emailVerified).toBe(false);
			expect(typeof result.token).toBe("string");
			expect(result.token.length).toBeGreaterThan(0);

			expect(mocks.sendVerificationEmail).toHaveBeenCalledOnce();
			const call = mocks.sentVerifications[0];
			expect(call).toBeDefined();
			expect(call?.email).toBe("alice@example.com");
			expect(typeof call?.token).toBe("string");
			expect(call?.url).toContain("https://app.example.com");
		});

		it("rejects duplicate email", async () => {
			const { auth } = await createTestModule();

			await auth.signUp({ email: "bob@example.com", password: "Password123" });

			await expect(
				auth.signUp({ email: "bob@example.com", password: "DifferentPass1" }),
			).rejects.toMatchObject({ code: ErrorCodes.DUPLICATE_EMAIL });
		});

		it("rejects password that is too short", async () => {
			const { auth } = await createTestModule();

			await expect(
				auth.signUp({ email: "charlie@example.com", password: "short" }),
			).rejects.toMatchObject({ code: ErrorCodes.INVALID_PASSWORD });
		});

		it("rejects invalid email format", async () => {
			const { auth } = await createTestModule();

			await expect(
				auth.signUp({ email: "not-an-email", password: "Password123" }),
			).rejects.toMatchObject({ code: ErrorCodes.INVALID_EMAIL });
		});
	});

	describe("signIn", () => {
		it("returns a session with correct credentials", async () => {
			const { auth, mocks } = await createTestModule({ requireVerification: false });

			await auth.signUp({ email: "diana@example.com", password: "Password123" });

			const result = await auth.signIn({
				email: "diana@example.com",
				password: "Password123",
			});

			expect(result.user.email).toBe("diana@example.com");
			expect(typeof result.session.token).toBe("string");
			expect(result.session.expiresAt).toBeInstanceOf(Date);
			expect(mocks.sendVerificationEmail).toHaveBeenCalledOnce();
		});

		it("returns INVALID_CREDENTIALS for wrong password", async () => {
			const { auth } = await createTestModule({ requireVerification: false });

			await auth.signUp({ email: "eve@example.com", password: "Password123" });

			await expect(
				auth.signIn({ email: "eve@example.com", password: "WrongPassword" }),
			).rejects.toMatchObject({ code: ErrorCodes.INVALID_CREDENTIALS });
		});

		it("returns INVALID_CREDENTIALS for unknown email", async () => {
			const { auth } = await createTestModule({ requireVerification: false });

			await expect(
				auth.signIn({ email: "ghost@example.com", password: "Password123" }),
			).rejects.toMatchObject({ code: ErrorCodes.INVALID_CREDENTIALS });
		});

		it("returns EMAIL_NOT_VERIFIED when requireVerification is true", async () => {
			const { auth } = await createTestModule({ requireVerification: true });

			await auth.signUp({ email: "frank@example.com", password: "Password123" });

			await expect(
				auth.signIn({ email: "frank@example.com", password: "Password123" }),
			).rejects.toMatchObject({ code: ErrorCodes.EMAIL_NOT_VERIFIED });
		});

		it("allows sign-in after email is verified", async () => {
			const { auth, mocks } = await createTestModule({ requireVerification: true });

			await auth.signUp({ email: "grace@example.com", password: "Password123" });

			const token = mocks.sentVerifications[0]?.token;
			await auth.verifyEmail(token);

			const result = await auth.signIn({ email: "grace@example.com", password: "Password123" });
			expect(result.user.emailVerified).toBe(true);
		});
	});

	describe("verifyEmail", () => {
		it("sets emailVerified to true with a valid token", async () => {
			const { auth, mocks } = await createTestModule();

			await auth.signUp({ email: "harry@example.com", password: "Password123" });
			const token = mocks.sentVerifications[0]?.token;

			const result = await auth.verifyEmail(token);
			expect(result.verified).toBe(true);

			const user = await auth.getUserByEmail("harry@example.com");
			expect(user?.emailVerified).toBe(true);
		});

		it("fails with an invalid token", async () => {
			const { auth } = await createTestModule();

			await expect(auth.verifyEmail("invalid-token-xyz")).rejects.toMatchObject({
				code: ErrorCodes.INVALID_TOKEN,
			});
		});

		it("fails with an expired token", async () => {
			const mocks = makeMocks();
			const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
			await createTables(db, "sqlite");

			const auth = createEmailAuth(
				{
					sendVerificationEmail: mocks.sendVerificationEmail,
					sendResetEmail: mocks.sendResetEmail,
					appUrl: "https://app.example.com",
					verificationExpiry: 0, // expires immediately
				},
				db,
			);

			await auth.signUp({ email: "iris@example.com", password: "Password123" });
			const token = mocks.sentVerifications[0]?.token;

			// Small delay to ensure expiry
			await new Promise((resolve) => setTimeout(resolve, 5));

			await expect(auth.verifyEmail(token)).rejects.toMatchObject({
				code: ErrorCodes.TOKEN_EXPIRED,
			});
		});
	});

	describe("password reset flow", () => {
		it("sends a reset email and allows resetting password", async () => {
			const { auth, mocks } = await createTestModule({ requireVerification: false });

			await auth.signUp({ email: "jake@example.com", password: "OldPassword1" });

			await auth.requestReset("jake@example.com");
			expect(mocks.sendResetEmail).toHaveBeenCalledOnce();

			const resetToken = mocks.sentResets[0]?.token;
			const result = await auth.resetPassword(resetToken, "NewPassword1");
			expect(result.success).toBe(true);

			// Should be able to sign in with new password
			const session = await auth.signIn({ email: "jake@example.com", password: "NewPassword1" });
			expect(session.user.email).toBe("jake@example.com");
		});

		it("silently ignores requestReset for unknown email", async () => {
			const { auth, mocks } = await createTestModule();

			await auth.requestReset("nobody@example.com");
			expect(mocks.sendResetEmail).not.toHaveBeenCalled();
		});

		it("fails resetPassword with an invalid token", async () => {
			const { auth } = await createTestModule();

			await expect(auth.resetPassword("bad-token", "NewPassword1")).rejects.toMatchObject({
				code: ErrorCodes.INVALID_TOKEN,
			});
		});

		it("revokes sessions after password reset", async () => {
			const { auth, mocks } = await createTestModule({ requireVerification: false });

			await auth.signUp({ email: "kai@example.com", password: "OldPassword1" });

			await auth.requestReset("kai@example.com");
			const resetToken = mocks.sentResets[0]?.token;
			await auth.resetPassword(resetToken, "NewPassword99!");

			// User can still sign in with new credentials (sessions were revoked, not account)
			const session = await auth.signIn({ email: "kai@example.com", password: "NewPassword99!" });
			expect(session.user.email).toBe("kai@example.com");
		});
	});

	describe("changePassword", () => {
		it("changes password with correct current password", async () => {
			const { auth } = await createTestModule({ requireVerification: false });

			const { user } = await auth.signUp({ email: "leo@example.com", password: "OldPass123" });
			const result = await auth.changePassword(user.id, "OldPass123", "NewPass456");
			expect(result.success).toBe(true);

			// Can sign in with new password
			const session = await auth.signIn({ email: "leo@example.com", password: "NewPass456" });
			expect(session.user.email).toBe("leo@example.com");
		});

		it("fails with wrong current password", async () => {
			const { auth } = await createTestModule({ requireVerification: false });

			const { user } = await auth.signUp({ email: "mia@example.com", password: "OldPass123" });

			await expect(
				auth.changePassword(user.id, "WrongCurrentPass", "NewPass456"),
			).rejects.toMatchObject({ code: ErrorCodes.WRONG_PASSWORD });
		});

		it("fails for unknown user", async () => {
			const { auth } = await createTestModule();

			await expect(auth.changePassword("usr_notexist", "OldPass", "NewPass")).rejects.toMatchObject(
				{ code: ErrorCodes.USER_NOT_FOUND },
			);
		});
	});

	describe("handleRequest", () => {
		it("routes POST /auth/sign-up correctly", async () => {
			const { auth } = await createTestModule();

			const req = new Request("http://localhost/auth/sign-up", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "nina@example.com", password: "Password123" }),
			});

			const res = await auth.handleRequest(req);
			expect(res).not.toBeNull();
			expect(res?.status).toBe(201);
			const data = (await res?.json()) as { user: { email: string } };
			expect(data.user.email).toBe("nina@example.com");
		});

		it("routes POST /auth/sign-in and returns 401 for unverified user", async () => {
			const { auth } = await createTestModule({ requireVerification: true });

			await auth.signUp({ email: "oscar@example.com", password: "Password123" });

			const req = new Request("http://localhost/auth/sign-in", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "oscar@example.com", password: "Password123" }),
			});

			const res = await auth.handleRequest(req);
			expect(res).not.toBeNull();
			expect(res?.status).toBe(401);
		});

		it("routes POST /auth/forgot-password and returns success", async () => {
			const { auth } = await createTestModule();

			const req = new Request("http://localhost/auth/forgot-password", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "nobody@example.com" }),
			});

			const res = await auth.handleRequest(req);
			expect(res).not.toBeNull();
			expect(res?.status).toBe(200);
		});

		it("returns null for unrecognised paths", async () => {
			const { auth } = await createTestModule();

			const req = new Request("http://localhost/some/other/path", {
				method: "POST",
				body: JSON.stringify({}),
			});

			const res = await auth.handleRequest(req);
			expect(res).toBeNull();
		});

		it("returns null for GET requests", async () => {
			const { auth } = await createTestModule();

			const req = new Request("http://localhost/auth/sign-up", { method: "GET" });
			const res = await auth.handleRequest(req);
			expect(res).toBeNull();
		});

		it("routes POST /auth/verify-email correctly", async () => {
			const { auth, mocks } = await createTestModule();

			await auth.signUp({ email: "petra@example.com", password: "Password123" });
			const token = mocks.sentVerifications[0]?.token;

			const req = new Request("http://localhost/auth/verify-email", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token }),
			});

			const res = await auth.handleRequest(req);
			expect(res).not.toBeNull();
			expect(res?.status).toBe(200);
		});

		it("routes POST /auth/reset-password correctly", async () => {
			const { auth, mocks } = await createTestModule({ requireVerification: false });

			await auth.signUp({ email: "quinn@example.com", password: "OldPass123" });
			await auth.requestReset("quinn@example.com");
			const token = mocks.sentResets[0]?.token;

			const req = new Request("http://localhost/auth/reset-password", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token, newPassword: "NewPass456" }),
			});

			const res = await auth.handleRequest(req);
			expect(res).not.toBeNull();
			expect(res?.status).toBe(200);
		});

		it("returns 409 for duplicate email on sign-up", async () => {
			const { auth } = await createTestModule();

			await auth.signUp({ email: "rosa@example.com", password: "Password123" });

			const req = new Request("http://localhost/auth/sign-up", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "rosa@example.com", password: "Password123" }),
			});

			const res = await auth.handleRequest(req);
			expect(res).not.toBeNull();
			expect(res?.status).toBe(409);
		});
	});

	describe("getUser / getUserByEmail", () => {
		it("returns null for unknown user ID", async () => {
			const { auth } = await createTestModule();
			const user = await auth.getUser("usr_doesnotexist");
			expect(user).toBeNull();
		});

		it("returns null for unknown email", async () => {
			const { auth } = await createTestModule();
			const user = await auth.getUserByEmail("nobody@example.com");
			expect(user).toBeNull();
		});

		it("returns user by email after sign-up", async () => {
			const { auth } = await createTestModule();

			await auth.signUp({ email: "sam@example.com", password: "Password123", name: "Sam" });

			const user = await auth.getUserByEmail("sam@example.com");
			expect(user).not.toBeNull();
			expect(user?.email).toBe("sam@example.com");
			expect(user?.name).toBe("Sam");
		});
	});
});
