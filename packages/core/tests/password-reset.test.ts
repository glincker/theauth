/** Tests for password reset (forgot password) flow. */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { createOneTimeTokenModule } from "../src/auth/one-time-token.js";
import type { PasswordResetModule } from "../src/auth/password-reset.js";
import { createPasswordResetModule } from "../src/auth/password-reset.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import type { SessionManager } from "../src/session/session.js";
import { createSessionManager } from "../src/session/session.js";

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

describe("PasswordResetModule", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let resetModule: PasswordResetModule;
	let sendResetEmail: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		sendResetEmail = vi.fn().mockResolvedValue(undefined);
		const tokenModule = createOneTimeTokenModule({}, db);
		resetModule = createPasswordResetModule(
			{
				sendResetEmail,
				resetUrl: "https://app.example.com/reset-password",
			},
			db,
			sessionManager,
			tokenModule,
		);
	});

	async function createUserWithPassword(
		email: string,
		password: string,
	): Promise<{ userId: string; token: string }> {
		// Username module uses username@username.local as email, so we need
		// to create the user manually for email-based reset testing.
		const { generateId, pbkdf2Hash } = await import("../src/crypto/web-crypto.js");
		const { users, usernameAccounts } = await import("../src/db/schema.js");

		const userId = generateId();
		const now = new Date();
		const passwordHash = await pbkdf2Hash(password);

		await db.insert(users).values({
			id: userId,
			email,
			name: "Test User",
			createdAt: now,
			updatedAt: now,
		});

		await db.insert(usernameAccounts).values({
			id: generateId(),
			userId,
			username: email.split("@")[0]!,
			passwordHash,
			createdAt: now,
			updatedAt: now,
		});

		const { token } = await sessionManager.create(userId);
		return { userId, token };
	}

	describe("requestReset", () => {
		it("sends email for existing user with password account", async () => {
			await createUserWithPassword("alice@example.com", "OldPassword1!");

			const result = await resetModule.requestReset("alice@example.com");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(true);
			}
			expect(sendResetEmail).toHaveBeenCalledOnce();
			expect(sendResetEmail).toHaveBeenCalledWith(
				"alice@example.com",
				expect.any(String),
				expect.stringContaining("https://app.example.com/reset-password?token="),
			);
		});

		it("returns success for unknown email (no enumeration)", async () => {
			const result = await resetModule.requestReset("nobody@example.com");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(false);
			}
			expect(sendResetEmail).not.toHaveBeenCalled();
		});

		it("returns success for user without password account", async () => {
			// Create a user via magic link (no password account)
			const { generateId } = await import("../src/crypto/web-crypto.js");
			const { users } = await import("../src/db/schema.js");

			await db.insert(users).values({
				id: generateId(),
				email: "magic@example.com",
				name: "Magic User",
				createdAt: new Date(),
				updatedAt: new Date(),
			});

			const result = await resetModule.requestReset("magic@example.com");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(false);
			}
			expect(sendResetEmail).not.toHaveBeenCalled();
		});

		it("normalizes email to lowercase", async () => {
			await createUserWithPassword("alice@example.com", "OldPassword1!");

			const result = await resetModule.requestReset("ALICE@EXAMPLE.COM");
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(true);
			}
		});

		it("rejects empty email", async () => {
			const result = await resetModule.requestReset("");
			expect(result.success).toBe(false);
		});
	});

	describe("resetPassword", () => {
		it("resets password with valid token", async () => {
			const { userId } = await createUserWithPassword("alice@example.com", "OldPassword1!");

			await resetModule.requestReset("alice@example.com");
			const token = sendResetEmail.mock.calls[0]![1] as string;

			const result = await resetModule.resetPassword(token, "NewPassword1!");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.userId).toBe(userId);
			}

			// Verify the new password works by signing in
			const usernameModule = createUsernameAuthModule({}, db, sessionManager);
			const signIn = await usernameModule.signIn({
				username: "alice",
				password: "NewPassword1!",
			});
			expect(signIn.user.id).toBe(userId);
		});

		it("revokes all sessions after reset", async () => {
			const { userId } = await createUserWithPassword("alice@example.com", "OldPassword1!");

			await sessionManager.create(userId);
			await sessionManager.create(userId);

			const sessionsBefore = await sessionManager.list(userId);
			expect(sessionsBefore.length).toBe(3);

			await resetModule.requestReset("alice@example.com");
			const token = sendResetEmail.mock.calls[0]![1] as string;
			await resetModule.resetPassword(token, "NewPassword1!");

			const sessionsAfter = await sessionManager.list(userId);
			expect(sessionsAfter.length).toBe(0);
		});

		it("rejects invalid token", async () => {
			const result = await resetModule.resetPassword("invalid-token-here", "NewPassword1!");

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("INVALID_TOKEN");
			}
		});

		it("rejects already-used token", async () => {
			await createUserWithPassword("alice@example.com", "OldPassword1!");

			await resetModule.requestReset("alice@example.com");
			const token = sendResetEmail.mock.calls[0]![1] as string;

			const first = await resetModule.resetPassword(token, "NewPassword1!");
			expect(first.success).toBe(true);

			// Try to use it again
			const second = await resetModule.resetPassword(token, "AnotherPassword1!");
			expect(second.success).toBe(false);
			if (!second.success) {
				expect(second.error.code).toBe("INVALID_TOKEN");
			}
		});

		it("rejects short password", async () => {
			await createUserWithPassword("alice@example.com", "OldPassword1!");

			await resetModule.requestReset("alice@example.com");
			const token = sendResetEmail.mock.calls[0]![1] as string;

			const result = await resetModule.resetPassword(token, "short");
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("INVALID_PASSWORD");
			}
		});

		it("rejects empty token", async () => {
			const result = await resetModule.resetPassword("", "NewPassword1!");
			expect(result.success).toBe(false);
		});

		it("clears forcePasswordReset flag", async () => {
			const { userId } = await createUserWithPassword("alice@example.com", "OldPassword1!");

			const { users } = await import("../src/db/schema.js");
			const { eq } = await import("drizzle-orm");
			await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, userId));

			await resetModule.requestReset("alice@example.com");
			const token = sendResetEmail.mock.calls[0]![1] as string;
			await resetModule.resetPassword(token, "NewPassword1!");

			const rows = await db.select().from(users).where(eq(users.id, userId));
			expect(rows[0]!.forcePasswordReset).toBe(0);
		});
	});

	describe("handleRequest", () => {
		it("POST /auth/forgot-password returns 204", async () => {
			await createUserWithPassword("alice@example.com", "OldPassword1!");

			const request = new Request("http://localhost/auth/forgot-password", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "alice@example.com" }),
			});

			const response = await resetModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(204);
		});

		it("POST /auth/forgot-password returns 204 even for unknown email", async () => {
			const request = new Request("http://localhost/auth/forgot-password", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "nobody@example.com" }),
			});

			const response = await resetModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(204);
		});

		it("POST /auth/reset-password returns 204 on success", async () => {
			await createUserWithPassword("alice@example.com", "OldPassword1!");

			await resetModule.requestReset("alice@example.com");
			const token = sendResetEmail.mock.calls[0]![1] as string;

			const request = new Request("http://localhost/auth/reset-password", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token, password: "NewPassword1!" }),
			});

			const response = await resetModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(204);
		});

		it("POST /auth/reset-password returns 400 on bad token", async () => {
			const request = new Request("http://localhost/auth/reset-password", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token: "bad-token", password: "NewPassword1!" }),
			});

			const response = await resetModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(400);
		});

		it("returns null for unmatched paths", async () => {
			const request = new Request("http://localhost/auth/something-else", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const response = await resetModule.handleRequest(request);
			expect(response).toBeNull();
		});

		it("returns null for non-POST methods", async () => {
			const request = new Request("http://localhost/auth/forgot-password", {
				method: "GET",
			});

			const response = await resetModule.handleRequest(request);
			expect(response).toBeNull();
		});
	});
});
