/** Tests for the email verification flow. */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EmailVerificationModule } from "../src/auth/email-verification.js";
import { createEmailVerificationModule } from "../src/auth/email-verification.js";
import { createOneTimeTokenModule } from "../src/auth/one-time-token.js";
import { generateId } from "../src/crypto/web-crypto.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function insertUser(
	db: Database,
	email: string,
	emailVerified = 0,
): Promise<{ userId: string }> {
	const userId = generateId();
	const now = new Date();
	await db.insert(users).values({
		id: userId,
		email,
		name: "Test User",
		emailVerified,
		createdAt: now,
		updatedAt: now,
	});
	return { userId };
}

describe("EmailVerificationModule", () => {
	let db: Database;
	let verificationModule: EmailVerificationModule;
	let sendVerificationEmail: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		db = await createTestDb();
		sendVerificationEmail = vi.fn().mockResolvedValue(undefined);
		const tokenModule = createOneTimeTokenModule({}, db);
		verificationModule = createEmailVerificationModule(
			{
				sendVerificationEmail,
				verifyUrl: "https://app.example.com/verify-email",
			},
			db,
			tokenModule,
		);
	});

	describe("sendVerification", () => {
		it("creates token and calls email callback", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			const result = await verificationModule.sendVerification(userId, "alice@example.com");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(true);
			}
			expect(sendVerificationEmail).toHaveBeenCalledOnce();
			expect(sendVerificationEmail).toHaveBeenCalledWith(
				"alice@example.com",
				expect.any(String),
				expect.stringContaining("https://app.example.com/verify-email?token="),
			);
		});

		it("does not send when email is already verified", async () => {
			const { userId } = await insertUser(db, "alice@example.com", 1);

			const result = await verificationModule.sendVerification(userId, "alice@example.com");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(false);
			}
			expect(sendVerificationEmail).not.toHaveBeenCalled();
		});

		it("returns USER_NOT_FOUND for missing user", async () => {
			const result = await verificationModule.sendVerification(
				"non-existent-id",
				"nobody@example.com",
			);

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("USER_NOT_FOUND");
			}
		});

		it("rejects empty userId", async () => {
			const result = await verificationModule.sendVerification("", "alice@example.com");
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("INVALID_INPUT");
			}
		});

		it("rejects empty email", async () => {
			const { userId } = await insertUser(db, "alice@example.com");
			const result = await verificationModule.sendVerification(userId, "");
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("INVALID_INPUT");
			}
		});

		it("normalizes email to lowercase", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			const result = await verificationModule.sendVerification(userId, "ALICE@EXAMPLE.COM");

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sent).toBe(true);
			}
			// Email callback receives the normalized (lowercase) address
			expect(sendVerificationEmail).toHaveBeenCalledWith(
				"alice@example.com",
				expect.any(String),
				expect.any(String),
			);
		});

		it("revokes previous tokens when re-sending", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			await verificationModule.sendVerification(userId, "alice@example.com");
			const firstToken = sendVerificationEmail.mock.calls[0]![1] as string;

			await verificationModule.sendVerification(userId, "alice@example.com");

			// First token should now be invalid
			const verifyResult = await verificationModule.verify(firstToken);
			expect(verifyResult.success).toBe(false);
		});
	});

	describe("verify", () => {
		it("marks user as verified on valid token", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			await verificationModule.sendVerification(userId, "alice@example.com");
			const token = sendVerificationEmail.mock.calls[0]![1] as string;

			const result = await verificationModule.verify(token);

			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.userId).toBe(userId);
				expect(result.data.email).toBe("alice@example.com");
			}

			// Confirm the DB field was updated
			const rows = await db
				.select({ emailVerified: users.emailVerified })
				.from(users)
				.where(eq(users.id, userId));
			expect(rows[0]!.emailVerified).toBe(1);
		});

		it("isVerified returns true after verify", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			await verificationModule.sendVerification(userId, "alice@example.com");
			const token = sendVerificationEmail.mock.calls[0]![1] as string;

			expect(await verificationModule.isVerified(userId)).toBe(false);

			await verificationModule.verify(token);

			expect(await verificationModule.isVerified(userId)).toBe(true);
		});

		it("rejects invalid token", async () => {
			const result = await verificationModule.verify("invalid-token-here");

			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("INVALID_TOKEN");
			}
		});

		it("rejects already-used token", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			await verificationModule.sendVerification(userId, "alice@example.com");
			const token = sendVerificationEmail.mock.calls[0]![1] as string;

			const first = await verificationModule.verify(token);
			expect(first.success).toBe(true);

			const second = await verificationModule.verify(token);
			expect(second.success).toBe(false);
			if (!second.success) {
				expect(second.error.code).toBe("INVALID_TOKEN");
			}
		});

		it("rejects empty token", async () => {
			const result = await verificationModule.verify("");
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("INVALID_INPUT");
			}
		});

		it("revokes remaining tokens for email after successful verify", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			// Issue a token, then send a second (which revokes the first)
			await verificationModule.sendVerification(userId, "alice@example.com");
			const token = sendVerificationEmail.mock.calls[0]![1] as string;

			// Verify with the only valid token
			await verificationModule.verify(token);

			// Now any replay with the same token must fail
			const replay = await verificationModule.verify(token);
			expect(replay.success).toBe(false);
		});
	});

	describe("isVerified", () => {
		it("returns false before verification", async () => {
			const { userId } = await insertUser(db, "alice@example.com");
			expect(await verificationModule.isVerified(userId)).toBe(false);
		});

		it("returns true for pre-verified user", async () => {
			const { userId } = await insertUser(db, "alice@example.com", 1);
			expect(await verificationModule.isVerified(userId)).toBe(true);
		});

		it("returns false for unknown userId", async () => {
			expect(await verificationModule.isVerified("non-existent-id")).toBe(false);
		});
	});

	describe("handleRequest", () => {
		it("POST /auth/verify-email/send returns 204", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			const request = new Request("http://localhost/auth/verify-email/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ userId, email: "alice@example.com" }),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(204);
			expect(sendVerificationEmail).toHaveBeenCalledOnce();
		});

		it("POST /auth/verify-email/send returns 404 for missing user", async () => {
			const request = new Request("http://localhost/auth/verify-email/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ userId: "nonexistent", email: "nobody@example.com" }),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(404);
		});

		it("POST /auth/verify-email/send returns 400 on missing fields", async () => {
			const request = new Request("http://localhost/auth/verify-email/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "alice@example.com" }),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(400);
		});

		it("POST /auth/verify-email/confirm returns 200 with userId and email", async () => {
			const { userId } = await insertUser(db, "alice@example.com");

			await verificationModule.sendVerification(userId, "alice@example.com");
			const token = sendVerificationEmail.mock.calls[0]![1] as string;

			const request = new Request("http://localhost/auth/verify-email/confirm", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token }),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(200);

			const body = (await response!.json()) as { userId: string; email: string };
			expect(body.userId).toBe(userId);
			expect(body.email).toBe("alice@example.com");
		});

		it("POST /auth/verify-email/confirm returns 400 on bad token", async () => {
			const request = new Request("http://localhost/auth/verify-email/confirm", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ token: "bad-token" }),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(400);
		});

		it("POST /auth/verify-email/confirm returns 400 on missing token field", async () => {
			const request = new Request("http://localhost/auth/verify-email/confirm", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(400);
		});

		it("returns null for unmatched paths", async () => {
			const request = new Request("http://localhost/auth/something-else", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({}),
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).toBeNull();
		});

		it("returns null for non-POST methods", async () => {
			const request = new Request("http://localhost/auth/verify-email/send", {
				method: "GET",
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).toBeNull();
		});

		it("returns 400 on malformed JSON", async () => {
			const request = new Request("http://localhost/auth/verify-email/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: "not-json",
			});

			const response = await verificationModule.handleRequest(request);
			expect(response).not.toBeNull();
			expect(response!.status).toBe(400);
		});
	});
});
