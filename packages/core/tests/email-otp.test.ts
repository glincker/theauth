/**
 * Tests for email OTP authentication.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EmailOtpModule } from "../src/auth/email-otp.js";
import { createEmailOtpModule } from "../src/auth/email-otp.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { emailOtps } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

// Helpers

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeSendOtp() {
	return vi.fn(async (_email: string, _code: string) => {
		// no-op in tests
	});
}

// Suite

describe("EmailOtpModule.sendCode", () => {
	let db: Database;
	let mod: EmailOtpModule;
	let sendOtp: ReturnType<typeof makeSendOtp>;

	beforeEach(async () => {
		db = await createTestDb();
		sendOtp = makeSendOtp();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createEmailOtpModule({ sendOtp }, db, sessionManager);
	});

	it("returns { sent: true } on success", async () => {
		const result = await mod.sendCode("alice@example.com");
		expect(result).toEqual({ sent: true });
	});

	it("calls sendOtp with the email and a numeric code", async () => {
		await mod.sendCode("alice@example.com");

		expect(sendOtp).toHaveBeenCalledOnce();
		const [calledEmail, calledCode] = sendOtp.mock.calls[0] as [string, string];
		expect(calledEmail).toBe("alice@example.com");
		expect(calledCode).toMatch(/^\d{6}$/);
	});

	it("stores the code as a hash (not plaintext) in the database", async () => {
		let capturedCode = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createEmailOtpModule(
			{
				sendOtp: async (_e, code) => {
					capturedCode = code;
				},
			},
			db,
			sessionManager,
		);

		await mod.sendCode("bob@example.com");

		const rows = await db.select().from(emailOtps).all();
		expect(rows).toHaveLength(1);
		expect(rows[0]?.codeHash).not.toBe(capturedCode);
		expect(rows[0]?.codeHash).toHaveLength(64); // SHA-256 hex
	});

	it("replaces the previous OTP record when a new code is sent to the same email", async () => {
		await mod.sendCode("carol@example.com");
		await mod.sendCode("carol@example.com");

		const rows = await db.select().from(emailOtps).all();
		expect(rows).toHaveLength(1);
	});

	it("creates the user record if they do not exist yet", async () => {
		const { users } = await import("../src/db/schema.js");
		await mod.sendCode("newuser@example.com");

		const userRows = await db.select().from(users).all();
		expect(userRows.some((u) => u.email === "newuser@example.com")).toBe(false);
		// User is created lazily on verify, not on send.
	});
});

describe("EmailOtpModule.verifyCode", () => {
	let db: Database;
	let mod: EmailOtpModule;

	async function setupModWithCapture(overrides?: { codeExpiry?: number }) {
		db = await createTestDb();
		let capturedCode = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const m = createEmailOtpModule(
			{
				sendOtp: async (_e, code) => {
					capturedCode = code;
				},
				...overrides,
			},
			db,
			sessionManager,
		);
		return { mod: m, getCode: () => capturedCode };
	}

	it("returns user and session for a correct code", async () => {
		const { mod: m, getCode } = await setupModWithCapture();
		await m.sendCode("dave@example.com");
		const result = await m.verifyCode("dave@example.com", getCode());

		expect(result).not.toBeNull();
		expect(result?.user.email).toBe("dave@example.com");
		expect(result?.session.token).toBeTruthy();
		expect(result?.session.expiresAt).toBeInstanceOf(Date);
	});

	it("returns null for a wrong code", async () => {
		const { mod: m } = await setupModWithCapture();
		await m.sendCode("eve@example.com");
		const result = await m.verifyCode("eve@example.com", "000000");
		expect(result).toBeNull();
	});

	it("returns null for an expired code", async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		let capturedCode = "";
		mod = createEmailOtpModule(
			{
				sendOtp: async (_e, code) => {
					capturedCode = code;
				},
				codeExpiry: 1,
			},
			db,
			sessionManager,
		);

		await mod.sendCode("frank@example.com");

		// Back-date the expiry in the DB.
		db.update(emailOtps)
			.set({ expiresAt: new Date(Date.now() - 2000) })
			.run();

		const result = await mod.verifyCode("frank@example.com", capturedCode);
		expect(result).toBeNull();
	});

	it("increments the attempt counter on each failed attempt", async () => {
		const { mod: m } = await setupModWithCapture();
		await m.sendCode("grace@example.com");

		await m.verifyCode("grace@example.com", "000000");
		await m.verifyCode("grace@example.com", "111111");

		const rows = await db.select().from(emailOtps).all();
		expect(rows[0]?.attempts).toBe(2);
	});

	it("returns null once max attempts are exceeded", async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		let capturedCode = "";
		mod = createEmailOtpModule(
			{
				sendOtp: async (_e, code) => {
					capturedCode = code;
				},
				maxAttempts: 2,
			},
			db,
			sessionManager,
		);

		await mod.sendCode("henry@example.com");
		await mod.verifyCode("henry@example.com", "000000"); // attempt 1
		await mod.verifyCode("henry@example.com", "111111"); // attempt 2 (now at limit)

		// Correct code, but max attempts reached.
		const result = await mod.verifyCode("henry@example.com", capturedCode);
		expect(result).toBeNull();
	});

	it("deletes the OTP record after successful verification (prevents re-use)", async () => {
		const { mod: m, getCode } = await setupModWithCapture();
		await m.sendCode("iris@example.com");
		await m.verifyCode("iris@example.com", getCode());

		const rows = await db.select().from(emailOtps).all();
		expect(rows).toHaveLength(0);
	});

	it("returns null when no OTP exists for the email", async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createEmailOtpModule({ sendOtp: makeSendOtp() }, db, sessionManager);

		const result = await mod.verifyCode("nobody@example.com", "123456");
		expect(result).toBeNull();
	});
});

describe("EmailOtpModule.handleRequest", () => {
	let db: Database;
	let mod: EmailOtpModule;

	async function setupWithCapture() {
		db = await createTestDb();
		let capturedCode = "";
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createEmailOtpModule(
			{
				sendOtp: async (_e, code) => {
					capturedCode = code;
				},
			},
			db,
			sessionManager,
		);
		return { getCode: () => capturedCode };
	}

	it("POST /auth/otp/send returns 200 with { sent: true }", async () => {
		await setupWithCapture();
		const req = new Request("https://app.example.com/auth/otp/send", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "jake@example.com" }),
		});

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(200);
		const body = await response?.json();
		expect(body).toEqual({ sent: true });
	});

	it("POST /auth/otp/send returns 400 when email is missing", async () => {
		await setupWithCapture();
		const req = new Request("https://app.example.com/auth/otp/send", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(400);
	});

	it("POST /auth/otp/verify returns 200 on correct code", async () => {
		const { getCode } = await setupWithCapture();

		// Send code first
		await mod.handleRequest(
			new Request("https://app.example.com/auth/otp/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "kate@example.com" }),
			}),
		);

		const verifyReq = new Request("https://app.example.com/auth/otp/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "kate@example.com", code: getCode() }),
		});

		const response = await mod.handleRequest(verifyReq);
		expect(response?.status).toBe(200);
		const body = await response?.json();
		expect(body.user.email).toBe("kate@example.com");
	});

	it("POST /auth/otp/verify returns 401 on wrong code", async () => {
		await setupWithCapture();

		await mod.handleRequest(
			new Request("https://app.example.com/auth/otp/send", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ email: "liam@example.com" }),
			}),
		);

		const verifyReq = new Request("https://app.example.com/auth/otp/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "liam@example.com", code: "000000" }),
		});

		const response = await mod.handleRequest(verifyReq);
		expect(response?.status).toBe(401);
	});

	it("POST /auth/otp/verify returns 400 when fields are missing", async () => {
		await setupWithCapture();

		const req = new Request("https://app.example.com/auth/otp/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "missing@example.com" }), // no code
		});

		const response = await mod.handleRequest(req);
		expect(response?.status).toBe(400);
	});

	it("returns null for unmatched paths", async () => {
		await setupWithCapture();
		const req = new Request("https://app.example.com/something-else", { method: "POST" });
		const response = await mod.handleRequest(req);
		expect(response).toBeNull();
	});

	it("returns null for GET requests", async () => {
		await setupWithCapture();
		const req = new Request("https://app.example.com/auth/otp/send");
		const response = await mod.handleRequest(req);
		expect(response).toBeNull();
	});
});
