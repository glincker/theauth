/** Tests for phone number (SMS OTP) authentication. */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PhoneAuthModule } from "../src/auth/phone.js";
import { createPhoneAuthModule } from "../src/auth/phone.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { phoneVerifications } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeModule(
	db: Database,
	overrides?: { codeExpiry?: number; maxAttempts?: number },
): { mod: PhoneAuthModule; sendSms: ReturnType<typeof vi.fn>; getCode: () => string } {
	const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
	let capturedCode = "";
	const sendSms = vi.fn(async (_phone: string, code: string) => {
		capturedCode = code;
	});
	const mod = createPhoneAuthModule({ sendSms, ...overrides }, db, sessionManager);
	return { mod, sendSms, getCode: () => capturedCode };
}

describe("PhoneAuthModule.sendCode", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("calls sendSms with the phone number and a numeric code", async () => {
		const { mod, sendSms } = makeModule(db);
		await mod.sendCode("+14155551234");
		expect(sendSms).toHaveBeenCalledOnce();
		const [phone, code] = sendSms.mock.calls[0] as [string, string];
		expect(phone).toBe("+14155551234");
		expect(code).toMatch(/^\d{6}$/);
	});

	it("stores a hashed code (not plaintext)", async () => {
		const { mod, getCode } = makeModule(db);
		await mod.sendCode("+14155551234");
		const rows = await db.select().from(phoneVerifications).all();
		expect(rows).toHaveLength(1);
		expect(rows[0]?.codeHash).not.toBe(getCode());
		expect(rows[0]?.codeHash).toHaveLength(64); // SHA-256 hex
	});

	it("replaces existing record for same phone number", async () => {
		const { mod } = makeModule(db);
		await mod.sendCode("+14155551234");
		await mod.sendCode("+14155551234");
		const rows = await db.select().from(phoneVerifications).all();
		expect(rows).toHaveLength(1);
	});

	it("returns { sent: true }", async () => {
		const { mod } = makeModule(db);
		const result = await mod.sendCode("+14155551234");
		expect(result).toEqual({ sent: true });
	});
});

describe("PhoneAuthModule.verifyCode", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("returns user and session on correct code", async () => {
		const { mod, getCode } = makeModule(db);
		await mod.sendCode("+14155551234");
		const result = await mod.verifyCode("+14155551234", getCode());
		expect(result).not.toBeNull();
		expect(result?.user.phone).toBe("+14155551234");
		expect(result?.session.token).toBeTruthy();
		expect(result?.session.expiresAt).toBeInstanceOf(Date);
	});

	it("returns null for wrong code", async () => {
		const { mod } = makeModule(db);
		await mod.sendCode("+14155551234");
		const result = await mod.verifyCode("+14155551234", "000000");
		expect(result).toBeNull();
	});

	it("returns null for expired code", async () => {
		const { mod } = makeModule(db, { codeExpiry: 1 });
		await mod.sendCode("+14155551234");
		db.update(phoneVerifications)
			.set({ expiresAt: new Date(Date.now() - 2000) })
			.run();
		const result = await mod.verifyCode("+14155551234", "123456");
		expect(result).toBeNull();
	});

	it("returns null when max attempts exceeded", async () => {
		const { mod, getCode } = makeModule(db, { maxAttempts: 2 });
		await mod.sendCode("+14155551234");
		await mod.verifyCode("+14155551234", "000000"); // attempt 1
		await mod.verifyCode("+14155551234", "111111"); // attempt 2
		const result = await mod.verifyCode("+14155551234", getCode()); // over limit
		expect(result).toBeNull();
	});

	it("deletes record on successful verification", async () => {
		const { mod, getCode } = makeModule(db);
		await mod.sendCode("+14155551234");
		await mod.verifyCode("+14155551234", getCode());
		const rows = await db.select().from(phoneVerifications).all();
		expect(rows).toHaveLength(0);
	});

	it("creates a new user on first verification", async () => {
		const { users } = await import("../src/db/schema.js");
		const { mod, getCode } = makeModule(db);
		await mod.sendCode("+14155559999");
		await mod.verifyCode("+14155559999", getCode());
		const rows = await db.select().from(users).all();
		expect(rows.some((u) => u.metadata?.phone === "+14155559999")).toBe(true);
	});
});

describe("PhoneAuthModule.handleRequest", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("POST /auth/phone/send-code returns 200", async () => {
		const { mod } = makeModule(db);
		const req = new Request("https://app.example.com/auth/phone/send-code", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ phoneNumber: "+14155551234" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(body.sent).toBe(true);
	});

	it("POST /auth/phone/send-code returns 400 when field is missing", async () => {
		const { mod } = makeModule(db);
		const req = new Request("https://app.example.com/auth/phone/send-code", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({}),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
	});

	it("POST /auth/phone/verify returns 200 on correct code", async () => {
		const { mod, getCode } = makeModule(db);
		await mod.sendCode("+14155551234");
		const req = new Request("https://app.example.com/auth/phone/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ phoneNumber: "+14155551234", code: getCode() }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
	});

	it("POST /auth/phone/verify returns 401 on wrong code", async () => {
		const { mod } = makeModule(db);
		await mod.sendCode("+14155551234");
		const req = new Request("https://app.example.com/auth/phone/verify", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ phoneNumber: "+14155551234", code: "000000" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(401);
	});

	it("returns null for unmatched paths", async () => {
		const { mod } = makeModule(db);
		const req = new Request("https://app.example.com/other", { method: "POST" });
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});
});
