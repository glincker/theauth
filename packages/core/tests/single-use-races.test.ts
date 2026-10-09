/**
 * Concurrency tests: single-use credentials must be redeemable exactly once,
 * and attempt counters must not be bypassable by firing guesses in parallel.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { createEmailOtpModule } from "../src/auth/email-otp.js";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import { createOneTimeTokenModule } from "../src/auth/one-time-token.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createSessionManager } from "../src/session/session.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function testDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

describe("magic link replay race", () => {
	it("two concurrent verifies of one link yield one session", async () => {
		const db = await testDb();
		const sent: string[] = [];
		const mod = createMagicLinkModule(
			{
				appUrl: "https://app.example.com",
				sendMagicLink: async (_e, token) => {
					sent.push(token);
				},
			},
			db,
			createSessionManager({ secret: SECRET }, db),
		);
		await mod.sendLink("a@example.com");
		const token = sent[0] as string;
		const results = await Promise.all([mod.verify(token), mod.verify(token), mod.verify(token)]);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
	});
});

describe("email OTP", () => {
	let db: Database;
	beforeEach(async () => {
		db = await testDb();
	});

	function make(maxAttempts = 3) {
		const codes: string[] = [];
		const mod = createEmailOtpModule(
			{
				maxAttempts,
				sendOtp: async (_e, code) => {
					codes.push(code);
				},
			},
			db,
			createSessionManager({ secret: SECRET }, db),
		);
		return { mod, codes };
	}

	it("parallel wrong guesses cannot exceed maxAttempts before lockout", async () => {
		const { mod, codes } = make(3);
		await mod.sendCode("a@example.com");
		const real = codes[0] as string;
		// 40 parallel guesses, one of which is the right code. Only the first
		// 3 attempts may be evaluated, so the right code must not get through
		// when it is not among them.
		const wrong = Array.from({ length: 40 }, (_, i) => String(i).padStart(6, "0")).filter(
			(c) => c !== real,
		);
		const guesses = [...wrong.slice(0, 39), real];
		const results = await Promise.all(guesses.map((g) => mod.verifyCode("a@example.com", g)));
		expect(results.every((r) => r === null)).toBe(true);
	});

	it("two concurrent correct verifies yield one session", async () => {
		const { mod, codes } = make(5);
		await mod.sendCode("a@example.com");
		const code = codes[0] as string;
		const results = await Promise.all([
			mod.verifyCode("a@example.com", code),
			mod.verifyCode("a@example.com", code),
		]);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
	});

	it("is case-insensitive on the email when called directly", async () => {
		const { mod, codes } = make(5);
		await mod.sendCode("Alice@Example.com");
		const res = await mod.verifyCode("alice@example.com", codes[0] as string);
		expect(res?.user.email).toBe("alice@example.com");
	});
});

describe("one-time token race", () => {
	it("concurrent consumes succeed once", async () => {
		const db = await testDb();
		const mod = createOneTimeTokenModule({}, db);
		const created = await mod.createToken({ purpose: "custom", identifier: "user-1" });
		if (!created.success) throw new Error("create failed");
		const token = created.data.token;
		const results = await Promise.all([
			mod.validateToken(token, "custom"),
			mod.validateToken(token, "custom"),
			mod.validateToken(token, "custom"),
		]);
		expect(results.filter((r) => r.success)).toHaveLength(1);
	});
});

void vi;
