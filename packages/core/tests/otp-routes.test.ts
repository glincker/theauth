/**
 * Tests for the HTTP surface of the OTP service: the otpRoutes plugin, the
 * opt-in two-factor OTP method, and code-based password reset.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createOneTimeTokenModule } from "../src/auth/one-time-token.js";
import { createOtpService } from "../src/auth/otp.js";
import { otpRoutes } from "../src/auth/otp-plugin.js";
import type { OtpMessage } from "../src/auth/otp-senders.js";
import { createPasswordResetModule } from "../src/auth/password-reset.js";
import { twoFactor } from "../src/auth/totp-plugin.js";
import type { ResolvedUser } from "../src/auth/types.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createPluginRouter } from "../src/plugin/router.js";
import type { EndpointContext, PluginEndpoint, TheAuthPlugin } from "../src/plugin/types.js";
import { createSessionManager } from "../src/session/session.js";

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function testDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeService(cooldown = 0) {
	const sent: OtpMessage[] = [];
	const service = createOtpService({
		senders: {
			email: {
				async send(m) {
					sent.push(m);
				},
			},
		},
		secret: "s3cret",
		resendCooldownSeconds: cooldown,
		maxAttempts: 3,
	});
	return { service, sent };
}

async function mount(plugin: TheAuthPlugin, db: Database, userId: string | null = null) {
	const endpoints: PluginEndpoint[] = [];
	await plugin.init?.({
		db,
		config: {} as never,
		addEndpoint: (e) => endpoints.push(e),
		addMigration: () => undefined,
		sessionManager: null,
	});
	const router = createPluginRouter(endpoints);
	const ctx: EndpointContext = {
		db,
		getUser: async () => (userId ? ({ id: userId } as ResolvedUser) : null),
		getSession: async () => null,
	};
	return (path: string, body: unknown) =>
		router.handle(
			new Request(`http://localhost${path}`, {
				method: "POST",
				body: typeof body === "string" ? body : JSON.stringify(body),
			}),
			"",
			ctx,
		);
}

describe("otpRoutes", () => {
	let db: Database;
	beforeEach(async () => {
		db = await testDb();
	});

	it("sends and verifies a code end to end", async () => {
		const { service, sent } = makeService();
		const call = await mount(otpRoutes({ service, onVerified: () => ({ extra: 1 }) }), db);

		const res = await call("/auth/code/send", { identifier: "ada@example.com" });
		expect(res?.status).toBe(202);
		expect(await res?.json()).toEqual({ sent: true });
		expect(sent).toHaveLength(1);

		const ok = await call("/auth/code/verify", {
			identifier: "ada@example.com",
			code: sent[0]?.code,
		});
		expect(ok?.status).toBe(200);
		expect(await ok?.json()).toEqual({ verified: true, extra: 1 });
	});

	it("gives the same send answer whether or not a code went out", async () => {
		const { service, sent } = makeService(60);
		const call = await mount(
			otpRoutes({ service, canSend: (i) => i.identifier === "known@example.com" }),
			db,
		);
		const known = await call("/auth/code/send", { identifier: "known@example.com" });
		const throttled = await call("/auth/code/send", { identifier: "known@example.com" });
		const unknown = await call("/auth/code/send", { identifier: "ghost@example.com" });
		for (const r of [known, throttled, unknown]) {
			expect(r?.status).toBe(202);
			expect(await r?.json()).toEqual({ sent: true });
		}
		expect(sent).toHaveLength(1);
	});

	it("uses one error for wrong, unknown and expired codes", async () => {
		const { service } = makeService();
		const call = await mount(otpRoutes({ service }), db);
		const res = await call("/auth/code/verify", {
			identifier: "nobody@example.com",
			code: "000000",
		});
		expect(res?.status).toBe(400);
		expect(await res?.json()).toEqual({ error: "Invalid or expired code" });
	});

	it("answers 429 with Retry-After once locked", async () => {
		const { service } = makeService();
		const call = await mount(otpRoutes({ service }), db);
		await call("/auth/code/send", { identifier: "ada@example.com" });
		let last: Response | null = null;
		for (let i = 0; i < 3; i++) {
			last = await call("/auth/code/verify", { identifier: "ada@example.com", code: "999999" });
		}
		expect(last?.status).toBe(429);
		expect(last?.headers.get("Retry-After")).toBeTruthy();
	});

	it("rejects purposes that are not exposed and malformed input", async () => {
		const { service } = makeService();
		const call = await mount(otpRoutes({ service }), db);
		const bad = await call("/auth/code/send", { purpose: "reset-password", identifier: "a@b.co" });
		expect(bad?.status).toBe(400);
		expect((await call("/auth/code/send", { identifier: "a@b.co", channel: "sms" }))?.status).toBe(
			400,
		);
		expect((await call("/auth/code/send", "not json"))?.status).toBe(400);
		expect((await call("/auth/code/send", {}))?.status).toBe(400);
	});

	it("rate limits send per client", async () => {
		const { service } = makeService();
		const call = await mount(otpRoutes({ service, sendRateLimit: { window: 60, max: 2 } }), db);
		const statuses: number[] = [];
		for (let i = 0; i < 3; i++) {
			statuses.push(
				(await call("/auth/code/send", { identifier: `u${i}@example.com` }))?.status ?? 0,
			);
		}
		expect(statuses).toEqual([202, 202, 429]);
	});
});

describe("twoFactor OTP method", () => {
	it("is not mounted unless configured", async () => {
		const db = await testDb();
		const call = await mount(twoFactor(), db, "u1");
		expect(await call("/auth/2fa/otp/send", {})).toBeNull();
	});

	it("sends to the contact on file and verifies for the same user", async () => {
		const db = await testDb();
		const { service, sent } = makeService();
		const call = await mount(
			twoFactor({
				otp: {
					service,
					resolveContact: async (id) =>
						id === "u1" ? { channel: "email", identifier: "ada@example.com" } : null,
				},
			}),
			db,
			"u1",
		);
		expect((await call("/auth/2fa/otp/send", {}))?.status).toBe(202);
		expect(sent[0]).toMatchObject({ to: "ada@example.com", purpose: "two-factor" });

		expect((await call("/auth/2fa/otp/verify", { code: "000000" }))?.status).toBe(400);
		const ok = await call("/auth/2fa/otp/verify", { code: sent[0]?.code });
		expect(await ok?.json()).toEqual({ valid: true });
	});

	it("requires a signed in user and hides a missing contact", async () => {
		const db = await testDb();
		const { service, sent } = makeService();
		const config = { otp: { service, resolveContact: async () => null } };
		const anon = await mount(twoFactor(config), db, null);
		expect((await anon("/auth/2fa/otp/send", {}))?.status).toBe(401);
		const authed = await mount(twoFactor(config), db, "u2");
		expect((await authed("/auth/2fa/otp/send", {}))?.status).toBe(202);
		expect(sent).toHaveLength(0);
	});
});

describe("password reset with OTP", () => {
	async function setup() {
		const db = await testDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const { service, sent } = makeService();
		const module = createPasswordResetModule(
			{
				sendResetEmail: async () => undefined,
				resetUrl: "https://app.example.com/reset",
				otp: { service },
			},
			db,
			sessionManager,
			createOneTimeTokenModule({}, db),
		);
		const { generateId, pbkdf2Hash } = await import("../src/crypto/web-crypto.js");
		const { users, usernameAccounts } = await import("../src/db/schema.js");
		const userId = generateId();
		const now = new Date();
		await db.insert(users).values({
			id: userId,
			email: "alice@example.com",
			name: "A",
			createdAt: now,
			updatedAt: now,
		});
		await db.insert(usernameAccounts).values({
			id: generateId(),
			userId,
			username: "alice",
			passwordHash: await pbkdf2Hash("OldPassword1!"),
			createdAt: now,
			updatedAt: now,
		});
		return { module, sent, userId, sessionManager };
	}

	it("sends a code and resets the password with it", async () => {
		const { module, sent, userId, sessionManager } = await setup();
		const { token } = await sessionManager.create(userId);

		const req = await module.requestResetOtp("Alice@Example.com");
		expect(req).toEqual({ success: true, data: { sent: true } });
		expect(sent[0]?.purpose).toBe("reset-password");

		const done = await module.resetPasswordWithOtp(
			"alice@example.com",
			sent[0]?.code ?? "",
			"NewPassword1!",
		);
		expect(done).toEqual({ success: true, data: { userId } });
		expect(await sessionManager.validate(token)).toBeNull();

		const replay = await module.resetPasswordWithOtp(
			"alice@example.com",
			sent[0]?.code ?? "",
			"Another1234!",
		);
		expect(replay.success).toBe(false);
	});

	it("does not reveal unknown emails and rejects wrong codes generically", async () => {
		const { module, sent } = await setup();
		expect(await module.requestResetOtp("ghost@example.com")).toEqual({
			success: true,
			data: { sent: false },
		});
		expect(sent).toHaveLength(0);

		const wrong = await module.resetPasswordWithOtp("ghost@example.com", "123456", "NewPassword1!");
		expect(wrong.success).toBe(false);
		if (!wrong.success) expect(wrong.error.code).toBe("INVALID_CODE");
	});

	it("serves the OTP routes and keeps them off without config", async () => {
		const { module, sent } = await setup();
		const post = (path: string, body: unknown) =>
			module.handleRequest(
				new Request(`http://localhost${path}`, { method: "POST", body: JSON.stringify(body) }),
			);
		expect((await post("/auth/forgot-password/otp", { email: "alice@example.com" }))?.status).toBe(
			204,
		);
		const reset = await post("/auth/reset-password/otp", {
			email: "alice@example.com",
			code: sent[0]?.code,
			password: "NewPassword1!",
		});
		expect(reset?.status).toBe(204);

		const db = await testDb();
		const plain = createPasswordResetModule(
			{ sendResetEmail: async () => undefined, resetUrl: "https://x.test/r" },
			db,
			createSessionManager({ secret: SESSION_SECRET }, db),
			createOneTimeTokenModule({}, db),
		);
		const off = await plain.handleRequest(
			new Request("http://localhost/auth/forgot-password/otp", {
				method: "POST",
				body: JSON.stringify({ email: "a@b.co" }),
			}),
		);
		expect(off).toBeNull();
	});
});
