/**
 * Sign-in gate coverage for phone, email OTP, Google One Tap and device auth.
 *
 * Each method is opt-in through `require2faFor`; the defaults are unchanged.
 */

import { SignJWT } from "jose";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createDeviceAuthModule } from "../src/auth/device-auth.js";
import { createEmailOtpModule } from "../src/auth/email-otp.js";
import { createOneTapModule } from "../src/auth/one-tap.js";
import { createPhoneAuthModule } from "../src/auth/phone.js";
import type { SignInGate, SignInGateConfig, TwoFactorFactor } from "../src/auth/sign-in-gate.js";
import { createSignInGate, SignInGateError, signInGateResponse } from "../src/auth/sign-in-gate.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { sessions } from "../src/db/schema.js";
import { createSessionManager } from "../src/session/session.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const GOOGLE_SECRET = new TextEncoder().encode(
	"test-google-hmac-secret-for-unit-tests-only-32chars",
);
const CLIENT_ID = "gate-client.apps.googleusercontent.com";

vi.mock("jose", async (importOriginal) => {
	const original = await importOriginal<typeof import("jose")>();
	return {
		...original,
		createRemoteJWKSet: vi.fn(() => async () => GOOGLE_SECRET),
	};
});

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

/** Every user has this factor enabled; the valid code is "123456". */
const factor: TwoFactorFactor = {
	id: "fake",
	isEnabled: async () => true,
	verify: async (_userId, code) => code === "123456",
};

function gateFor(db: Database, config: SignInGateConfig): SignInGate {
	return createSignInGate({
		db,
		sessionSecret: SECRET,
		config: { factors: [factor], ...config },
	});
}

async function sessionCount(db: Database): Promise<number> {
	return (await db.select().from(sessions)).length;
}

async function idToken(email: string): Promise<string> {
	return new SignJWT({ sub: "g-1", email, email_verified: true, name: "Gate User" })
		.setProtectedHeader({ alg: "HS256" })
		.setAudience(CLIENT_ID)
		.setIssuer("https://accounts.google.com")
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(GOOGLE_SECRET);
}

describe("phone sign-in gate", () => {
	let db: Database;
	let code = "";

	beforeEach(async () => {
		db = await createTestDb();
		code = "";
	});

	function phoneModule(gate: SignInGate) {
		return createPhoneAuthModule(
			{
				sendSms: async (_p, c) => {
					code = c;
				},
			},
			db,
			createSessionManager({ secret: SECRET }, db),
			gate,
		);
	}

	it("issues a session by default even when a factor is enabled", async () => {
		const mod = phoneModule(gateFor(db, {}));
		await mod.sendCode("+14155550001");
		const result = await mod.verifyCode("+14155550001", code);
		expect(result?.session.token).toBeTruthy();
	});

	it("throws SignInGateError and issues no session when phone is required", async () => {
		const gate = gateFor(db, { require2faFor: ["phone"] });
		const mod = phoneModule(gate);
		await mod.sendCode("+14155550001");
		await expect(mod.verifyCode("+14155550001", code)).rejects.toBeInstanceOf(SignInGateError);
		expect(await sessionCount(db)).toBe(0);
	});

	it("answers the HTTP verify route with a two-factor challenge", async () => {
		const gate = gateFor(db, { require2faFor: ["phone"] });
		const mod = phoneModule(gate);
		await mod.sendCode("+14155550001");
		const res = await mod.handleRequest(
			new Request("https://app.example.com/auth/phone/verify", {
				method: "POST",
				body: JSON.stringify({ phoneNumber: "+14155550001", code }),
			}),
		);
		expect(res?.status).toBe(200);
		const body = (await res?.json()) as { twoFactorRequired: boolean; challenge: string };
		expect(body.twoFactorRequired).toBe(true);
		const done = await gate.completeTwoFactor({ challenge: body.challenge, code: "123456" });
		expect(done).toMatchObject({ ok: true, method: "phone" });
	});
});

describe("email OTP sign-in gate", () => {
	let db: Database;
	let code = "";

	beforeEach(async () => {
		db = await createTestDb();
	});

	function otpModule(gate: SignInGate) {
		return createEmailOtpModule(
			{
				sendOtp: async (_e, c) => {
					code = c;
				},
			},
			db,
			createSessionManager({ secret: SECRET }, db),
			gate,
		);
	}

	it("issues a session by default", async () => {
		const mod = otpModule(gateFor(db, {}));
		await mod.sendCode("a@example.com");
		expect((await mod.verifyCode("a@example.com", code))?.session.token).toBeTruthy();
	});

	it("gates the session when email_otp is required", async () => {
		const gate = gateFor(db, { require2faFor: ["email_otp"] });
		const mod = otpModule(gate);
		await mod.sendCode("a@example.com");
		const err = await mod.verifyCode("a@example.com", code).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(SignInGateError);
		expect(await sessionCount(db)).toBe(0);
		const res = signInGateResponse(err as SignInGateError);
		const body = (await res.json()) as { methods: string[] };
		expect(body.methods).toEqual(["fake"]);
	});

	it("answers the HTTP route with a challenge, not a session", async () => {
		const mod = otpModule(gateFor(db, { require2faFor: ["email_otp"] }));
		await mod.sendCode("a@example.com");
		const res = await mod.handleRequest(
			new Request("https://app.example.com/auth/otp/verify", {
				method: "POST",
				body: JSON.stringify({ email: "a@example.com", code }),
			}),
		);
		const body = (await res?.json()) as Record<string, unknown>;
		expect(body.twoFactorRequired).toBe(true);
		expect(body.session).toBeUndefined();
	});
});

describe("one tap sign-in gate", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	async function callback(gate: SignInGate): Promise<Response> {
		const mod = createOneTapModule(
			{ clientId: CLIENT_ID },
			db,
			createSessionManager({ secret: SECRET }, db),
			gate,
		);
		const body = new URLSearchParams({
			credential: await idToken("tap@example.com"),
			g_csrf_token: "c1",
		});
		const res = await mod.handleRequest(
			new Request("https://app.example.com/auth/one-tap/callback", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					cookie: "g_csrf_token=c1",
				},
				body: body.toString(),
			}),
		);
		if (!res) throw new Error("no response");
		return res;
	}

	it("issues a session by default", async () => {
		const res = await callback(gateFor(db, {}));
		const body = (await res.json()) as { session?: { token: string } };
		expect(body.session?.token).toBeTruthy();
	});

	it("returns a challenge and no session when one_tap is required", async () => {
		const res = await callback(gateFor(db, { require2faFor: ["one_tap"] }));
		const body = (await res.json()) as { twoFactorRequired?: boolean; session?: unknown };
		expect(body.twoFactorRequired).toBe(true);
		expect(body.session).toBeUndefined();
		expect(await sessionCount(db)).toBe(0);
	});
});

describe("device auth sign-in gate", () => {
	it("answers the token poll with the gate challenge when issueToken is gated", async () => {
		const db = await createTestDb();
		const gate = gateFor(db, { require2faFor: ["device"] });
		const sessionManager = createSessionManager({ secret: SECRET }, db);
		const mod = createDeviceAuthModule({
			verificationUri: "https://app.example.com/device",
			issueToken: async (userId) => {
				const decision = await gate.evaluate({ userId, method: "device" });
				if (decision.action !== "allow") throw new SignInGateError(decision);
				const { token } = await sessionManager.create(userId);
				return { accessToken: token };
			},
		});
		const { deviceCode, userCode } = await mod.requestCode();
		await mod.authorize(userCode, "user-1");
		const res = await mod.handleRequest(
			new Request("https://app.example.com/auth/device/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					device_code: deviceCode,
					grant_type: "urn:ietf:params:oauth:grant-type:device_code",
				}),
			}),
		);
		const body = (await res?.json()) as Record<string, unknown>;
		expect(body.twoFactorRequired).toBe(true);
		expect(body.access_token).toBeUndefined();
	});
});
