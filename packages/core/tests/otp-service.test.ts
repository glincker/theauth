/**
 * Tests for the unified OTP service, its senders, and the resend cooldown on
 * the email and phone modules.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createEmailOtpModule } from "../src/auth/email-otp.js";
import { createOtpService, generateOtpCode } from "../src/auth/otp.js";
import type { OtpMessage, OtpSender } from "../src/auth/otp-senders.js";
import { consoleOtpSender, emailOtpSender, twilioOtpSender } from "../src/auth/otp-senders.js";
import { createPhoneAuthModule } from "../src/auth/phone.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createSessionManager } from "../src/session/session.js";

function capture(): { sender: OtpSender; sent: OtpMessage[] } {
	const sent: OtpMessage[] = [];
	return {
		sent,
		sender: {
			async send(m) {
				sent.push(m);
			},
		},
	};
}

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(new Date("2026-10-08T12:00:00Z"));
});

afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
});

describe("generateOtpCode", () => {
	it("returns digits of the requested length", () => {
		for (let i = 0; i < 50; i++) expect(generateOtpCode(8)).toMatch(/^\d{8}$/);
	});
});

describe("createOtpService", () => {
	function setup(extra: Partial<Parameters<typeof createOtpService>[0]> = {}) {
		const email = capture();
		const sms = capture();
		const svc = createOtpService({
			senders: { email: email.sender, sms: sms.sender },
			secret: "s3cret",
			resendCooldownSeconds: 30,
			maxAttempts: 3,
			lockoutSeconds: 600,
			...extra,
		});
		return { svc, email, sms };
	}

	it("sends and verifies a sign-in code, then rejects reuse", async () => {
		const { svc, email } = setup();
		const sent = await svc.send({ purpose: "sign-in", channel: "email", identifier: "a@x.com" });
		expect(sent.success).toBe(true);
		const code = email.sent[0]?.code ?? "";
		expect(code).toMatch(/^\d{6}$/);
		expect((await svc.verify({ purpose: "sign-in", identifier: "A@x.com", code })).success).toBe(
			true,
		);
		const again = await svc.verify({ purpose: "sign-in", identifier: "a@x.com", code });
		expect(again.success).toBe(false);
	});

	it("routes sms to the sms sender", async () => {
		const { svc, sms, email } = setup();
		await svc.send({ purpose: "two-factor", channel: "sms", identifier: "+15550001111" });
		expect(sms.sent).toHaveLength(1);
		expect(email.sent).toHaveLength(0);
	});

	it("scopes codes by purpose", async () => {
		const { svc, email } = setup();
		await svc.send({ purpose: "verify-email", channel: "email", identifier: "a@x.com" });
		const code = email.sent[0]?.code ?? "";
		const wrong = await svc.verify({ purpose: "reset-password", identifier: "a@x.com", code });
		expect(wrong.success).toBe(false);
		const ok = await svc.verify({ purpose: "verify-email", identifier: "a@x.com", code });
		expect(ok.success).toBe(true);
	});

	it("enforces the resend cooldown and reports retryAfter", async () => {
		const { svc } = setup();
		const input = { purpose: "sign-in", channel: "email", identifier: "a@x.com" } as const;
		await svc.send(input);
		const second = await svc.send(input);
		expect(second.success).toBe(false);
		if (!second.success) {
			expect(second.error.code).toBe("OTP_COOLDOWN");
			expect(second.error.details?.retryAfter).toBe(30);
		}
		vi.advanceTimersByTime(31_000);
		expect((await svc.send(input)).success).toBe(true);
	});

	it("locks out after max wrong attempts, even for the right code", async () => {
		const { svc, email } = setup();
		await svc.send({ purpose: "sign-in", channel: "email", identifier: "a@x.com" });
		const code = email.sent[0]?.code ?? "";
		const bad = code === "000000" ? "111111" : "000000";
		for (let i = 0; i < 2; i++) {
			const r = await svc.verify({ purpose: "sign-in", identifier: "a@x.com", code: bad });
			expect(r.success === false && r.error.code).toBe("OTP_INVALID");
		}
		const third = await svc.verify({ purpose: "sign-in", identifier: "a@x.com", code: bad });
		expect(third.success === false && third.error.code).toBe("OTP_LOCKED");
		const right = await svc.verify({ purpose: "sign-in", identifier: "a@x.com", code });
		expect(right.success === false && right.error.code).toBe("OTP_LOCKED");
		const resend = await svc.send({ purpose: "sign-in", channel: "email", identifier: "a@x.com" });
		expect(resend.success === false && resend.error.code).toBe("OTP_LOCKED");
		vi.advanceTimersByTime(601_000);
		expect(
			(await svc.send({ purpose: "sign-in", channel: "email", identifier: "a@x.com" })).success,
		).toBe(true);
	});

	it("expires codes", async () => {
		const { svc, email } = setup({ expiresIn: 60 });
		await svc.send({ purpose: "sign-in", channel: "email", identifier: "a@x.com" });
		vi.advanceTimersByTime(61_000);
		const r = await svc.verify({
			purpose: "sign-in",
			identifier: "a@x.com",
			code: email.sent[0]?.code ?? "",
		});
		expect(r.success).toBe(false);
	});

	it("fails cleanly with no sender for the channel", async () => {
		const svc = createOtpService({ senders: {} });
		const r = await svc.send({ purpose: "sign-in", channel: "sms", identifier: "+1555" });
		expect(r.success === false && r.error.code).toBe("OTP_CHANNEL_UNAVAILABLE");
	});

	it("drops the code and reports OTP_SEND_FAILED when delivery throws", async () => {
		const svc = createOtpService({
			senders: {
				email: {
					async send() {
						throw new Error("boom");
					},
				},
			},
		});
		const input = { purpose: "sign-in", channel: "email", identifier: "a@x.com" } as const;
		const r = await svc.send(input);
		expect(r.success === false && r.error.code).toBe("OTP_SEND_FAILED");
		// No cooldown is left behind by a failed send.
		const retry = await svc.send(input);
		expect(retry.success === false && retry.error.code).toBe("OTP_SEND_FAILED");
	});
});

describe("senders", () => {
	it("emailOtpSender forwards to the email provider", async () => {
		const send = vi.fn(async () => ({ id: "1" }));
		await emailOtpSender({ send }).send({
			channel: "email",
			to: "a@x.com",
			code: "123456",
			purpose: "reset-password",
			expiresInSeconds: 300,
		});
		const arg = send.mock.calls[0] as unknown as [{ to: string; text: string; subject: string }];
		expect(arg[0].to).toBe("a@x.com");
		expect(arg[0].text).toContain("123456");
		expect(arg[0].subject).toContain("password reset");
	});

	it("twilioOtpSender posts a basic-auth form to the Messages endpoint", async () => {
		const fetchMock = vi.fn(async () => new Response("{}", { status: 201 }));
		vi.stubGlobal("fetch", fetchMock);
		await twilioOtpSender({ accountSid: "AC1", authToken: "tok", from: "+15550000000" }).send({
			channel: "sms",
			to: "+15551112222",
			code: "424242",
			purpose: "sign-in",
			expiresInSeconds: 300,
		});
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://api.twilio.com/2010-04-01/Accounts/AC1/Messages.json");
		expect((init.headers as Record<string, string>).Authorization).toBe(`Basic ${btoa("AC1:tok")}`);
		const body = new URLSearchParams(String(init.body));
		expect(body.get("To")).toBe("+15551112222");
		expect(body.get("From")).toBe("+15550000000");
		expect(body.get("Body")).toContain("424242");
	});

	it("twilioOtpSender throws on a non-ok response and validates config", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response("no", { status: 401 })),
		);
		const sender = twilioOtpSender({
			accountSid: "AC1",
			authToken: "t",
			messagingServiceSid: "MG1",
		});
		await expect(
			sender.send({
				channel: "sms",
				to: "+1",
				code: "1",
				purpose: "sign-in",
				expiresInSeconds: 60,
			}),
		).rejects.toThrow(/401/);
		expect(() => twilioOtpSender({ accountSid: "AC1", authToken: "t" })).toThrow(/from/);
	});

	it("consoleOtpSender logs the code", async () => {
		const lines: string[] = [];
		await consoleOtpSender((l) => lines.push(l)).send({
			channel: "email",
			to: "a@x.com",
			code: "999999",
			purpose: "sign-in",
			expiresInSeconds: 60,
		});
		expect(lines[0]).toContain("999999");
	});
});

describe("resendCooldownSeconds on existing modules", () => {
	async function dbAndSessions() {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const sessions = createSessionManager(
			{ secret: "test-session-secret-that-is-at-least-32-chars!!" },
			db,
		);
		return { db, sessions };
	}

	it("email otp: second send inside the window is refused with 429", async () => {
		const { db, sessions } = await dbAndSessions();
		const sendOtp = vi.fn(async () => undefined);
		const mod = createEmailOtpModule({ sendOtp, resendCooldownSeconds: 60 }, db, sessions);
		expect((await mod.sendCode("a@x.com")).sent).toBe(true);
		const second = await mod.sendCode("a@x.com");
		expect(second.sent).toBe(false);
		expect(second.retryAfter).toBeGreaterThan(0);
		expect(sendOtp).toHaveBeenCalledOnce();
		const res = await mod.handleRequest(
			new Request("http://x/auth/otp/send", {
				method: "POST",
				body: JSON.stringify({ email: "a@x.com" }),
			}),
		);
		expect(res?.status).toBe(429);
		expect(res?.headers.get("Retry-After")).toBeTruthy();
	});

	it("phone: second send inside the window is refused", async () => {
		const { db, sessions } = await dbAndSessions();
		const sendSms = vi.fn(async () => undefined);
		const mod = createPhoneAuthModule({ sendSms, resendCooldownSeconds: 60 }, db, sessions);
		expect((await mod.sendCode("+15551112222")).sent).toBe(true);
		expect((await mod.sendCode("+15551112222")).sent).toBe(false);
		expect(sendSms).toHaveBeenCalledOnce();
	});
});
