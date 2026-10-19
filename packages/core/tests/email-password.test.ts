/**
 * Email and password sign-in through the real HTTP handler, with no browser:
 * sign up, verify, sign in, read the session, change the password, sign out, reset.
 */
import { describe, expect, it } from "vitest";
import { LoginLockedError } from "../src/auth/login-lockout.js";
import { createTheAuthHandler } from "../src/http/index.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const BASE = "http://localhost/api/theauth";

interface Mail {
	email: string;
	token: string;
}

async function setup(opts: { requireVerification?: boolean; lockout?: false } = {}) {
	const verifications: Mail[] = [];
	const resets: Mail[] = [];
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		auth: { session: { secret: SECRET } },
		emailVerification: {
			sendVerificationEmail: async (email, token) => {
				verifications.push({ email, token });
			},
			verifyUrl: "https://app.example.com/verify",
		},
		passwordReset: {
			sendResetEmail: async (email, token) => {
				resets.push({ email, token });
			},
			resetUrl: "https://app.example.com/reset",
		},
		emailPassword: {
			requireVerification: opts.requireVerification,
			...(opts.lockout === false && { lockout: false as const }),
		},
	});
	const handler = createTheAuthHandler(theauth, { basePath: "/api/theauth" });
	const call = async (
		method: string,
		path: string,
		body?: unknown,
		headers: Record<string, string> = {},
	) => {
		const res = await handler(
			new Request(`${BASE}${path}`, {
				method,
				headers: { "content-type": "application/json", ...headers },
				...(body !== undefined && { body: JSON.stringify(body) }),
			}),
		);
		const text = await res.text();
		return {
			status: res.status,
			json: text ? (JSON.parse(text) as Record<string, any>) : null,
			cookie: res.headers.get("set-cookie"),
		};
	};
	return { theauth, call, verifications, resets };
}

const PASSWORD = "correct horse battery";

describe("email and password flow", () => {
	it("signs up, verifies, signs in, reads the session and signs out", async () => {
		const { call, verifications } = await setup();

		const up = await call("POST", "/auth/email/sign-up", {
			email: "Ada@Example.com",
			password: PASSWORD,
			name: "Ada",
		});
		expect(up.status).toBe(201);
		expect(up.json).toEqual({ verificationRequired: true });
		expect(up.cookie).toBeNull();
		expect(verifications).toHaveLength(1);
		expect(verifications[0]?.email).toBe("ada@example.com");

		const early = await call("POST", "/auth/email/sign-in", {
			email: "ada@example.com",
			password: PASSWORD,
		});
		expect(early.status).toBe(403);
		expect(early.json?.error.code).toBe("EMAIL_NOT_VERIFIED");
		expect(early.cookie).toBeNull();

		const verified = await call("POST", "/auth/email/verify", { token: verifications[0]?.token });
		expect(verified.status).toBe(200);
		expect(verified.json?.user).toMatchObject({ email: "ada@example.com", emailVerified: true });
		const replay = await call("POST", "/auth/email/verify", { token: verifications[0]?.token });
		expect(replay.status).toBe(400);

		const wrong = await call("POST", "/auth/email/sign-in", {
			email: "ada@example.com",
			password: "not the password",
		});
		expect(wrong.status).toBe(401);
		expect(wrong.json?.error.code).toBe("INVALID_CREDENTIALS");

		const inn = await call("POST", "/auth/email/sign-in", {
			email: "ADA@example.com",
			password: PASSWORD,
		});
		expect(inn.status).toBe(200);
		expect(inn.json?.user).toMatchObject({ email: "ada@example.com", name: "Ada" });
		const token = inn.json?.session.token as string;
		expect(token).toBeTruthy();
		expect(inn.cookie).toContain("theauth_session=");
		expect(inn.cookie).toContain("HttpOnly");

		const viaBearer = await call("GET", "/auth/session", undefined, {
			authorization: `Bearer ${token}`,
		});
		expect(viaBearer.status).toBe(200);
		expect(viaBearer.json?.user.email).toBe("ada@example.com");
		const viaCookie = await call("GET", "/auth/session", undefined, {
			cookie: `theauth_session=${token}`,
		});
		expect(viaCookie.status).toBe(200);

		const out = await call("POST", "/auth/sign-out", undefined, {
			authorization: `Bearer ${token}`,
		});
		expect(out.status).toBe(200);
		const after = await call("GET", "/auth/session", undefined, {
			authorization: `Bearer ${token}`,
		});
		expect(after.status).toBe(401);
	});

	it("answers a sign-up for a taken address like a new one and never attaches a password", async () => {
		const { theauth, call, verifications } = await setup();
		await theauth.user.create({ id: "oauth-user", email: "oauth@example.com", name: "O" });

		const taken = await call("POST", "/auth/email/sign-up", {
			email: "oauth@example.com",
			password: "attacker password 1",
		});
		expect(taken.status).toBe(201);
		expect(taken.json).toEqual({ verificationRequired: true });
		// The existing user has no password account, so no message and no credential.
		expect(verifications).toHaveLength(0);
		const sign = await call("POST", "/auth/email/sign-in", {
			email: "oauth@example.com",
			password: "attacker password 1",
		});
		expect(sign.status).toBe(401);

		// An unverified password account gets a new message, and its password stays.
		await call("POST", "/auth/email/sign-up", { email: "new@example.com", password: PASSWORD });
		const again = await call("POST", "/auth/email/sign-up", {
			email: "new@example.com",
			password: "attacker password 2",
		});
		expect(again.json).toEqual({ verificationRequired: true });
		expect(verifications.map((v) => v.email)).toEqual(["new@example.com", "new@example.com"]);
		await call("POST", "/auth/email/verify", { token: verifications[1]?.token });
		const attacker = await call("POST", "/auth/email/sign-in", {
			email: "new@example.com",
			password: "attacker password 2",
		});
		expect(attacker.status).toBe(401);
		const owner = await call("POST", "/auth/email/sign-in", {
			email: "new@example.com",
			password: PASSWORD,
		});
		expect(owner.status).toBe(200);
	});

	it("resends verification without revealing whether the address exists", async () => {
		const { call, verifications } = await setup();
		await call("POST", "/auth/email/sign-up", { email: "a@example.com", password: PASSWORD });
		const known = await call("POST", "/auth/email/resend-verification", { email: "a@example.com" });
		const unknown = await call("POST", "/auth/email/resend-verification", {
			email: "x@example.com",
		});
		expect(known.status).toBe(204);
		expect(unknown.status).toBe(204);
		expect(verifications.map((v) => v.email)).toEqual(["a@example.com", "a@example.com"]);
	});

	it("validates the email and the password", async () => {
		const { call } = await setup();
		const bad = await call("POST", "/auth/email/sign-up", { email: "nope", password: PASSWORD });
		expect(bad.status).toBe(400);
		expect(bad.json?.error.code).toBe("INVALID_EMAIL");
		const short = await call("POST", "/auth/email/sign-up", {
			email: "a@example.com",
			password: "short",
		});
		expect(short.status).toBe(400);
		expect(short.json?.error.code).toBe("INVALID_PASSWORD");
		const empty = await call("POST", "/auth/email/sign-in", {});
		expect(empty.status).toBe(401);
	});

	it("changes the password for the signed-in user only", async () => {
		const { call, verifications } = await setup();
		await call("POST", "/auth/email/sign-up", { email: "a@example.com", password: PASSWORD });
		await call("POST", "/auth/email/verify", { token: verifications[0]?.token });
		const inn = await call("POST", "/auth/email/sign-in", {
			email: "a@example.com",
			password: PASSWORD,
		});
		const auth = { authorization: `Bearer ${inn.json?.session.token}` };

		const anon = await call("POST", "/auth/email/change-password", {
			current: PASSWORD,
			newPassword: "a brand new password",
		});
		expect(anon.status).toBe(401);
		const wrong = await call(
			"POST",
			"/auth/email/change-password",
			{ current: "wrong wrong wrong", newPassword: "a brand new password" },
			auth,
		);
		expect(wrong.status).toBe(400);
		const ok = await call(
			"POST",
			"/auth/email/change-password",
			{ current: PASSWORD, newPassword: "a brand new password" },
			auth,
		);
		expect(ok.status).toBe(200);

		const old = await call("POST", "/auth/email/sign-in", {
			email: "a@example.com",
			password: PASSWORD,
		});
		expect(old.status).toBe(401);
		const fresh = await call("POST", "/auth/email/sign-in", {
			email: "a@example.com",
			password: "a brand new password",
		});
		expect(fresh.status).toBe(200);
	});

	it("resets a forgotten password and counts the address as verified", async () => {
		const { call, resets } = await setup();
		await call("POST", "/auth/email/sign-up", { email: "a@example.com", password: PASSWORD });

		const unknown = await call("POST", "/auth/email/forgot-password", {
			email: "none@example.com",
		});
		expect(unknown.status).toBe(204);
		expect(resets).toHaveLength(0);
		const forgot = await call("POST", "/auth/email/forgot-password", { email: "a@example.com" });
		expect(forgot.status).toBe(204);
		expect(resets).toHaveLength(1);

		const weak = await call("POST", "/auth/email/reset-password", {
			token: resets[0]?.token,
			password: "x",
		});
		expect(weak.status).toBe(400);
		const reset = await call("POST", "/auth/email/reset-password", {
			token: resets[0]?.token,
			password: "a brand new password",
		});
		expect(reset.status).toBe(200);
		const used = await call("POST", "/auth/email/reset-password", {
			token: resets[0]?.token,
			password: "another new password",
		});
		expect(used.status).toBe(400);

		// The reset proved the inbox, so sign-in works without the verification link.
		const inn = await call("POST", "/auth/email/sign-in", {
			email: "a@example.com",
			password: "a brand new password",
		});
		expect(inn.status).toBe(200);
	});

	it("locks the account after repeated failures", async () => {
		const { theauth, call } = await setup();
		await call("POST", "/auth/email/sign-up", { email: "a@example.com", password: PASSWORD });
		const attempt = () =>
			theauth.emailPassword?.signIn({ email: "a@example.com", password: "wrong password!" });
		for (let i = 0; i < 10; i++)
			await expect(attempt()).rejects.toThrow(/Invalid email or password/);
		await expect(attempt()).rejects.toBeInstanceOf(LoginLockedError);
	});

	it("rate limits the sign-in route per client", async () => {
		const { call } = await setup();
		let last = 0;
		for (let i = 0; i < 12; i++) {
			last = (await call("POST", "/auth/email/sign-in", { email: "a@example.com", password: "x" }))
				.status;
		}
		expect(last).toBe(429);
	});

	it("issues a session at sign-up when verification is off, and refuses a taken address", async () => {
		const { call } = await setup({ requireVerification: false });
		const up = await call("POST", "/auth/email/sign-up", {
			email: "a@example.com",
			password: PASSWORD,
		});
		expect(up.status).toBe(201);
		expect(up.json?.user).toMatchObject({ email: "a@example.com", emailVerified: false });
		expect(up.cookie).toContain("theauth_session=");
		const session = await call("GET", "/auth/session", undefined, {
			authorization: `Bearer ${up.json?.session.token}`,
		});
		expect(session.status).toBe(200);
		const dup = await call("POST", "/auth/email/sign-up", {
			email: "a@example.com",
			password: PASSWORD,
		});
		expect(dup.status).toBe(409);
		expect(dup.json?.error.code).toBe("EMAIL_TAKEN");
		const inn = await call("POST", "/auth/email/sign-in", {
			email: "a@example.com",
			password: PASSWORD,
		});
		expect(inn.status).toBe(200);
	});

	it("does not accept a username account as an email credential", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			username: { allowedPattern: /^[a-z0-9:@._-]+$/i, maxUsernameLength: 64 },
			emailPassword: { requireVerification: false },
		});
		const handler = createTheAuthHandler(theauth, { basePath: "/api/theauth" });
		// A username shaped like an email credential key must not sign in as that address.
		await theauth.username?.signUp({
			username: "email:victim@example.com",
			password: "attacker password",
		});
		const res = await handler(
			new Request(`${BASE}/auth/email/sign-in`, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ email: "victim@example.com", password: "attacker password" }),
			}),
		);
		expect(res.status).toBe(401);
	});

	it("refuses to start with verification on and no way to send it", async () => {
		await expect(
			createTheAuth({
				database: { provider: "sqlite", url: ":memory:" },
				auth: { session: { secret: SECRET } },
				emailPassword: {},
			}),
		).rejects.toThrow(/emailVerification/);
	});
});
