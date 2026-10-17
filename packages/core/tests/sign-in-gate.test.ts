/** Tests for the central sign-in gate, its routes, and the session limit. */

import { createHmac } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import type { SignInGate, TwoFactorFactor } from "../src/auth/sign-in-gate.js";
import { createSignInGate, evaluateSignInGate, SignInGateError } from "../src/auth/sign-in-gate.js";
import { createTotpModule } from "../src/auth/totp.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { magicLinks, sessions, users } from "../src/db/schema.js";
import { MultiSessionLimitError } from "../src/session/multi-session.js";
import { createSessionManager } from "../src/session/session.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function addUser(db: Database, id: string, extra: { forcePasswordReset?: number } = {}) {
	const now = new Date();
	await db.insert(users).values({
		id,
		email: `${id}@example.com`,
		createdAt: now,
		updatedAt: now,
		...extra,
	});
}

/** A fake factor whose valid code is "123456" for enabled users. */
function fakeFactor(enabledFor: string[]): TwoFactorFactor {
	return {
		id: "fake",
		isEnabled: async (userId) => enabledFor.includes(userId),
		verify: async (_userId, code) => code === "123456",
	};
}

function totpCode(secret: string): string {
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of secret) {
		value = (value << 5) | BASE32.indexOf(ch);
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
	}
	const counter = Math.floor(Date.now() / 1000 / 30);
	const buf = Buffer.alloc(8);
	buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
	buf.writeUInt32BE(counter >>> 0, 4);
	const digest = createHmac("sha1", Buffer.from(out)).update(buf).digest();
	const offset = (digest[19] ?? 0) & 0xf;
	const bin =
		(((digest[offset] ?? 0) & 0x7f) << 24) |
		(((digest[offset + 1] ?? 0) & 0xff) << 16) |
		(((digest[offset + 2] ?? 0) & 0xff) << 8) |
		((digest[offset + 3] ?? 0) & 0xff);
	return String(bin % 1_000_000).padStart(6, "0");
}

describe("evaluateSignInGate (pure)", () => {
	const base = {
		user: { id: "u", mustChangePassword: false },
		method: "password" as const,
		policy: { require2faFor: ["password" as const] },
		hasPasswordCredential: true,
		enabledFactors: ["totp"],
		deviceTrusted: false,
	};

	it("requires 2FA for listed methods with an enabled factor", () => {
		expect(evaluateSignInGate(base)).toBe("two_factor_required");
	});

	it("allows methods not in the policy", () => {
		expect(evaluateSignInGate({ ...base, method: "social" })).toBe("allow");
	});

	it("allows when no factor is enabled or the device is trusted", () => {
		expect(evaluateSignInGate({ ...base, enabledFactors: [] })).toBe("allow");
		expect(evaluateSignInGate({ ...base, deviceTrusted: true })).toBe("allow");
	});

	it("forced password change wins over 2FA", () => {
		const user = { id: "u", mustChangePassword: true };
		expect(evaluateSignInGate({ ...base, user })).toBe("password_change_required");
	});

	it("does not lock out users without a password credential", () => {
		const user = { id: "u", mustChangePassword: true };
		expect(
			evaluateSignInGate({ ...base, user, hasPasswordCredential: false, method: "social" }),
		).toBe("allow");
	});
});

describe("SignInGate", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	function gateWith(factorUsers: string[], overrides: object = {}): SignInGate {
		return createSignInGate({
			db,
			sessionSecret: SECRET,
			config: { factors: [fakeFactor(factorUsers)], ...overrides },
		});
	}

	it("allows by default with no policy", async () => {
		await addUser(db, "u1");
		const gate = createSignInGate({ db, sessionSecret: SECRET });
		expect(await gate.evaluate({ userId: "u1", method: "password" })).toEqual({ action: "allow" });
	});

	it("without config the 2FA policy is empty even for enrolled users", async () => {
		await addUser(db, "u1");
		const gate = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: undefined,
			totp: createTotpModule({}, db),
		});
		expect((await gate.evaluate({ userId: "u1", method: "password" })).action).toBe("allow");
	});

	it("applies 2FA by method and honours require2faFor", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"], { require2faFor: ["password", "passkey"] });
		expect((await gate.evaluate({ userId: "u1", method: "password" })).action).toBe(
			"two_factor_required",
		);
		expect((await gate.evaluate({ userId: "u1", method: "passkey" })).action).toBe(
			"two_factor_required",
		);
		expect((await gate.evaluate({ userId: "u1", method: "social" })).action).toBe("allow");
	});

	it("default policy when configured covers password, social and magic_link", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"]);
		for (const method of ["password", "social", "magic_link"] as const) {
			expect((await gate.evaluate({ userId: "u1", method })).action).toBe("two_factor_required");
		}
		expect((await gate.evaluate({ userId: "u1", method: "passkey" })).action).toBe("allow");
	});

	it("completes a challenge with a valid code and rejects bad or replayed ones", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"]);
		const decision = await gate.evaluate({ userId: "u1", method: "social" });
		if (decision.action !== "two_factor_required") throw new Error("expected 2fa");

		const bad = await gate.completeTwoFactor({ challenge: decision.challenge, code: "000000" });
		expect(bad).toEqual({ ok: false, reason: "invalid_code" });

		const last = decision.challenge.slice(-1);
		const tampered = `${decision.challenge.slice(0, -1)}${last === "0" ? "1" : "0"}`;
		expect(await gate.completeTwoFactor({ challenge: tampered, code: "123456" })).toEqual({
			ok: false,
			reason: "invalid_challenge",
		});

		const ok = await gate.completeTwoFactor({ challenge: decision.challenge, code: "123456" });
		expect(ok).toMatchObject({ ok: true, userId: "u1", method: "social" });

		const replay = await gate.completeTwoFactor({ challenge: decision.challenge, code: "123456" });
		expect(replay).toEqual({ ok: false, reason: "invalid_challenge" });
	});

	it("locks a challenge after too many wrong codes", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"], { maxChallengeAttempts: 2 });
		const decision = await gate.evaluate({ userId: "u1", method: "password" });
		if (decision.action !== "two_factor_required") throw new Error("expected 2fa");
		await gate.completeTwoFactor({ challenge: decision.challenge, code: "1" });
		await gate.completeTwoFactor({ challenge: decision.challenge, code: "2" });
		const locked = await gate.completeTwoFactor({ challenge: decision.challenge, code: "123456" });
		expect(locked).toEqual({ ok: false, reason: "too_many_attempts" });
	});

	it("rejects an expired challenge", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"], { challengeTtlSeconds: -5 });
		const decision = await gate.evaluate({ userId: "u1", method: "password" });
		if (decision.action !== "two_factor_required") throw new Error("expected 2fa");
		const result = await gate.completeTwoFactor({ challenge: decision.challenge, code: "123456" });
		expect(result).toEqual({ ok: false, reason: "invalid_challenge" });
	});

	it("does not issue trusted devices unless enabled", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"]);
		const d = await gate.evaluate({ userId: "u1", method: "password" });
		if (d.action !== "two_factor_required") throw new Error("expected 2fa");
		const r = await gate.completeTwoFactor({
			challenge: d.challenge,
			code: "123456",
			trustDevice: true,
		});
		expect(r.ok && r.trustedDeviceCookie).toBeFalsy();
	});

	it("skips 2FA on a trusted device and revokes on password change", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"], { trustedDevice: { enabled: true } });
		const d = await gate.evaluate({ userId: "u1", method: "password" });
		if (d.action !== "two_factor_required") throw new Error("expected 2fa");
		const r = await gate.completeTwoFactor({
			challenge: d.challenge,
			code: "123456",
			trustDevice: true,
		});
		if (!r.ok || !r.trustedDeviceCookie) throw new Error("expected cookie");
		const cookie = r.trustedDeviceCookie;

		const withCookie = new Request("http://localhost/x", {
			headers: { cookie: `${cookie.name}=${cookie.value}` },
		});
		expect(
			(await gate.evaluate({ userId: "u1", method: "password", request: withCookie })).action,
		).toBe("allow");

		// A different user cannot reuse the cookie.
		await addUser(db, "u2");
		const gate2 = gateWith(["u1", "u2"], { trustedDevice: { enabled: true } });
		expect(
			(await gate2.evaluate({ userId: "u2", method: "password", request: withCookie })).action,
		).toBe("two_factor_required");

		expect((await gate.listTrustedDevices("u1")).length).toBe(1);
		await gate.onPasswordChanged("u1");
		expect((await gate.listTrustedDevices("u1")).length).toBe(0);
		expect(
			(await gate.evaluate({ userId: "u1", method: "password", request: withCookie })).action,
		).toBe("two_factor_required");
	});

	it("revokes a single trusted device by id", async () => {
		await addUser(db, "u1");
		const gate = gateWith(["u1"], { trustedDevice: { enabled: true } });
		const d = await gate.evaluate({ userId: "u1", method: "password" });
		if (d.action !== "two_factor_required") throw new Error("expected 2fa");
		await gate.completeTwoFactor({ challenge: d.challenge, code: "123456", trustDevice: true });
		const [device] = await gate.listTrustedDevices("u1");
		expect(device).toBeDefined();
		expect(await gate.revokeTrustedDevice("u1", device?.id ?? "")).toBe(true);
		expect(await gate.revokeTrustedDevice("u1", "nope")).toBe(false);
		expect((await gate.listTrustedDevices("u1")).length).toBe(0);
	});
});

describe("username sign-in through the gate", () => {
	let db: Database;
	let gate: SignInGate;

	beforeEach(async () => {
		db = await createTestDb();
		gate = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: { factors: [] },
		});
	});

	function make(g: SignInGate = gate) {
		const sm = createSessionManager({ secret: SECRET }, db);
		return createUsernameAuthModule({}, db, sm, g);
	}

	it("forced change returns a challenge that completes the flow", async () => {
		const mod = make();
		const { user } = await mod.signUp({ username: "alice", password: "Password1!" });
		await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, user.id));

		let caught: unknown;
		try {
			await mod.signIn({ username: "alice", password: "Password1!" });
		} catch (err) {
			caught = err;
		}
		expect(caught).toBeInstanceOf(SignInGateError);
		const decision = (caught as SignInGateError).decision;
		if (decision.action !== "password_change_required") throw new Error("expected change");

		const done = await gate.completePasswordChange({
			challenge: decision.challenge,
			newPassword: "NewPassword2!",
		});
		expect(done).toMatchObject({ ok: true, userId: user.id, next: { action: "allow" } });

		const rows = await db.select().from(users).where(eq(users.id, user.id));
		expect(rows[0]?.forcePasswordReset).toBe(0);
		const signedIn = await mod.signIn({ username: "alice", password: "NewPassword2!" });
		expect(signedIn.session.token).toBeTruthy();
	});

	it("rejects a weak new password without consuming the challenge", async () => {
		const mod = make();
		const { user } = await mod.signUp({ username: "bob", password: "Password1!" });
		await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, user.id));
		const err = await mod.signIn({ username: "bob", password: "Password1!" }).catch((e) => e);
		const decision = (err as SignInGateError).decision;
		if (decision.action !== "password_change_required") throw new Error("expected change");

		const weak = await gate.completePasswordChange({
			challenge: decision.challenge,
			newPassword: "x",
		});
		expect(weak).toMatchObject({ ok: false, reason: "rejected" });
		const good = await gate.completePasswordChange({
			challenge: decision.challenge,
			newPassword: "LongEnough3!",
		});
		expect(good.ok).toBe(true);
	});

	it("username password change revokes trusted devices", async () => {
		let enabled: string[] = [];
		const g = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: {
				trustedDevice: { enabled: true },
				factors: [
					{
						id: "fake",
						isEnabled: async (id) => enabled.includes(id),
						verify: async (_id, code) => code === "123456",
					},
				],
			},
		});
		const mod = make(g);
		const { user } = await mod.signUp({ username: "carol", password: "Password1!" });
		enabled = [user.id];

		const d = await g.evaluate({ userId: user.id, method: "password" });
		if (d.action !== "two_factor_required") throw new Error("expected 2fa");
		await g.completeTwoFactor({ challenge: d.challenge, code: "123456", trustDevice: true });
		expect((await g.listTrustedDevices(user.id)).length).toBe(1);

		await mod.changePassword(user.id, "Password1!", "Another-pass2");
		expect((await g.listTrustedDevices(user.id)).length).toBe(0);
	});

	it("after a forced change the gate still demands 2FA", async () => {
		const g = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: { factors: [fakeFactor(["__pending__"])] },
		});
		const mod = make(g);
		const { user } = await mod.signUp({ username: "dave", password: "Password1!" });
		const g2 = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: { factors: [fakeFactor([user.id])] },
		});
		const mod2 = make(g2);
		await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, user.id));
		const err = await mod2.signIn({ username: "dave", password: "Password1!" }).catch((e) => e);
		const decision = (err as SignInGateError).decision;
		if (decision.action !== "password_change_required") throw new Error("expected change");
		const done = await g2.completePasswordChange({
			challenge: decision.challenge,
			newPassword: "BrandNew4!pw",
		});
		expect(done).toMatchObject({ ok: true, next: { action: "two_factor_required" } });
	});

	it("requires a real TOTP code end to end", async () => {
		const totp = createTotpModule({}, db);
		const g = createSignInGate({ db, sessionSecret: SECRET, config: {}, totp });
		const mod = make(g);
		const { user } = await mod.signUp({ username: "erin", password: "Password1!" });
		const setup = await totp.setup(user.id);
		expect((await totp.enable(user.id, totpCode(setup.secret))).enabled).toBe(true);

		const err = await mod.signIn({ username: "erin", password: "Password1!" }).catch((e) => e);
		expect(err).toBeInstanceOf(SignInGateError);
		const decision = (err as SignInGateError).decision;
		if (decision.action !== "two_factor_required") throw new Error("expected 2fa");
		expect(decision.methods).toEqual(["totp"]);

		const done = await g.completeTwoFactor({
			challenge: decision.challenge,
			code: totpCode(setup.secret),
		});
		expect(done).toMatchObject({ ok: true, userId: user.id, method: "password" });
	});
});

describe("magic link through the gate", () => {
	it("throws a gate error carrying the challenge when 2FA is required", async () => {
		const db = await createTestDb();
		const sm = createSessionManager({ secret: SECRET }, db);
		const gate = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: { factors: [] },
		});
		await addUser(db, "ml-user");
		const gate2 = createSignInGate({
			db,
			sessionSecret: SECRET,
			config: { factors: [fakeFactor(["ml-user"])] },
		});
		void gate;
		const mod = createMagicLinkModule(
			{ appUrl: "http://localhost", sendMagicLink: async () => {} },
			db,
			sm,
			gate2,
		);
		await db.insert(magicLinks).values({
			id: "ml1",
			email: "ml-user@example.com",
			token: "tok-1",
			expiresAt: new Date(Date.now() + 60_000),
			used: false,
			createdAt: new Date(),
		});
		const err = await mod.verify("tok-1").catch((e) => e);
		expect(err).toBeInstanceOf(SignInGateError);
		expect((err as SignInGateError).decision.action).toBe("two_factor_required");
	});
});

describe("session.maxConcurrent", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await addUser(db, "u1");
		await addUser(db, "u2");
	});

	it("is unlimited by default", async () => {
		const sm = createSessionManager({ secret: SECRET }, db);
		for (let i = 0; i < 4; i++) await sm.create("u1");
		expect((await sm.list("u1")).length).toBe(4);
	});

	it("evicts the oldest session by default", async () => {
		const sm = createSessionManager({ secret: SECRET, maxConcurrent: 2 }, db);
		const first = await sm.create("u1");
		await new Promise((r) => setTimeout(r, 5));
		const second = await sm.create("u1");
		await new Promise((r) => setTimeout(r, 5));
		const third = await sm.create("u1");

		expect(await sm.validate(first.token)).toBeNull();
		expect(await sm.validate(second.token)).not.toBeNull();
		expect(await sm.validate(third.token)).not.toBeNull();
		expect((await sm.list("u1")).length).toBe(2);
	});

	it("rejects with MultiSessionLimitError when onLimit is reject", async () => {
		const sm = createSessionManager({ secret: SECRET, maxConcurrent: 1, onLimit: "reject" }, db);
		await sm.create("u1");
		await expect(sm.create("u1")).rejects.toBeInstanceOf(MultiSessionLimitError);
		expect((await sm.list("u1")).length).toBe(1);
		// Other users are unaffected.
		await expect(sm.create("u2")).resolves.toBeDefined();
	});

	it("ignores expired sessions when counting", async () => {
		const sm = createSessionManager({ secret: SECRET, maxConcurrent: 1, onLimit: "reject" }, db);
		const old = await sm.create("u1");
		await db
			.update(sessions)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(sessions.id, old.session.id));
		await expect(sm.create("u1")).resolves.toBeDefined();
	});

	it("does not limit impersonation sessions", async () => {
		const sm = createSessionManager({ secret: SECRET, maxConcurrent: 1, onLimit: "reject" }, db);
		await sm.create("u1");
		await expect(sm.create("u1", { sessionType: "impersonation" })).resolves.toBeDefined();
	});

	it("reports revoked sessions to onRevoke and survives hook errors", async () => {
		const seen: string[] = [];
		const sm = createSessionManager(
			{
				secret: SECRET,
				onRevoke: async (revoked) => {
					for (const s of revoked) seen.push(s.id);
					throw new Error("boom");
				},
			},
			db,
		);
		const a = await sm.create("u1");
		await sm.revoke(a.session.id);
		expect(seen).toEqual([a.session.id]);
		expect(await sm.validate(a.token)).toBeNull();
	});
});

describe("gate routes via createTheAuth", () => {
	it("completes password change then 2FA through HTTP routes", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			username: {},
			signInGate: { trustedDevice: { enabled: true } },
			totp: {},
		});
		const username = theauth.username;
		if (!username) throw new Error("username module missing");
		const { user } = await username.signUp({ username: "frank", password: "Password1!" });

		const totp = theauth.totp;
		if (!totp) throw new Error("totp module missing");
		const setup = await totp.setup(user.id);
		await totp.enable(user.id, totpCode(setup.secret));
		await theauth.db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, user.id));

		const post = (path: string, body: unknown) =>
			theauth.plugins.handleRequest(
				new Request(`http://localhost${path}`, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				}),
			);

		const signIn = await username.handleRequest(
			new Request("http://localhost/auth/username/sign-in", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ username: "frank", password: "Password1!" }),
			}),
		);
		expect(signIn?.status).toBe(403);
		const change = (await signIn?.json()) as { challenge: string };

		const changed = await post("/auth/sign-in/password-change", {
			challenge: change.challenge,
			newPassword: "Rotated5!pass",
		});
		expect(changed?.status).toBe(200);
		const twoFa = (await changed?.json()) as { twoFactorRequired: boolean; challenge: string };
		expect(twoFa.twoFactorRequired).toBe(true);

		const done = await post("/auth/sign-in/two-factor", {
			challenge: twoFa.challenge,
			code: totpCode(setup.secret),
			trustDevice: true,
		});
		expect(done?.status).toBe(200);
		const cookies = done?.headers.getSetCookie() ?? [];
		expect(cookies.some((c) => c.startsWith("theauth_session="))).toBe(true);
		expect(cookies.some((c) => c.startsWith("theauth_trusted_device="))).toBe(true);
		const payload = (await done?.json()) as { session: { token: string } };
		expect(payload.session.token).toBeTruthy();
	});
});
