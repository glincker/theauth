/**
 * Sign-in paths record how the user proved themselves, and a signed-in user can step up by proving a
 * TOTP code again (RFC 9470 session side).
 */

import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { twoFactor } from "../src/auth/totp-plugin.js";
import { ACR } from "../src/session/auth-context.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

async function boot() {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		auth: { session: { secret: SECRET } },
		username: {},
		totp: {},
		signInGate: { require2faFor: ["password"] },
		plugins: [twoFactor()],
	});
	const username = theauth.username;
	const totp = theauth.totp;
	const sessions = theauth.auth.session;
	if (!username || !totp || !sessions) throw new Error("modules missing");
	return { theauth, username, totp, sessions };
}

const postJson = (path: string, body: unknown, token?: string) =>
	new Request(`http://localhost${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			...(token ? { authorization: `Bearer ${token}` } : {}),
		},
		body: JSON.stringify(body),
	});

describe("sign-in records authentication methods", () => {
	it("marks a password sign-in as single factor", async () => {
		const { username, sessions } = await boot();
		await username.signUp({ username: "gina", password: "Password1!" });
		const signedIn = await username.signIn({ username: "gina", password: "Password1!" });
		const session = await sessions.validate(signedIn.session.token);
		expect(session?.auth?.amr).toEqual(["pwd"]);
		expect(session?.auth?.acr).toBe(ACR.singleFactor);
	});

	it("marks password plus a TOTP code on the sign-in gate as multi factor", async () => {
		const { theauth, username, totp, sessions } = await boot();
		const { user } = await username.signUp({ username: "hank", password: "Password1!" });
		const setup = await totp.setup(user.id);
		await totp.enable(user.id, totpCode(setup.secret));

		const signIn = await username.handleRequest(
			postJson("/auth/username/sign-in", { username: "hank", password: "Password1!" }),
		);
		const gate = (await signIn?.json()) as { twoFactorRequired?: boolean; challenge: string };
		expect(gate.twoFactorRequired).toBe(true);
		const { challenge } = gate;
		const done = await theauth.plugins.handleRequest(
			postJson("/auth/sign-in/two-factor", { challenge, code: totpCode(setup.secret) }),
		);
		expect(done?.status).toBe(200);
		const { session: issued } = (await done?.json()) as { session: { token: string } };
		const session = await sessions.validate(issued.token);
		expect(session?.auth?.acr).toBe(ACR.mfa);
		expect(session?.auth?.amr).toEqual(["mfa", "otp", "pwd"]);
	});
});

describe("stepping up a signed-in session with /auth/2fa/verify", () => {
	it("raises acr to multi factor and refreshes auth_time after a correct code", async () => {
		const { theauth, username, totp, sessions } = await boot();
		const { user } = await username.signUp({ username: "iris", password: "Password1!" });
		const setup = await totp.setup(user.id);
		await totp.enable(user.id, totpCode(setup.secret));
		// A session created before any second factor: password only.
		const { session, token } = await sessions.create(user.id, undefined, {
			authMethods: ["password"],
		});
		expect(session.auth?.acr).toBe(ACR.singleFactor);

		const before = Math.floor(Date.now() / 1000);
		const res = await theauth.plugins.handleRequest(
			postJson("/auth/2fa/verify", { code: totpCode(setup.secret) }, token),
		);
		expect(res?.status).toBe(200);
		expect(((await res?.json()) as { valid: boolean }).valid).toBe(true);

		const after = await sessions.validate(token);
		expect(after?.auth?.acr).toBe(ACR.mfa);
		expect(after?.auth?.authTime).toBeGreaterThanOrEqual(before);
	});

	it("records nothing for a wrong code", async () => {
		const { theauth, username, totp, sessions } = await boot();
		const { user } = await username.signUp({ username: "jack", password: "Password1!" });
		const setup = await totp.setup(user.id);
		await totp.enable(user.id, totpCode(setup.secret));
		const { token } = await sessions.create(user.id, undefined, { authMethods: ["password"] });
		const res = await theauth.plugins.handleRequest(
			postJson("/auth/2fa/verify", { code: "000000" }, token),
		);
		expect(((await res?.json()) as { valid: boolean }).valid).toBe(false);
		expect((await sessions.validate(token))?.auth?.acr).toBe(ACR.singleFactor);
	});
});
