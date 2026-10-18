/**
 * Step-up follow-ups: passkey re-authentication on the CURRENT session, social sign-in recording
 * `fed` (plus the provider's amr hints), and the headless totp and passkey handlers recording
 * a step up.
 */

import { createHmac } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { oauth } from "../src/auth/oauth/plugin.js";
import type { OAuthProvider, OAuthUserInfo } from "../src/auth/oauth/types.js";
import { passkey } from "../src/auth/passkey-plugin.js";
import { passkeyCredentials, users } from "../src/db/schema.js";
import {
	ACR,
	authMethodsForSignIn,
	normalizeEvents,
	recordAuthEvent,
	resolveAuthContext,
	sanitizeIdpAmr,
} from "../src/session/auth-context.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const RP_ID = "example.com";
const ORIGIN = "https://example.com";
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

function b64u(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function unb64u(value: string): Uint8Array {
	return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}

function toDer(raw: Uint8Array): Uint8Array {
	const int = (bytes: Uint8Array): number[] => {
		let i = 0;
		while (i < bytes.length - 1 && bytes[i] === 0) i++;
		const trimmed = [...bytes.slice(i)];
		if ((trimmed[0] ?? 0) & 0x80) trimmed.unshift(0);
		return [0x02, trimmed.length, ...trimmed];
	};
	const r = int(raw.slice(0, 32));
	const s = int(raw.slice(32));
	return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}

interface Authenticator {
	credentialId: string;
	coseKey: Uint8Array;
	assert(challenge: string, signCount: number, userVerified: boolean): Promise<unknown>;
}

async function makeAuthenticator(credentialId: string): Promise<Authenticator> {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	]);
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const x = unb64u(jwk.x ?? "");
	const y = unb64u(jwk.y ?? "");
	const coseKey = Uint8Array.from([
		0xa5,
		0x01,
		0x02,
		0x03,
		0x26,
		0x20,
		0x01,
		0x21,
		0x58,
		0x20,
		...x,
		0x22,
		0x58,
		0x20,
		...y,
	]);
	return {
		credentialId,
		coseKey,
		async assert(challenge, signCount, userVerified) {
			const rpIdHash = new Uint8Array(
				await crypto.subtle.digest("SHA-256", new TextEncoder().encode(RP_ID)),
			);
			const authData = new Uint8Array(37);
			authData.set(rpIdHash, 0);
			authData[32] = userVerified ? 0x05 : 0x01;
			new DataView(authData.buffer).setUint32(33, signCount);
			const clientData = new TextEncoder().encode(
				JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN }),
			);
			const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
			const signed = new Uint8Array(authData.length + hash.length);
			signed.set(authData, 0);
			signed.set(hash, authData.length);
			const sig = new Uint8Array(
				await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed),
			);
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				response: {
					clientDataJSON: b64u(clientData),
					authenticatorData: b64u(authData),
					signature: b64u(toDer(sig)),
				},
			};
		},
	};
}

const passkeyConfig = {
	rpName: "Test",
	rpId: RP_ID,
	origin: ORIGIN,
	attestation: "none" as const,
};

const bearerJson = (path: string, body: unknown, token: string) =>
	new Request(`https://example.com${path}`, {
		method: "POST",
		headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
		body: JSON.stringify(body),
	});

async function bootPasskey() {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		baseUrl: ORIGIN,
		auth: { session: { secret: SECRET } },
		passkey: passkeyConfig,
		plugins: [passkey(passkeyConfig)],
	});
	const sessions = theauth.auth.session;
	const headless = theauth.passkey;
	if (!sessions || !headless) throw new Error("modules missing");
	const now = new Date();
	const keys: Record<string, Authenticator> = {};
	for (const id of ["alice", "bob"]) {
		await theauth.db.insert(users).values({
			id,
			email: `${id}@example.com`,
			createdAt: now,
			updatedAt: now,
		});
		const key = await makeAuthenticator(`${id}-cred`);
		keys[id] = key;
		await theauth.db.insert(passkeyCredentials).values({
			id: `row-${id}`,
			userId: id,
			credentialId: key.credentialId,
			publicKey: b64u(key.coseKey),
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});
	}
	const alice = keys.alice as Authenticator;
	const bob = keys.bob as Authenticator;
	return { theauth, sessions, headless, alice, bob };
}

describe("auth context: federated events", () => {
	it("maps a social sign-in to a federated event", () => {
		expect(authMethodsForSignIn("social")).toEqual(["federated"]);
	});

	it("rates federated as single factor with amr fed, and keeps provider hints informational", () => {
		const events = recordAuthEvent([], "federated", 100, ["pwd", "mfa", "bogus", "otp"]);
		const ctx = resolveAuthContext(events, 100);
		expect(ctx.acr).toBe(ACR.singleFactor);
		expect(ctx.amr).toEqual(["fed", "otp", "pwd"]);
		expect(ctx.amr).not.toContain("mfa");
	});

	it("drops idpAmr from stored events of other methods and from malformed values", () => {
		const events = normalizeEvents([
			{ method: "password", at: 1, idpAmr: ["otp"] },
			{ method: "federated", at: 2, idpAmr: "otp" },
		]);
		expect(events.find((e) => e.method === "password")?.idpAmr).toBeUndefined();
		expect(events.find((e) => e.method === "federated")?.idpAmr).toBeUndefined();
		expect(sanitizeIdpAmr(["otp", "otp", 5, "mfa", "x".repeat(10)])).toEqual(["otp"]);
	});

	it("a TOTP code on top of a federated sign-in reaches multi factor, never phishing resistant", () => {
		let events = recordAuthEvent([], "federated", 100);
		events = recordAuthEvent(events, "totp", 101);
		const ctx = resolveAuthContext(events, 100);
		expect(ctx.acr).toBe(ACR.mfa);
	});
});

describe("social sign-in records fed", () => {
	async function signIn(raw: Record<string, unknown>) {
		const info: OAuthUserInfo = {
			id: "provider-1",
			email: "member@example.com",
			emailVerified: true,
		};
		const provider: OAuthProvider = {
			id: "mock",
			name: "Mock",
			authorizationUrl: "https://mock.example/auth",
			tokenUrl: "https://mock.example/token",
			userInfoUrl: "https://mock.example/userinfo",
			scopes: ["email"],
			async getAuthorizationUrl(state) {
				return `https://mock.example/auth?state=${state}`;
			},
			async exchangeCode() {
				return { accessToken: "at", tokenType: "Bearer", raw };
			},
			async getUserInfo() {
				return info;
			},
		};
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			baseUrl: "https://app.example.com",
			auth: { session: { secret: SECRET } },
			plugins: [oauth({ providers: { mock: provider } })],
		});
		await theauth.db.insert(users).values({
			id: "member",
			email: "member@example.com",
			emailVerified: 1,
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const start = await theauth.plugins.handleRequest(
			new Request("https://app.example.com/auth/oauth/authorize/mock"),
		);
		const state = new URL(start?.headers.get("location") ?? "").searchParams.get("state");
		const res = await theauth.plugins.handleRequest(
			new Request(`https://app.example.com/auth/oauth/callback/mock?code=c&state=${state}`),
		);
		const cookie = res?.headers.get("set-cookie") ?? "";
		const token = decodeURIComponent(/theauth_session=([^;]+)/.exec(cookie)?.[1] ?? "");
		const sessions = theauth.auth.session;
		if (!sessions || !token) throw new Error("no session issued");
		return sessions.validate(token);
	}

	it("records fed and single factor when the provider sends no id_token", async () => {
		const session = await signIn({});
		expect(session?.auth?.amr).toEqual(["fed"]);
		expect(session?.auth?.acr).toBe(ACR.singleFactor);
	});

	it("adds the provider amr hints from the id_token but never mfa or a higher acr", async () => {
		const key = new Uint8Array(32).fill(7);
		const idToken = await new SignJWT({ amr: ["pwd", "mfa", "hwk", "nonsense"] })
			.setProtectedHeader({ alg: "HS256" })
			.setSubject("provider-1")
			.sign(key);
		const session = await signIn({ id_token: idToken });
		expect(session?.auth?.amr).toEqual(["fed", "hwk", "pwd"]);
		expect(session?.auth?.acr).toBe(ACR.singleFactor);
	});

	it("ignores a garbage id_token", async () => {
		const session = await signIn({ id_token: "not.a.jwt" });
		expect(session?.auth?.amr).toEqual(["fed"]);
	});
});

describe("headless totp handler records a step up", () => {
	it("raises acr to multi factor on /auth/2fa/verify and leaves a wrong code alone", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SECRET } },
			username: {},
			totp: {},
		});
		const { username, totp } = theauth;
		const sessions = theauth.auth.session;
		if (!username || !totp || !sessions) throw new Error("modules missing");
		const { user } = await username.signUp({ username: "kate", password: "Password1!" });
		const setup = await totp.setup(user.id);
		await totp.enable(user.id, totpCode(setup.secret));
		const { token } = await sessions.create(user.id, undefined, { authMethods: ["password"] });

		const wrong = await totp.handleRequest(
			bearerJson("/auth/2fa/verify", { code: "000000" }, token),
		);
		expect(((await wrong?.json()) as { valid: boolean }).valid).toBe(false);
		expect((await sessions.validate(token))?.auth?.acr).toBe(ACR.singleFactor);

		const ok = await totp.handleRequest(
			bearerJson("/auth/2fa/verify", { code: totpCode(setup.secret) }, token),
		);
		expect(((await ok?.json()) as { valid: boolean }).valid).toBe(true);
		expect((await sessions.validate(token))?.auth?.acr).toBe(ACR.mfa);
	});
});

describe("passkey step up on the current session", () => {
	async function challengeFor(
		theauth: Awaited<ReturnType<typeof bootPasskey>>["theauth"],
		token: string,
	) {
		const res = await theauth.plugins.handleRequest(
			bearerJson("/auth/passkey/step-up/options", {}, token),
		);
		expect(res?.status).toBe(200);
		return ((await res?.json()) as { challenge: string }).challenge;
	}

	it("records a user verified passkey on the same session, no new session", async () => {
		const { theauth, sessions, alice } = await bootPasskey();
		const { token } = await sessions.create("alice", undefined, { authMethods: ["password"] });
		const challenge = await challengeFor(theauth, token);
		const assertion = await alice.assert(challenge, 1, true);
		const res = await theauth.plugins.handleRequest(
			bearerJson("/auth/passkey/step-up/verify", { response: assertion }, token),
		);
		expect(res?.status).toBe(200);
		expect(res?.headers.get("set-cookie")).toBeNull();
		const body = (await res?.json()) as { verified: boolean; recorded: boolean };
		expect(body).toMatchObject({ verified: true, recorded: true });
		const after = await sessions.validate(token);
		expect(after?.auth?.acr).toBe(ACR.phishingResistant);
		expect(after?.auth?.amr).toContain("swk");
		expect((await sessions.list("alice")).length).toBe(1);
	});

	it("a presence only assertion does not reach phishing resistant", async () => {
		const { theauth, sessions, alice } = await bootPasskey();
		const { token } = await sessions.create("alice", undefined, { authMethods: ["password"] });
		const challenge = await challengeFor(theauth, token);
		const assertion = await alice.assert(challenge, 1, false);
		await theauth.plugins.handleRequest(
			bearerJson("/auth/passkey/step-up/verify", { response: assertion }, token),
		);
		expect((await sessions.validate(token))?.auth?.acr).not.toBe(ACR.phishingResistant);
	});

	it("refuses another user's passkey and records nothing", async () => {
		const { theauth, sessions, bob } = await bootPasskey();
		const { token } = await sessions.create("alice", undefined, { authMethods: ["password"] });
		const challenge = await challengeFor(theauth, token);
		const assertion = await bob.assert(challenge, 1, true);
		const res = await theauth.plugins.handleRequest(
			bearerJson("/auth/passkey/step-up/verify", { response: assertion }, token),
		);
		expect(res?.status).toBe(401);
		expect((await sessions.validate(token))?.auth?.acr).toBe(ACR.singleFactor);
	});

	it("requires a signed in user", async () => {
		const { theauth } = await bootPasskey();
		const res = await theauth.plugins.handleRequest(
			new Request("https://example.com/auth/passkey/step-up/options", { method: "POST" }),
		);
		expect(res?.status).toBe(401);
	});

	it("headless login/verify records on the caller's own session only", async () => {
		const { sessions, headless, alice, bob } = await bootPasskey();
		const aliceSession = await sessions.create("alice", undefined, { authMethods: ["password"] });

		// Bob proves his own passkey while carrying Alice's session: Alice's session must not change.
		const bobOptions = await headless.getAuthenticationOptions("bob");
		const bobAssertion = await bob.assert(bobOptions.challenge, 1, true);
		await headless.handleRequest(
			bearerJson("/auth/passkey/login/verify", { response: bobAssertion }, aliceSession.token),
		);
		expect((await sessions.validate(aliceSession.token))?.auth?.acr).toBe(ACR.singleFactor);

		// Alice proves her own passkey with her session: recorded.
		const aliceOptions = await headless.getAuthenticationOptions("alice");
		const aliceAssertion = await alice.assert(aliceOptions.challenge, 1, true);
		const res = await headless.handleRequest(
			bearerJson("/auth/passkey/login/verify", { response: aliceAssertion }, aliceSession.token),
		);
		expect(res?.status).toBe(200);
		expect((await sessions.validate(aliceSession.token))?.auth?.acr).toBe(ACR.phishingResistant);
	});
});
