/** Passkey as a second factor: real ES256 assertions through the passkey module, driven by the sign-in gate. */

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { describe, expect, it } from "vitest";
import { createPasskeyModule } from "../src/auth/passkey.js";
import { createPasskeyTwoFactorFactor } from "../src/auth/passkey-second-factor.js";
import { createSignInGate } from "../src/auth/sign-in-gate.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const SECRET = "passkey-factor-secret-that-is-at-least-32-chars";

function b64u(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function unb64u(value: string): Uint8Array {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/");
	return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** Raw r||s to DER, as authenticators emit. */
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
	assert(challenge: string, signCount: number): Promise<Record<string, unknown>>;
	coseKey: Uint8Array;
}

async function makeAuthenticator(credentialId: string): Promise<Authenticator> {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	]);
	const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
	const x = unb64u(jwk.x ?? "");
	const y = unb64u(jwk.y ?? "");
	// COSE_Key map: kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x, y.
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
		async assert(challenge, signCount) {
			const rpIdHash = new Uint8Array(
				await crypto.subtle.digest("SHA-256", new TextEncoder().encode(RP_ID)),
			);
			const authData = new Uint8Array(37);
			authData.set(rpIdHash, 0);
			authData[32] = 0x01;
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

async function setup() {
	const db = drizzle(new Database(":memory:"), { schema });
	await createTables(db, "sqlite");
	const now = new Date();
	for (const id of ["alice", "bob"]) {
		await db.insert(schema.users).values({
			id,
			email: `${id}@example.com`,
			createdAt: now,
			updatedAt: now,
		});
	}
	const passkey = createPasskeyModule(
		{ rpName: "Test", rpId: RP_ID, origin: ORIGIN, attestation: "none" },
		db,
	);
	const aliceKey = await makeAuthenticator("alice-cred");
	const bobKey = await makeAuthenticator("bob-cred");
	for (const [userId, key] of [
		["alice", aliceKey],
		["bob", bobKey],
	] as const) {
		await db.insert(schema.passkeyCredentials).values({
			id: `row-${userId}`,
			userId,
			credentialId: key.credentialId,
			publicKey: b64u(key.coseKey),
			counter: 0,
			createdAt: now,
			lastUsedAt: now,
		});
	}
	const factor = createPasskeyTwoFactorFactor(passkey);
	const gate = createSignInGate({
		db,
		sessionSecret: SECRET,
		config: { require2faFor: ["password"], factors: [factor] },
	});
	return { db, passkey, factor, gate, aliceKey, bobKey };
}

describe("passkey two-factor factor", () => {
	it("is enabled only for users with a registered passkey", async () => {
		const { factor, db } = await setup();
		expect(await factor.isEnabled("alice")).toBe(true);
		expect(await factor.isEnabled("nobody")).toBe(false);
		expect(db).toBeDefined();
	});

	it("completes a gate challenge with a valid assertion", async () => {
		const { factor, gate, aliceKey } = await setup();
		const decision = await gate.evaluate({ userId: "alice", method: "password" });
		if (decision.action !== "two_factor_required") throw new Error("expected 2FA");
		expect(decision.methods).toContain("passkey");

		const options = await factor.getOptions("alice");
		expect(options.allowCredentials.map((c) => c.id)).toEqual(["alice-cred"]);
		const assertion = await aliceKey.assert(options.challenge, 1);

		const done = await gate.completeTwoFactor({
			challenge: decision.challenge,
			factor: "passkey",
			code: JSON.stringify(assertion),
		});
		expect(done).toMatchObject({ ok: true, userId: "alice", method: "password" });
	});

	it("accepts a base64url encoded assertion", async () => {
		const { factor, gate, aliceKey } = await setup();
		const decision = await gate.evaluate({ userId: "alice", method: "password" });
		if (decision.action !== "two_factor_required") throw new Error("expected 2FA");
		const { challenge } = await factor.getOptions("alice");
		const assertion = await aliceKey.assert(challenge, 1);
		const code = b64u(new TextEncoder().encode(JSON.stringify(assertion)));
		const done = await gate.completeTwoFactor({ challenge: decision.challenge, code });
		expect(done.ok).toBe(true);
	});

	it("rejects an assertion from another user's passkey", async () => {
		const { factor, gate, bobKey } = await setup();
		const decision = await gate.evaluate({ userId: "alice", method: "password" });
		if (decision.action !== "two_factor_required") throw new Error("expected 2FA");
		const { challenge } = await factor.getOptions("alice");
		const assertion = await bobKey.assert(challenge, 1);
		const done = await gate.completeTwoFactor({
			challenge: decision.challenge,
			factor: "passkey",
			code: JSON.stringify(assertion),
		});
		expect(done).toEqual({ ok: false, reason: "invalid_code" });
	});

	it("rejects a replayed assertion and malformed codes", async () => {
		const { factor, aliceKey } = await setup();
		const { challenge } = await factor.getOptions("alice");
		const code = JSON.stringify(await aliceKey.assert(challenge, 1));
		expect(await factor.verify("alice", code)).toBe(true);
		expect(await factor.verify("alice", code)).toBe(false);
		expect(await factor.verify("alice", "123456")).toBe(false);
		expect(await factor.verify("alice", '{"id":1}')).toBe(false);
	});
});
