/**
 * Stateless sessions: token cookie bound to the identity cookie (AAD), legacy
 * cookie compatibility, and the sign-in gate hook.
 */

import { describe, expect, it, vi } from "vitest";
import type { SignInGateDecision } from "../src/auth/sign-in-gate.js";
import { hmacSha256Raw, toBase64Url } from "../src/crypto/web-crypto.js";
import type { StatelessIdentity } from "../src/session/stateless.js";
import { createStatelessSessions } from "../src/session/stateless.js";

const SECRET = "stateless-binding-secret-that-is-at-least-32-chars";
const ALICE: StatelessIdentity = { sub: "idp|alice" };
const BOB: StatelessIdentity = { sub: "idp|bob" };
const TOKENS_NAME = "theauth_stateless_tokens";

function cookies(setCookies: string[]): Map<string, string> {
	const out = new Map<string, string>();
	for (const header of setCookies) {
		const pair = header.split(";")[0] ?? "";
		const eq = pair.indexOf("=");
		out.set(pair.slice(0, eq), pair.slice(eq + 1));
	}
	return out;
}

function toHeader(map: Map<string, string>): string {
	return [...map].map(([k, v]) => `${k}=${v}`).join("; ");
}

async function legacyTokenCookie(payload: unknown): Promise<string> {
	const raw = await hmacSha256Raw(SECRET, "theauth-stateless-enc-v1");
	const key = await crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [
		"encrypt",
	]);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		key,
		new TextEncoder().encode(JSON.stringify(payload)),
	);
	return `${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ct))}`;
}

async function issue(identity: StatelessIdentity, accessToken: string, secret = SECRET) {
	const s = createStatelessSessions({ secret });
	const created = await s.createSession(identity, { accessToken });
	if (!created.success) throw new Error(created.error.message);
	return cookies(created.data.headers);
}

describe("token cookie binding", () => {
	it("writes the versioned format", async () => {
		const jar = await issue(ALICE, "at-alice");
		expect(decodeURIComponent(jar.get(TOKENS_NAME) ?? "").startsWith("v2:")).toBe(true);
	});

	it("rejects a token cookie from another user sealed under the same secret", async () => {
		const s = createStatelessSessions({ secret: SECRET });
		const alice = await issue(ALICE, "at-alice");
		const bob = await issue(BOB, "at-bob");
		const mixed = new Map(alice);
		mixed.set(TOKENS_NAME, bob.get(TOKENS_NAME) ?? "");
		const r = await s.getAccessToken(toHeader(mixed));
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.code).toBe("NO_TOKENS");
	});

	it("rejects a token cookie from an older session of the same user", async () => {
		vi.useFakeTimers();
		try {
			const old = await issue(ALICE, "at-old");
			vi.advanceTimersByTime(5_000);
			const current = await issue(ALICE, "at-new");
			const mixed = new Map(current);
			mixed.set(TOKENS_NAME, old.get(TOKENS_NAME) ?? "");
			const r = await createStatelessSessions({ secret: SECRET }).getAccessToken(toHeader(mixed));
			expect(r.success).toBe(false);
		} finally {
			vi.useRealTimers();
		}
	});

	it("still reads its own cookie pair", async () => {
		const s = createStatelessSessions({ secret: SECRET });
		const jar = await issue(ALICE, "at-alice");
		const r = await s.getAccessToken(toHeader(jar));
		expect(r.success && r.data.accessToken).toBe("at-alice");
	});
});

describe("legacy token cookies", () => {
	async function legacyJar() {
		const jar = await issue(ALICE, "ignored");
		jar.set(TOKENS_NAME, await legacyTokenCookie({ accessToken: "at-legacy" }));
		return jar;
	}

	it("are read, upgraded to v2 and reported once per read", async () => {
		const onDeprecation = vi.fn();
		const s = createStatelessSessions({ secret: SECRET, onDeprecation });
		const r = await s.getAccessToken(toHeader(await legacyJar()));
		expect(r.success).toBe(true);
		if (!r.success) return;
		expect(r.data.accessToken).toBe("at-legacy");
		expect(onDeprecation).toHaveBeenCalledTimes(1);
		const upgraded = cookies(r.data.headers).get(TOKENS_NAME);
		expect(decodeURIComponent(upgraded ?? "").startsWith("v2:")).toBe(true);
	});

	it("are refused when acceptLegacyTokenCookies is false", async () => {
		const s = createStatelessSessions({ secret: SECRET, acceptLegacyTokenCookies: false });
		const r = await s.getAccessToken(toHeader(await legacyJar()));
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.code).toBe("NO_TOKENS");
	});
});

describe("sign-in gate", () => {
	it("issues no cookies while the gate asks for a second factor", async () => {
		const decision: SignInGateDecision = {
			action: "two_factor_required",
			challenge: "chal",
			methods: ["totp"],
			expiresAt: new Date(0),
		};
		const evaluate = vi.fn(async () => decision);
		const s = createStatelessSessions({ secret: SECRET, signInGate: { evaluate } });
		const r = await s.createSession(ALICE, { accessToken: "at" });
		expect(r.success).toBe(false);
		if (!r.success) {
			expect(r.error.code).toBe("TWO_FACTOR_REQUIRED");
			expect(r.error.details?.challenge).toBe("chal");
		}
		expect(evaluate).toHaveBeenCalledWith(
			expect.objectContaining({ userId: "idp|alice", method: "social" }),
		);
	});

	it("issues cookies when the gate allows", async () => {
		const s = createStatelessSessions({
			secret: SECRET,
			signInGate: { evaluate: async () => ({ action: "allow" }) },
		});
		const r = await s.createSession(ALICE, { accessToken: "at" });
		expect(r.success).toBe(true);
	});
});
