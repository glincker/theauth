/**
 * Tests for the opt-in session features: reuse grace window, cookie cache,
 * per-request base URL and back-channel logout verification.
 */

import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	BACKCHANNEL_LOGOUT_EVENT,
	createBackChannelLogoutReceiver,
} from "../src/auth/federated-logout.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import { createBaseUrlResolver } from "../src/session/base-url.js";
import { createSessionCookieCache } from "../src/session/cookie-cache.js";
import type { Session } from "../src/session/session.js";
import { createTokenFamilyStore, MAX_REUSE_GRACE_MS } from "../src/session/token-family.js";

const SECRET = "a-test-secret-that-is-at-least-32-chars-long!!";

function makeSession(): Session {
	return {
		id: "s1",
		userId: "u1",
		expiresAt: new Date(Date.now() + 3_600_000),
		createdAt: new Date(),
		metadata: { ipAddress: "1.2.3.4", role: "admin" },
	};
}

describe("token family reuse grace", () => {
	async function setup(reuseGraceMs: number) {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		db.insert(schema.users)
			.values({ id: "u1", email: "a@example.com", createdAt: new Date(), updatedAt: new Date() })
			.run();
		const store = createTokenFamilyStore(db, { reuseGraceMs });
		const family = await store.createFamily("u1", new Date(Date.now() + 86_400_000));
		const { rawToken } = await store.issueToken(family.id, 86_400_000);
		return { store, family, rawToken };
	}

	it("stays strict by default", async () => {
		const { store, rawToken } = await setup(0);
		expect((await store.consumeToken(rawToken)).status).toBe("ok");
		expect((await store.consumeToken(rawToken)).status).toBe("reuse");
	});

	it("accepts a replay inside the window and flags it", async () => {
		const { store, rawToken } = await setup(10_000);
		await store.consumeToken(rawToken);
		const again = await store.consumeToken(rawToken);
		expect(again.status).toBe("ok");
		expect(again.graceReplay).toBe(true);
	});

	it("still revokes the family when the window is zero for that call", async () => {
		const { store, family, rawToken } = await setup(10_000);
		await store.consumeToken(rawToken);
		expect((await store.consumeToken(rawToken, { graceMs: 0 })).status).toBe("reuse");
		expect(await store.isFamilyActive(family.id)).toBe(false);
	});

	it("caps the window", () => {
		expect(MAX_REUSE_GRACE_MS).toBe(300_000);
	});
});

describe("session cookie cache", () => {
	it("round trips and drops excluded fields", async () => {
		const cache = createSessionCookieCache({ secret: SECRET, exclude: ["metadata.ipAddress"] });
		const written = await cache.encode(makeSession(), "token-a");
		expect(written.success).toBe(true);
		if (!written.success) return;
		const cookie = written.data.headers.map((h) => h.split(";")[0]).join("; ");
		const hit = await cache.decode(cookie, "token-a");
		expect(hit?.session.userId).toBe("u1");
		expect(hit?.session.metadata).toEqual({ role: "admin" });
	});

	it("rejects a different session token, tampering and a short secret", async () => {
		const cache = createSessionCookieCache({ secret: SECRET });
		const written = await cache.encode(makeSession(), "token-a");
		if (!written.success) throw new Error("encode failed");
		const pair = written.data.headers[0]?.split(";")[0] ?? "";
		expect(await cache.decode(pair, "token-b")).toBeNull();
		expect(await cache.decode(`${pair.slice(0, -2)}xx`, "token-a")).toBeNull();
		expect(() => createSessionCookieCache({ secret: "short" })).toThrow();
	});

	it("fails with COOKIE_TOO_LARGE instead of truncating", async () => {
		const cache = createSessionCookieCache({ secret: SECRET, maxBytes: 200 });
		const session = { ...makeSession(), metadata: { blob: "x".repeat(500) } };
		const written = await cache.encode(session, "t");
		expect(written.success).toBe(false);
		if (!written.success) expect(written.error.code).toBe("COOKIE_TOO_LARGE");
	});
});

describe("base url resolver", () => {
	const resolver = createBaseUrlResolver({
		baseUrl: "https://app.example.com",
		allowedHosts: ["app.example.com", "*.example.com"],
	});

	it("echoes an allowed host and falls back for others", () => {
		const ok = resolver.resolve(new Request("https://tenant.example.com/x"));
		expect(ok).toEqual({ success: true, data: "https://tenant.example.com" });
		const other = resolver.resolve(new Request("https://evil.test/x"));
		expect(other).toEqual({ success: true, data: "https://app.example.com" });
	});

	it("ignores forwarded headers unless trusted", () => {
		const req = () =>
			new Request("https://app.example.com/x", {
				headers: { "x-forwarded-host": "t.example.com" },
			});
		expect(resolver.resolve(req())).toEqual({ success: true, data: "https://app.example.com" });
		const trusting = createBaseUrlResolver({
			baseUrl: "https://app.example.com",
			allowedHosts: ["*.example.com"],
			trustForwardedHeaders: true,
		});
		expect(trusting.resolve(req())).toEqual({ success: true, data: "https://t.example.com" });
	});

	it("does not let a lookalike host match a wildcard", () => {
		expect(resolver.isAllowedHost("evil.com.example.com.attacker.io")).toBe(false);
		expect(resolver.isAllowedHost("example.com")).toBe(false);
	});
});

describe("back-channel logout receiver", () => {
	const key = new TextEncoder().encode(SECRET);
	const base = { issuer: "https://idp.test", clientId: "client-1", verificationKey: key };

	async function logoutToken(claims: Record<string, unknown>, jti = "j1"): Promise<string> {
		return new SignJWT({ events: { [BACKCHANNEL_LOGOUT_EVENT]: {} }, sid: "sid-1", ...claims })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer("https://idp.test")
			.setAudience("client-1")
			.setIssuedAt()
			.setJti(jti)
			.sign(key);
	}

	it("accepts a valid token once and rejects its replay", async () => {
		const receiver = createBackChannelLogoutReceiver({
			...base,
			algorithms: ["HS256"],
			onLogout: async () => {},
		});
		const token = await logoutToken({});
		expect((await receiver.verifyLogoutToken(token)).success).toBe(true);
		expect((await receiver.verifyLogoutToken(token)).success).toBe(false);
	});

	it("rejects a token carrying a nonce or no logout event", async () => {
		const receiver = createBackChannelLogoutReceiver({
			...base,
			algorithms: ["HS256"],
			onLogout: async () => {},
		});
		expect(
			(await receiver.verifyLogoutToken(await logoutToken({ nonce: "n" }, "j2"))).success,
		).toBe(false);
		expect(
			(await receiver.verifyLogoutToken(await logoutToken({ events: {} }, "j3"))).success,
		).toBe(false);
	});
});
