/** Secret rotation for the session cookie cache and stateless session cookies. */

import { describe, expect, it } from "vitest";
import { createSessionCookieCache } from "../src/session/cookie-cache.js";
import type { Session } from "../src/session/session.js";
import { createStatelessSessions } from "../src/session/stateless.js";

const OLD = "old-secret-that-is-at-least-32-characters!!";
const NEW = "new-secret-that-is-at-least-32-characters!!";

function makeSession(): Session {
	return {
		id: "s1",
		userId: "u1",
		expiresAt: new Date(Date.now() + 3_600_000),
		createdAt: new Date(),
	};
}

function pairs(headers: string[]): string {
	return headers.map((h) => h.split(";")[0]).join("; ");
}

async function cacheCookie(secret: Parameters<typeof createSessionCookieCache>[0]["secret"]) {
	const cache = createSessionCookieCache({ secret });
	const written = await cache.encode(makeSession(), "tok");
	if (!written.success) throw new Error("encode failed");
	return pairs(written.data.headers);
}

describe("cookie cache rotation", () => {
	it("keeps a cookie valid across a rotation and stops after the old key is removed", async () => {
		const cookie = await cacheCookie(OLD);
		const rotating = createSessionCookieCache({ secret: [NEW, OLD] });
		expect((await rotating.decode(cookie, "tok"))?.session.userId).toBe("u1");
		const removed = createSessionCookieCache({ secret: [NEW] });
		expect(await removed.decode(cookie, "tok")).toBeNull();
	});

	it("signs new cookies with the first key", async () => {
		const cookie = await cacheCookie([NEW, OLD]);
		expect(await createSessionCookieCache({ secret: NEW }).decode(cookie, "tok")).not.toBeNull();
		expect(await createSessionCookieCache({ secret: OLD }).decode(cookie, "tok")).toBeNull();
	});

	it("writes the key id into the cookie and still accepts id-less cookies", async () => {
		const ring = [
			{ id: "k2", secret: NEW },
			{ id: "k1", secret: OLD },
		];
		const cookie = await cacheCookie(ring);
		expect(cookie.split(".").pop()).toBe("k2");
		expect(await createSessionCookieCache({ secret: ring }).decode(cookie, "tok")).not.toBeNull();
		const legacy = await cacheCookie(OLD);
		expect(await createSessionCookieCache({ secret: ring }).decode(legacy, "tok")).not.toBeNull();
	});

	it("rejects tampering, including a swapped key id", async () => {
		const ring = [
			{ id: "k2", secret: NEW },
			{ id: "k1", secret: OLD },
		];
		const cache = createSessionCookieCache({ secret: ring });
		const cookie = await cacheCookie(ring);
		const tampered = cookie.replace(
			/\.[^.]+\.([^.]+)\.k2$/,
			(_m, sig: string) => `.eyJ4Ijoie30ifQ.${sig}.k2`,
		);
		expect(await cache.decode(tampered, "tok")).toBeNull();
	});

	it("validates config", () => {
		expect(() => createSessionCookieCache({ secret: "short" })).toThrow(/at least 32/);
		expect(() => createSessionCookieCache({ secret: [] })).toThrow(/at least one/);
		expect(() => createSessionCookieCache({ secret: [NEW, NEW] })).toThrow(/duplicate/);
		expect(() => createSessionCookieCache({ secret: [NEW, ""] })).toThrow(/empty/);
		expect(() => createSessionCookieCache({ secret: [NEW, "short"] })).toThrow(/at least 32/);
	});
});

describe("stateless sessions rotation", () => {
	const identity = { sub: "idp|1", sid: "sid-1" };

	async function issue(secret: Parameters<typeof createStatelessSessions>[0]["secret"]) {
		const s = createStatelessSessions({ secret });
		const created = await s.createSession(identity, { accessToken: "at", refreshToken: "rt" });
		if (!created.success) throw new Error("create failed");
		return pairs(created.data.headers);
	}

	it("identity and token cookies survive a rotation", async () => {
		const cookie = await issue(OLD);
		const rotated = createStatelessSessions({ secret: [NEW, OLD] });
		expect((await rotated.getSession(cookie))?.identity.sub).toBe("idp|1");
		const token = await rotated.getAccessToken(cookie);
		expect(token.success && token.data.accessToken).toBe("at");
	});

	it("removed old key invalidates old cookies", async () => {
		const cookie = await issue(OLD);
		const removed = createStatelessSessions({ secret: [NEW] });
		expect(await removed.getSession(cookie)).toBeNull();
	});

	it("new cookies need the new key", async () => {
		const cookie = await issue([NEW, OLD]);
		expect(await createStatelessSessions({ secret: NEW }).getSession(cookie)).not.toBeNull();
		expect(await createStatelessSessions({ secret: OLD }).getSession(cookie)).toBeNull();
		const onlyNew = createStatelessSessions({ secret: NEW });
		const token = await onlyNew.getAccessToken(cookie);
		expect(token.success && token.data.accessToken).toBe("at");
	});

	it("supports key ids", async () => {
		const ring = [
			{ id: "k2", secret: NEW },
			{ id: "k1", secret: OLD },
		];
		const cookie = await issue(ring);
		expect(cookie).toContain(".k2");
		expect(await createStatelessSessions({ secret: ring }).getSession(cookie)).not.toBeNull();
		const legacy = await issue(OLD);
		expect(await createStatelessSessions({ secret: ring }).getSession(legacy)).not.toBeNull();
	});

	it("validates config", () => {
		expect(() => createStatelessSessions({ secret: "short" })).toThrow(/at least 32/);
		expect(() => createStatelessSessions({ secret: [NEW, NEW] })).toThrow(/duplicate/);
		expect(() => createStatelessSessions({ secret: [] })).toThrow(/at least one/);
	});
});
