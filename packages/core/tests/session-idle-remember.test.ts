/** Idle timeout, remember me and the cookie manager wiring. A fake clock drives every test; nothing sleeps. */

import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import { createCookieSessionManager } from "../src/session/manager.js";
import { createSessionManager } from "../src/session/session.js";
import { buildSessionCookie } from "../src/session/session-cookie.js";

const SECRET = "a-test-secret-that-is-at-least-32-chars-long!!";
const MIN = 60_000;
const DAY = 86_400;

async function setup() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	db.insert(schema.users)
		.values({ id: "u1", email: "a@example.com", createdAt: new Date(), updatedAt: new Date() })
		.run();
	const clock = { t: Date.UTC(2026, 9, 17, 12, 0, 0) };
	return { db, clock, now: () => clock.t };
}

async function writes(db: Awaited<ReturnType<typeof setup>>["db"], id: string) {
	const row = (await db.select().from(schema.sessions).where(eq(schema.sessions.id, id)))[0];
	return row?.metadata ?? null;
}

afterEach(() => {
	vi.useRealTimers();
	delete process.env.THEAUTH_SESSION_IDLE_TIMEOUT_MS;
	delete process.env.THEAUTH_SESSION_ACTIVITY_GRANULARITY_MS;
});

describe("idle timeout", () => {
	it("is off by default and stamps nothing", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager({ secret: SECRET, now }, db);
		const { session, token } = await m.create("u1");
		expect(await writes(db, session.id)).toBeNull();
		clock.t += 3 * DAY * 1000;
		expect((await m.validateDetailed(token)).session?.id).toBe(session.id);
	});

	it("denies an idle session with idle_timeout, deletes it and reports the revoke", async () => {
		const { db, clock, now } = await setup();
		const revoked: string[] = [];
		const m = createSessionManager(
			{
				secret: SECRET,
				now,
				idleTimeoutMs: 30 * MIN,
				onRevoke: (r) => void revoked.push(r[0]?.id ?? ""),
			},
			db,
		);
		const { session, token } = await m.create("u1");
		clock.t += 29 * MIN;
		expect((await m.validateDetailed(token)).session).not.toBeNull();
		clock.t += 31 * MIN;
		const out = await m.validateDetailed(token);
		expect(out).toEqual({ session: null, reason: "idle_timeout" });
		expect(revoked).toEqual([session.id]);
		expect((await m.validateDetailed(token)).reason).toBe("not_found");
		expect(await m.validate(token)).toBeNull();
	});

	it("activity extends the idle window", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager({ secret: SECRET, now, idleTimeoutMs: 30 * MIN }, db);
		const { token } = await m.create("u1");
		for (let i = 0; i < 6; i++) {
			clock.t += 20 * MIN;
			expect((await m.validateDetailed(token)).session).not.toBeNull();
		}
		clock.t += 31 * MIN;
		expect((await m.validateDetailed(token)).reason).toBe("idle_timeout");
	});

	it("writes lastActiveAt at most once per granularity window", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager(
			{ secret: SECRET, now, idleTimeoutMs: 30 * MIN, activityGranularityMs: 5 * MIN },
			db,
		);
		const { session, token } = await m.create("u1");
		const stamp = async () => (await writes(db, session.id))?.theauthLastActiveAt;
		const created = clock.t;
		for (let i = 0; i < 20; i++) {
			clock.t += 10_000; // 200s total, below 5 min
			await m.validate(token);
		}
		expect(await stamp()).toBe(created);
		clock.t = created + 5 * MIN;
		const touched = await m.validateDetailed(token);
		expect(await stamp()).toBe(created + 5 * MIN);
		expect(touched.session?.lastActiveAt?.getTime()).toBe(created + 5 * MIN);
		clock.t += 60_000;
		await m.validate(token);
		expect(await stamp()).toBe(created + 5 * MIN);
	});

	it("keeps caller metadata clean and preserves it across touches", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager({ secret: SECRET, now, idleTimeoutMs: 30 * MIN }, db);
		const { session, token } = await m.create("u1", { role: "admin" });
		expect(session.metadata).toEqual({ role: "admin" });
		clock.t += 10 * MIN;
		const out = await m.validate(token);
		expect(out?.metadata).toEqual({ role: "admin" });
		expect((await m.list("u1"))[0]?.metadata).toEqual({ role: "admin" });
	});

	it("treats a session with no stamp as active instead of idle", async () => {
		const { db, clock, now } = await setup();
		const legacy = createSessionManager({ secret: SECRET, now }, db);
		const { token } = await legacy.create("u1");
		clock.t += 3 * DAY * 1000;
		const m = createSessionManager({ secret: SECRET, now, idleTimeoutMs: 30 * MIN }, db);
		const out = await m.validateDetailed(token);
		expect(out.session?.lastActiveAt?.getTime()).toBe(clock.t);
	});

	it("absolute timeout still applies to a busy session", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager(
			{ secret: SECRET, now, maxAge: 3600, idleTimeoutMs: 30 * MIN },
			db,
		);
		const { token } = await m.create("u1");
		for (let i = 0; i < 5; i++) {
			clock.t += 15 * MIN;
			await m.validate(token);
		}
		clock.t += 1 * MIN;
		const out = await m.validateDetailed(token);
		expect(out.reason).toBe("invalid_token");
	});

	it("reads config from the environment and config wins", async () => {
		const { db, clock, now } = await setup();
		process.env.THEAUTH_SESSION_IDLE_TIMEOUT_MS = String(10 * MIN);
		const fromEnv = createSessionManager({ secret: SECRET, now }, db);
		const a = await fromEnv.create("u1");
		clock.t += 11 * MIN;
		expect((await fromEnv.validateDetailed(a.token)).reason).toBe("idle_timeout");
		const config = createSessionManager({ secret: SECRET, now, idleTimeoutMs: 60 * MIN }, db);
		const b = await config.create("u1");
		clock.t += 11 * MIN;
		expect((await config.validateDetailed(b.token)).session).not.toBeNull();
	});

	it("rejects a granularity at or above the idle timeout", async () => {
		const { db } = await setup();
		expect(() =>
			createSessionManager({ secret: SECRET, idleTimeoutMs: MIN, activityGranularityMs: MIN }, db),
		).toThrow(/shorter than idleTimeoutMs/);
		expect(() => createSessionManager({ secret: SECRET, idleTimeoutMs: -5 }, db)).toThrow();
	});
});

describe("remember me", () => {
	it("gives a longer absolute lifetime, capped", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager({ secret: SECRET, now, maxAge: DAY }, db);
		const remembered = await m.create("u1", undefined, { rememberMe: true });
		const plain = await m.create("u1", undefined, { rememberMe: false });
		const legacy = await m.create("u1");
		expect(remembered.session.expiresAt.getTime() - clock.t).toBe(30 * DAY * 1000);
		expect(plain.session.expiresAt.getTime() - clock.t).toBe(DAY * 1000);
		expect(legacy.session.expiresAt.getTime() - clock.t).toBe(DAY * 1000);
		expect(remembered.session.rememberMe).toBe(true);
		expect(legacy.session.rememberMe).toBeUndefined();

		const capped = createSessionManager(
			{ secret: SECRET, now, rememberMeMaxAge: 400 * DAY, rememberMeMaxAgeCap: 60 * DAY },
			db,
		);
		const c = await capped.create("u1", undefined, { rememberMe: true });
		expect(c.session.expiresAt.getTime() - clock.t).toBe(60 * DAY * 1000);
	});

	it("a remembered session validates past the normal lifetime and a plain one does not", async () => {
		const { db, clock, now } = await setup();
		const m = createSessionManager({ secret: SECRET, now, maxAge: DAY }, db);
		const r = await m.create("u1", undefined, { rememberMe: true });
		const p = await m.create("u1", undefined, { rememberMe: false });
		clock.t += 2 * DAY * 1000;
		expect((await m.validate(r.token))?.rememberMe).toBe(true);
		expect(await m.validate(p.token)).toBeNull();
	});

	it("builds a persistent cookie for true and a session cookie for false", () => {
		const exp = new Date(Date.now() + 30 * DAY * 1000);
		const on = buildSessionCookie(
			"s",
			"tok",
			{ expiresAt: exp, rememberMe: true },
			{ secure: true },
		);
		expect(on).toMatch(/Max-Age=(2591999|2592000)/);
		expect(on).toContain("Expires=");
		const off = buildSessionCookie(
			"s",
			"tok",
			{ expiresAt: exp, rememberMe: false },
			{ secure: true },
		);
		expect(off).not.toContain("Max-Age");
		expect(off).not.toContain("Expires");
		expect(off).toContain("HttpOnly");
		expect(off).toContain("Secure");
		const legacy = buildSessionCookie(
			"s",
			"tok",
			{ expiresAt: exp },
			{ secure: true, defaultMaxAge: 600 },
		);
		expect(legacy).toContain("Max-Age=600");
	});

	it("cookie manager sets the cookie per choice, survives auto refresh and reports idle", async () => {
		const { db, clock, now } = await setup();
		const m = createCookieSessionManager(
			{ secret: SECRET, now, maxAge: DAY, idleTimeoutMs: 30 * MIN },
			db,
		);
		const on = await m.createSession("u1", undefined, { rememberMe: true });
		expect(on.setCookieHeader).toContain(`Max-Age=${30 * DAY}`);
		const off = await m.createSession("u1", undefined, { rememberMe: false });
		expect(off.setCookieHeader).not.toContain("Max-Age");

		const cookieOf = (h: string) => h.split(";")[0] ?? "";
		clock.t += 10 * MIN;
		const refreshed = await m.validateSession(cookieOf(off.setCookieHeader));
		expect(refreshed.refreshCookieHeader).not.toBeNull();
		expect(refreshed.refreshCookieHeader).not.toContain("Max-Age");
		expect(refreshed.session?.rememberMe).toBe(false);

		clock.t += 31 * MIN;
		const idle = await m.validateSession(cookieOf(on.setCookieHeader));
		expect(idle.session).toBeNull();
		expect(idle.reason).toBe("idle_timeout");
	});
});

describe("cookie cache is not revocation safe", () => {
	it("a revoked session keeps validating from the cache until its maxAge, then falls back to the database", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-10-17T12:00:00Z"));
		const { db } = await setup();
		const m = createCookieSessionManager({ secret: SECRET, cookieCache: { maxAge: 120 } }, db);
		const created = await m.createSession("u1");
		const jar = [created.setCookieHeader, ...(created.cacheCookieHeaders ?? [])]
			.map((h) => h.split(";")[0])
			.join("; ");
		await m.revokeSession(created.session.id);
		const hit = await m.validateSession(jar);
		expect(hit.fromCache).toBe(true);
		expect(hit.session?.id).toBe(created.session.id);
		vi.setSystemTime(new Date("2026-10-17T12:02:01Z"));
		expect((await m.validateSession(jar)).session).toBeNull();
	});
});
