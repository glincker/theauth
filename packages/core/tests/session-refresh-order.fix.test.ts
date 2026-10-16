/**
 * Session refresh creates the replacement first; maxConcurrent holds under races.
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { sessions, users } from "../src/db/schema.js";
import { createCookieSessionManager } from "../src/session/manager.js";
import { createSessionManager } from "../src/session/session.js";

const SECRET = "session-fix-secret-that-is-at-least-32-chars!!";
const USER = "u-fix";

async function makeDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db
		.insert(users)
		.values({ id: USER, email: "fix@example.com", createdAt: now, updatedAt: now });
	return db;
}

const liveFor = (db: Database) => db.select().from(sessions).where(eq(sessions.userId, USER));

describe("refreshSession ordering", () => {
	let db: Database;
	beforeEach(async () => {
		db = await makeDb();
	});

	it("keeps the old session when creating the new one fails", async () => {
		const mgr = createCookieSessionManager({ secret: SECRET }, db);
		const { session } = await mgr.createSession(USER);
		const spy = vi.spyOn(db, "insert").mockImplementationOnce(() => {
			throw new Error("insert failed");
		});
		await expect(mgr.refreshSession(session.id)).rejects.toThrow("insert failed");
		spy.mockRestore();
		const rows = await liveFor(db);
		expect(rows.map((r) => r.id)).toEqual([session.id]);
	});

	it("concurrent refreshes of one session leave exactly one live session", async () => {
		const mgr = createCookieSessionManager({ secret: SECRET }, db);
		const { session } = await mgr.createSession(USER);
		const results = await Promise.all([
			mgr.refreshSession(session.id),
			mgr.refreshSession(session.id),
		]);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		const rows = await liveFor(db);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.id).not.toBe(session.id);
	});

	it("refresh at the cap does not evict another session", async () => {
		const mgr = createCookieSessionManager({ secret: SECRET, maxConcurrent: 2 }, db);
		const a = await mgr.createSession(USER);
		const b = await mgr.createSession(USER);
		await mgr.refreshSession(b.session.id);
		const ids = (await liveFor(db)).map((r) => r.id);
		expect(ids).toHaveLength(2);
		expect(ids).toContain(a.session.id);
	});
});

describe("maxConcurrent under concurrent sign-ins", () => {
	it("never exceeds the cap (evict-oldest)", async () => {
		const db = await makeDb();
		const mgr = createSessionManager({ secret: SECRET, maxConcurrent: 2 }, db);
		// Racers that lose are dropped and reject; the cap itself must hold.
		const out = await Promise.allSettled(Array.from({ length: 6 }, () => mgr.create(USER)));
		expect(out.some((o) => o.status === "fulfilled")).toBe(true);
		expect(await liveFor(db)).toHaveLength(2);
	});

	it("never exceeds the cap (reject)", async () => {
		const db = await makeDb();
		const mgr = createSessionManager({ secret: SECRET, maxConcurrent: 2, onLimit: "reject" }, db);
		const out = await Promise.allSettled(Array.from({ length: 6 }, () => mgr.create(USER)));
		expect(out.filter((o) => o.status === "fulfilled").length).toBeLessThanOrEqual(2);
		expect((await liveFor(db)).length).toBeLessThanOrEqual(2);
	});
});
