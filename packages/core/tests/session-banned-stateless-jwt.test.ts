/** Stateless and JWT session managers refuse banned users, like the database session manager. */
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createJwtSessionModule } from "../src/auth/jwt-session.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { auditLogs, users } from "../src/db/schema.js";
import { createStatelessSessions } from "../src/session/stateless.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function seed(db: Database, id: string, banned: number, banExpiresAt?: Date) {
	const now = new Date();
	await db.insert(users).values({
		id,
		email: `${id}@example.com`,
		banned,
		banExpiresAt: banExpiresAt ?? null,
		createdAt: now,
		updatedAt: now,
	});
}

async function deniedRows(db: Database, userId: string) {
	return (await db.select().from(auditLogs).where(eq(auditLogs.userId, userId))).filter(
		(r) => r.action === "sign_in" && r.result === "denied",
	);
}

describe("JWT session module", () => {
	let db: Database;
	beforeEach(async () => {
		db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
	});

	it("refuses to issue tokens for a banned user and audits it", async () => {
		await seed(db, "bad", 1);
		const jwt = createJwtSessionModule({ secret: SECRET }, db);
		const res = await jwt.createSession({ id: "bad" });
		expect(res.success).toBe(false);
		if (!res.success) {
			expect(res.error.code).toBe("USER_BANNED");
			expect(res.error.message).toBe("Sign-in is not available for this account.");
		}
		expect((await deniedRows(db, "bad")).length).toBe(1);
	});

	it("lets an unbanned user and an expired ban in", async () => {
		await seed(db, "ok", 0);
		await seed(db, "past", 1, new Date(Date.now() - 60_000));
		const jwt = createJwtSessionModule({ secret: SECRET }, db);
		expect((await jwt.createSession({ id: "ok" })).success).toBe(true);
		expect((await jwt.createSession({ id: "past" })).success).toBe(true);
	});

	it("a ban stops refresh token rotation", async () => {
		await seed(db, "later", 0);
		const jwt = createJwtSessionModule({ secret: SECRET }, db);
		const first = await jwt.createSession({ id: "later" });
		if (!first.success) throw new Error("setup failed");
		await db.update(users).set({ banned: 1 }).where(eq(users.id, "later"));
		const refreshed = await jwt.refreshSession(first.data.refreshToken);
		expect(refreshed.success).toBe(false);
		if (!refreshed.success) expect(refreshed.error.code).toBe("USER_BANNED");
	});
});

describe("stateless session manager", () => {
	it("refuses a banned user when given a db, with an audit row", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		await seed(db, "bad", 1);
		await seed(db, "ok", 0);
		const stateless = createStatelessSessions({ secret: SECRET, db });
		const refused = await stateless.createSession({ sub: "bad" });
		expect(refused.success).toBe(false);
		if (!refused.success) expect(refused.error.code).toBe("USER_BANNED");
		expect((await deniedRows(db, "bad")).length).toBe(1);
		expect((await stateless.createSession({ sub: "ok" })).success).toBe(true);
	});

	it("a ban ends a session that was issued before it, when given a db", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		await seed(db, "u1", 0);
		const stateless = createStatelessSessions({ secret: SECRET, db });
		const created = await stateless.createSession({ sub: "u1" });
		if (!created.success) throw new Error("setup failed");
		const cookie = created.data.headers.map((h) => h.split(";")[0]).join("; ");
		expect(await stateless.getSession(cookie)).not.toBeNull();
		await db.update(users).set({ banned: 1 }).where(eq(users.id, "u1"));
		expect(await stateless.getSession(cookie)).toBeNull();
	});

	it("isBanned refuses at create and ends existing sessions at read", async () => {
		const banned = new Set<string>();
		const stateless = createStatelessSessions({
			secret: SECRET,
			isBanned: async (identity) => banned.has(identity.sub),
		});
		const created = await stateless.createSession({ sub: "u1" });
		if (!created.success) throw new Error("setup failed");
		const cookie = created.data.headers.map((h) => h.split(";")[0]).join("; ");
		expect(await stateless.getSession(cookie)).not.toBeNull();
		banned.add("u1");
		expect(await stateless.getSession(cookie)).toBeNull();
		const again = await stateless.createSession({ sub: "u1" });
		expect(again.success).toBe(false);
		if (!again.success) expect(again.error.code).toBe("USER_BANNED");
	});
});
