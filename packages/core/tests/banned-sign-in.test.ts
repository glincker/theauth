/** A banned user cannot start a session on any sign-in path, gets a generic error, and leaves a denied audit row. */
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { auditLogs, magicLinks, users } from "../src/db/schema.js";
import { UserBannedError } from "../src/session/banned.js";
import { createSessionManager } from "../src/session/session.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function setup() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const sessions = createSessionManager({ secret: SECRET }, db);
	return { db, sessions };
}

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

describe("session creation refuses banned users", () => {
	let db: Database;
	let sessions: ReturnType<typeof createSessionManager>;
	beforeEach(async () => {
		({ db, sessions } = await setup());
	});

	it("throws a generic error and writes a denied audit row", async () => {
		await seed(db, "bad", 1);
		await expect(sessions.create("bad")).rejects.toBeInstanceOf(UserBannedError);
		await expect(sessions.create("bad")).rejects.toThrow(
			"Sign-in is not available for this account.",
		);
		const rows = await deniedRows(db, "bad");
		expect(rows.length).toBe(2);
		expect(rows[0]?.reason).toBe("user_banned");
		expect(await sessions.list("bad")).toHaveLength(0);
	});

	it("lets an unbanned user and a user whose ban expired in", async () => {
		await seed(db, "ok", 0);
		await seed(db, "past", 1, new Date(Date.now() - 60_000));
		expect((await sessions.create("ok")).token).toBeTruthy();
		expect((await sessions.create("past")).token).toBeTruthy();
	});

	it("still refuses while a timed ban is running", async () => {
		await seed(db, "soon", 1, new Date(Date.now() + 60_000));
		await expect(sessions.create("soon")).rejects.toBeInstanceOf(UserBannedError);
	});
});

describe("sign-in paths", () => {
	it("password (username) sign-in is refused after a ban", async () => {
		const { db, sessions } = await setup();
		const mod = createUsernameAuthModule({}, db, sessions);
		const up = await mod.signUp({ username: "alice", password: "Password1!" });
		await db.update(users).set({ banned: 1 }).where(eq(users.id, up.user.id));
		await expect(mod.signIn({ username: "alice", password: "Password1!" })).rejects.toBeInstanceOf(
			UserBannedError,
		);
		expect((await deniedRows(db, up.user.id)).length).toBeGreaterThan(0);
	});

	it("magic link verification is refused after a ban", async () => {
		const { db, sessions } = await setup();
		const mod = createMagicLinkModule(
			{ sendMagicLink: async () => {}, appUrl: "https://app.example.com" },
			db,
			sessions,
		);
		await mod.sendLink("carol@example.com");
		await db.update(users).set({ banned: 1 }).where(eq(users.email, "carol@example.com"));
		const [link] = await db.select().from(magicLinks);
		await expect(mod.verify(link?.token ?? "")).rejects.toBeInstanceOf(UserBannedError);
	});
});
