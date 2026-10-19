/** Per-model database hooks: abort, payload replace, fail closed, and claim path safety. */

import { describe, expect, it, vi } from "vitest";
import { createMagicLinkModule } from "../src/auth/magic-link.js";
import { createOAuthModule } from "../src/auth/oauth/module.js";
import { oauthAccounts } from "../src/auth/oauth/schema.js";
import type { OAuthProvider } from "../src/auth/oauth/types.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { sessions, users } from "../src/db/schema.js";
import type { DatabaseHooks } from "../src/hooks/database-hooks.js";
import { createDatabaseHookRunner, DatabaseHookError } from "../src/hooks/database-hooks.js";
import { createCookieSessionManager } from "../src/session/manager.js";
import { createSessionManager } from "../src/session/session.js";
import { createUserModule } from "../src/user/user.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function makeDb() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function codeOf(p: Promise<unknown>): Promise<string | undefined> {
	try {
		await p;
		return undefined;
	} catch (err) {
		return err instanceof DatabaseHookError ? err.code : "OTHER";
	}
}

describe("database hook runner", () => {
	const base = { id: "u1", email: "a@example.com", name: null, metadata: null };

	it("is inactive without hooks", async () => {
		const runner = createDatabaseHookRunner(undefined);
		expect(runner.active).toBe(false);
		expect(runner.has("user", "create")).toBe(false);
		expect(await runner.before("user", "create", base)).toEqual(base);
	});

	it("aborts on false", async () => {
		const runner = createDatabaseHookRunner({ user: { create: { before: () => false } } });
		expect(await codeOf(runner.before("user", "create", base))).toBe("DATABASE_HOOK_ABORTED");
	});

	it("replaces allowed fields and normalizes the email", async () => {
		const runner = createDatabaseHookRunner({
			user: { create: { before: () => ({ data: { name: "Ada", email: "ADA@Example.com" } }) } },
		});
		const out = await runner.before("user", "create", base);
		expect(out).toEqual({ ...base, name: "Ada", email: "ada@example.com" });
	});

	it("rejects an attempt to replace id or an unknown field", async () => {
		const runner = createDatabaseHookRunner({
			user: {
				create: { before: () => ({ data: { id: "evil" } }) as never },
			},
		});
		expect(await codeOf(runner.before("user", "create", base))).toBe(
			"DATABASE_HOOK_INVALID_PAYLOAD",
		);
	});

	it("fails closed on a throw even when hookSafety says allow", async () => {
		const runner = createDatabaseHookRunner(
			{
				user: {
					create: {
						before: () => {
							throw new Error("boom");
						},
					},
				},
			},
			{ hookSafety: { onError: "allow", onTimeout: "allow" } },
		);
		expect(await codeOf(runner.before("user", "create", base))).toBe("DATABASE_HOOK_FAILED");
	});

	it("fails closed on a timeout", async () => {
		const runner = createDatabaseHookRunner(
			{ user: { create: { before: () => new Promise(() => {}) } } },
			{ hookSafety: { timeoutMs: 20 } },
		);
		expect(await codeOf(runner.before("user", "create", base))).toBe("DATABASE_HOOK_TIMEOUT");
	});

	it("fails closed on a malformed result", async () => {
		const runner = createDatabaseHookRunner({
			user: { create: { before: () => "nope" as never } },
		});
		expect(await codeOf(runner.before("user", "create", base))).toBe(
			"DATABASE_HOOK_INVALID_PAYLOAD",
		);
	});

	it("swallows and logs after hook errors", async () => {
		const warn = vi.fn();
		const runner = createDatabaseHookRunner(
			{
				user: {
					create: {
						after: () => {
							throw new Error("late");
						},
					},
				},
			},
			{ logger: { warn, error: vi.fn() } },
		);
		await expect(runner.after("user", "create", base)).resolves.toBeUndefined();
		expect(warn).toHaveBeenCalledOnce();
	});

	it("hands hooks a copy so mutating it does not change what is stored", async () => {
		const runner = createDatabaseHookRunner({
			user: {
				create: {
					before: (data) => {
						data.email = "mutated@example.com";
						return undefined;
					},
				},
			},
		});
		expect((await runner.before("user", "create", base)).email).toBe("a@example.com");
	});
});

describe("user hooks", () => {
	it("replaces the payload and runs after with the stored row", async () => {
		const db = await makeDb();
		const after = vi.fn();
		const runner = createDatabaseHookRunner({
			user: {
				create: {
					before: (d) => ({ data: { name: d.name ?? "Default", metadata: { src: "hook" } } }),
					after,
				},
			},
		});
		const mod = createUserModule({ db, databaseHooks: runner });
		const user = await mod.create({ email: "x@example.com" });
		expect(user.name).toBe("Default");
		expect(user.metadata).toEqual({ src: "hook" });
		expect(after).toHaveBeenCalledOnce();
		expect(after.mock.calls[0]?.[0]).toMatchObject({ id: user.id, name: "Default" });
	});

	it("an abort writes no row", async () => {
		const db = await makeDb();
		const mod = createUserModule({
			db,
			databaseHooks: createDatabaseHookRunner({ user: { create: { before: () => false } } }),
		});
		expect(await codeOf(mod.create({ email: "no@example.com" }))).toBe("DATABASE_HOOK_ABORTED");
		expect(await db.select().from(users)).toHaveLength(0);
	});

	it("does not fire for an idempotent repeat create", async () => {
		const db = await makeDb();
		const before = vi.fn(() => undefined);
		const mod = createUserModule({
			db,
			databaseHooks: createDatabaseHookRunner({ user: { create: { before } } }),
		});
		await mod.create({ email: "r@example.com" });
		await mod.create({ email: "r@example.com" });
		expect(before).toHaveBeenCalledOnce();
	});

	it("a replaced email that already exists returns that user", async () => {
		const db = await makeDb();
		const plain = createUserModule({ db });
		const existing = await plain.create({ email: "taken@example.com" });
		const mod = createUserModule({
			db,
			databaseHooks: createDatabaseHookRunner({
				user: { create: { before: () => ({ data: { email: "taken@example.com" } }) } },
			}),
		});
		const got = await mod.create({ email: "new@example.com" });
		expect(got.id).toBe(existing.id);
		expect(await db.select().from(users)).toHaveLength(1);
	});
});

async function seedUser(db: Awaited<ReturnType<typeof makeDb>>, id = "u-1") {
	await createUserModule({ db }).create({ id, email: `${id}@example.com` });
	return id;
}

describe("session hooks", () => {
	it("replaces expiresAt, keeps internal metadata keys, runs after", async () => {
		const db = await makeDb();
		const userId = await seedUser(db);
		const after = vi.fn();
		const later = new Date(Date.now() + 3600_000);
		const mgr = createSessionManager(
			{ secret: SECRET },
			db,
			createDatabaseHookRunner({
				session: {
					create: {
						before: () => ({ data: { expiresAt: later, metadata: { tag: "x" } } }),
						after,
					},
				},
			}),
		);
		const { session } = await mgr.create(userId, { orig: 1 }, { authMethods: ["password"] });
		expect(session.expiresAt.getTime()).toBe(later.getTime());
		expect(session.metadata).toEqual({ tag: "x" });
		expect(session.auth?.amr).toContain("pwd");
		expect(after).toHaveBeenCalledOnce();
	});

	it("an abort writes no session and evicts nobody", async () => {
		const db = await makeDb();
		const userId = await seedUser(db);
		let allow = true;
		const mgr = createSessionManager(
			{ secret: SECRET, maxConcurrent: 1 },
			db,
			createDatabaseHookRunner({
				session: { create: { before: () => (allow ? undefined : false) } },
			}),
		);
		const first = await mgr.create(userId);
		allow = false;
		expect(await codeOf(mgr.create(userId))).toBe("DATABASE_HOOK_ABORTED");
		expect(await mgr.validate(first.token)).not.toBeNull();
		expect(await db.select().from(sessions)).toHaveLength(1);
	});

	it("a refresh abort leaves the old session usable", async () => {
		const db = await makeDb();
		const userId = await seedUser(db);
		let allow = true;
		const runner = createDatabaseHookRunner({
			session: { create: { before: () => (allow ? undefined : false) } },
		});
		const mgr = createCookieSessionManager({ secret: SECRET }, db, runner);
		const { session } = await mgr.createSession(userId);
		allow = false;
		await expect(mgr.refreshSession(session.id)).rejects.toBeInstanceOf(DatabaseHookError);
		const rows = await db.select().from(sessions);
		expect(rows.map((r) => r.id)).toEqual([session.id]);
	});

	it("concurrent refreshes still leave one session and fire after once", async () => {
		const db = await makeDb();
		const userId = await seedUser(db);
		const after = vi.fn();
		const runner = createDatabaseHookRunner({ session: { create: { after } } });
		const mgr = createCookieSessionManager({ secret: SECRET }, db, runner);
		const { session } = await mgr.createSession(userId);
		after.mockClear();
		const results = await Promise.all(
			Array.from({ length: 5 }, () => mgr.refreshSession(session.id)),
		);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		expect(await db.select().from(sessions)).toHaveLength(1);
		expect(after).toHaveBeenCalledOnce();
	});

	it("update hook sees recordAuth and cannot overwrite the step-up proof", async () => {
		const db = await makeDb();
		const userId = await seedUser(db);
		const after = vi.fn();
		const mgr = createSessionManager(
			{ secret: SECRET },
			db,
			createDatabaseHookRunner({
				session: {
					update: { before: () => ({ data: { metadata: { only: "this" } } }), after },
				},
			}),
		);
		const { session } = await mgr.create(userId, undefined, { authMethods: ["password"] });
		const updated = await mgr.recordAuth(session.id, "totp");
		expect(updated?.auth?.amr).toContain("otp");
		expect(updated?.metadata).toEqual({ only: "this" });
		expect(after).toHaveBeenCalledOnce();
	});
});

function stubProvider(): OAuthProvider {
	return {
		id: "mock",
		name: "Mock",
		authorizationUrl: "https://mock.example/auth",
		tokenUrl: "https://mock.example/token",
		userInfoUrl: "https://mock.example/userinfo",
		scopes: [],
		exchangeCode: async () => ({ accessToken: "a", tokenType: "Bearer", raw: {} }),
		getUserInfo: async () => ({ id: "p-1", raw: {} }),
	} as unknown as OAuthProvider;
}

describe("account hooks", () => {
	async function setup(hooks: DatabaseHooks) {
		const db = await makeDb();
		const userId = await seedUser(db);
		const mod = createOAuthModule(db, {
			providers: { mock: stubProvider() },
			databaseHooks: createDatabaseHookRunner(hooks),
		});
		return { db, userId, mod };
	}
	const tokens = { accessToken: "tok", tokenType: "Bearer", raw: {} };

	it("replaces expiresAt on create and fires after", async () => {
		const exp = new Date(Math.floor((Date.now() + 5000_000) / 1000) * 1000);
		const after = vi.fn();
		const { db, userId, mod } = await setup({
			account: { create: { before: () => ({ data: { expiresAt: exp } }), after } },
		});
		const acct = await mod.linkAccount(userId, "mock", { id: "p-1", raw: {} }, tokens);
		expect(acct.expiresAt?.getTime()).toBe(exp.getTime());
		expect(after).toHaveBeenCalledOnce();
		expect(await db.select().from(oauthAccounts)).toHaveLength(1);
	});

	it("an abort writes no account row", async () => {
		const { db, userId, mod } = await setup({ account: { create: { before: () => false } } });
		expect(await codeOf(mod.linkAccount(userId, "mock", { id: "p-1", raw: {} }, tokens))).toBe(
			"DATABASE_HOOK_ABORTED",
		);
		expect(await db.select().from(oauthAccounts)).toHaveLength(0);
	});

	it("a second link of the same account is an update", async () => {
		const update = vi.fn(() => undefined);
		const { userId, mod } = await setup({ account: { update: { before: update } } });
		await mod.linkAccount(userId, "mock", { id: "p-1", raw: {} }, tokens);
		await mod.linkAccount(userId, "mock", { id: "p-1", raw: {} }, tokens);
		expect(update).toHaveBeenCalledOnce();
	});
});

describe("single-use claim paths", () => {
	it("a magic link redeems once under concurrency and the user hook fires once", async () => {
		const db = await makeDb();
		let token = "";
		const before = vi.fn(() => undefined);
		const after = vi.fn();
		const runner = createDatabaseHookRunner({ user: { create: { before, after } } });
		const mod = createMagicLinkModule(
			{
				sendMagicLink: async (_e, t) => {
					token = t;
				},
				appUrl: "https://app.example.com",
			},
			db,
			createSessionManager({ secret: SECRET }, db, runner),
			undefined,
			runner,
		);
		await mod.sendLink("claim@example.com");
		const results = await Promise.all(Array.from({ length: 6 }, () => mod.verify(token)));
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		expect(before).toHaveBeenCalledOnce();
		expect(after).toHaveBeenCalledOnce();
		expect(await db.select().from(sessions)).toHaveLength(1);
	});

	it("a user abort while the link is created fails closed with no user or session", async () => {
		const db = await makeDb();
		const runner = createDatabaseHookRunner({ user: { create: { before: () => false } } });
		const mod = createMagicLinkModule(
			{
				sendMagicLink: async () => {},
				appUrl: "https://app.example.com",
			},
			db,
			createSessionManager({ secret: SECRET }, db, runner),
			undefined,
			runner,
		);
		expect(await codeOf(mod.sendLink("deny@example.com"))).toBe("DATABASE_HOOK_ABORTED");
		expect(await db.select().from(users)).toHaveLength(0);
		expect(await db.select().from(sessions)).toHaveLength(0);
	});
});
