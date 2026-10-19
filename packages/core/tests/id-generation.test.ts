/** `advanced.database.generateId`: uuid v7, custom functions, refusal of database generated ids. */

import { describe, expect, it } from "vitest";
import { createAnonymousAuthModule } from "../src/auth/anonymous.js";
import { createOAuthModule } from "../src/auth/oauth/module.js";
import { oauthAccounts } from "../src/auth/oauth/schema.js";
import type { OAuthProvider } from "../src/auth/oauth/types.js";
import { createDatabase } from "../src/db/database.js";
import { createIdSource, generateUuidV7, IdGenerationError } from "../src/db/id-generation.js";
import { createTables } from "../src/db/migrations.js";
import { sessions, users } from "../src/db/schema.js";
import { createDatabaseHookRunner } from "../src/hooks/database-hooks.js";
import { createSessionManager } from "../src/session/session.js";
import { createTheAuth } from "../src/theauth.js";
import { createUserModule } from "../src/user/user.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

async function makeDb() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

describe("generateUuidV7", () => {
	it("has the v7 layout and carries the timestamp", () => {
		const now = 1_760_000_000_123;
		const id = generateUuidV7(now);
		expect(id).toMatch(V7);
		const ms = Number.parseInt(id.replace(/-/g, "").slice(0, 12), 16);
		expect(ms).toBe(now);
	});

	it("sorts by creation order, even inside one millisecond and when the clock steps back", () => {
		const t = 1_770_000_000_000;
		const ids = [
			generateUuidV7(t),
			generateUuidV7(t),
			generateUuidV7(t),
			generateUuidV7(t - 5000),
			generateUuidV7(t + 1),
		];
		expect([...ids].sort()).toEqual(ids);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("stays ordered across a counter overflow", () => {
		const t = 1_780_000_000_000;
		const ids = Array.from({ length: 6000 }, () => generateUuidV7(t));
		expect([...ids].sort()).toEqual(ids);
		expect(new Set(ids).size).toBe(ids.length);
	});
});

describe("createIdSource", () => {
	it("defaults to random v4 UUIDs", () => {
		expect(createIdSource(undefined).newId("user")).toMatch(V4);
		expect(createIdSource("uuid").newId("session")).toMatch(V4);
	});

	it("calls a custom function with the model", () => {
		const seen: string[] = [];
		const src = createIdSource(({ model }: { model: string }) => {
			seen.push(model);
			return `${model}_${seen.length}`;
		});
		expect(src.newId("user")).toBe("user_1");
		expect(src.newId("account")).toBe("account_2");
		expect(seen).toEqual(["user", "account"]);
	});

	it.each([false, "serial", "ulid", 42, null])("refuses %j", (value) => {
		expect(() => createIdSource(value)).toThrow(IdGenerationError);
	});

	it("refuses database generated ids with a pointer to the supported options", () => {
		expect(() => createIdSource("serial")).toThrow(/THEAUTH_ID_UNSUPPORTED.*uuidv7/);
	});

	it.each([
		"",
		"a".repeat(192),
		"has space",
		"semi;colon",
		"emoji\u{1F600}",
		42 as unknown as string,
		undefined as unknown as string,
	])("rejects a generator result of %j", (bad) => {
		const src = createIdSource(() => bad);
		expect(() => src.newId("user")).toThrow(/THEAUTH_ID_INVALID/);
	});

	it("accepts the longest allowed id", () => {
		expect(createIdSource(() => "a".repeat(191)).newId("user")).toHaveLength(191);
	});
});

describe("core tables use the configured generator", () => {
	const runner = () => createDatabaseHookRunner(undefined, { generateId: "uuidv7" });

	it("users and sessions", async () => {
		const db = await makeDb();
		const hooks = runner();
		const user = await createUserModule({ db, databaseHooks: hooks }).create({
			email: "a@example.com",
		});
		expect(user.id).toMatch(V7);
		const manager = createSessionManager({ secret: SECRET }, db, hooks);
		const { session } = await manager.create(user.id);
		expect(session.id).toMatch(V7);
		const rows = await db.select().from(sessions);
		expect(rows[0]?.id).toBe(session.id);
	});

	it("keeps an explicit user id", async () => {
		const db = await makeDb();
		const user = await createUserModule({ db, databaseHooks: runner() }).create({
			id: "given",
			email: "g@example.com",
		});
		expect(user.id).toBe("given");
	});

	it("anonymous users", async () => {
		const db = await makeDb();
		const hooks = runner();
		const manager = createSessionManager({ secret: SECRET }, db, hooks);
		const anon = createAnonymousAuthModule({}, db, manager, hooks);
		const { userId } = await anon.createAnonymousUser();
		expect(userId).toMatch(V7);
		expect((await db.select().from(users))[0]?.id).toBe(userId);
	});

	it("OAuth accounts", async () => {
		const db = await makeDb();
		const provider: OAuthProvider = {
			id: "fake",
			name: "Fake",
			authorizationUrl: "https://idp.example/auth",
			tokenUrl: "https://idp.example/token",
			userInfoUrl: "https://idp.example/me",
			scopes: [],
			getAuthorizationUrl: async () => "https://idp.example/auth",
			exchangeCode: async () => ({ accessToken: "at", tokenType: "Bearer", raw: {} }),
			getUserInfo: async () => ({ id: "p1", email: "o@example.com", raw: {} }),
		};
		const hooks = createDatabaseHookRunner(undefined, {
			generateId: ({ model }: { model: string }) => `${model}-fixed`,
		});
		const mod = createOAuthModule(db, {
			providers: { fake: provider },
			redirectUri: "https://app.example/cb",
			databaseHooks: hooks,
		} as never);
		const user = await createUserModule({ db, databaseHooks: hooks }).create({
			email: "o@example.com",
		});
		expect(user.id).toBe("user-fixed");
		await mod.linkAccount(
			user.id,
			"fake",
			{ id: "p1", email: "o@example.com", raw: {} },
			{ accessToken: "at", tokenType: "Bearer", raw: {} },
		);
		const rows = await db.select().from(oauthAccounts);
		expect(rows[0]?.id).toBe("account-fixed");
	});
});

describe("createTheAuth", () => {
	it("applies the option to username sign up and the session", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			secret: SECRET,
			auth: { session: { secret: SECRET } },
			username: {},
			advanced: { database: { generateId: "uuidv7" } },
		});
		const signedUp = await theauth.username?.signUp({ username: "alice", password: "Password1!x" });
		expect(signedUp?.user.id).toMatch(V7);
		const db = theauth.db as Awaited<ReturnType<typeof makeDb>>;
		const rows = await db.select().from(sessions);
		expect(rows[0]?.id).toMatch(V7);
	});

	it("refuses serial ids at startup", async () => {
		await expect(
			createTheAuth({
				database: { provider: "sqlite", url: ":memory:" },
				advanced: { database: { generateId: "serial" as never } },
			}),
		).rejects.toThrow(/THEAUTH_ID_UNSUPPORTED/);
	});
});
