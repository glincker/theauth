/** Tests for username + password authentication. */

import { beforeEach, describe, expect, it } from "vitest";
import type { UsernameAuthModule } from "../src/auth/username.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createSessionManager } from "../src/session/session.js";

const SESSION_SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeModule(db: Database, overrides?: object): UsernameAuthModule {
	const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
	return createUsernameAuthModule({ ...overrides }, db, sessionManager);
}

describe("UsernameAuthModule.signUp", () => {
	let db: Database;
	let mod: UsernameAuthModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
	});

	it("returns user and session on valid input", async () => {
		const result = await mod.signUp({ username: "alice", password: "Password1!" });
		expect(result.user.username).toBe("alice");
		expect(result.user.id).toBeTruthy();
		expect(result.session.token).toBeTruthy();
		expect(result.session.expiresAt).toBeInstanceOf(Date);
	});

	it("normalises username to lowercase by default", async () => {
		const result = await mod.signUp({ username: "Alice", password: "Password1!" });
		expect(result.user.username).toBe("alice");
	});

	it("preserves username case when caseSensitive is true", async () => {
		const m = makeModule(db, { caseSensitive: true });
		const result = await m.signUp({ username: "Alice", password: "Password1!" });
		expect(result.user.username).toBe("Alice");
	});

	it("stores the optional name field", async () => {
		const result = await mod.signUp({ username: "bob", password: "Password1!", name: "Bob" });
		expect(result.user.name).toBe("Bob");
	});

	it("rejects username shorter than minUsernameLength", async () => {
		await expect(mod.signUp({ username: "ab", password: "Password1!" })).rejects.toThrow(
			/at least/,
		);
	});

	it("rejects username with invalid characters", async () => {
		await expect(mod.signUp({ username: "hello world", password: "Password1!" })).rejects.toThrow(
			/invalid characters/,
		);
	});

	it("rejects duplicate username", async () => {
		await mod.signUp({ username: "carol", password: "Password1!" });
		await expect(mod.signUp({ username: "carol", password: "Password2!" })).rejects.toThrow(
			/already taken/,
		);
	});

	it("rejects password shorter than minimum", async () => {
		const m = makeModule(db, { password: { minLength: 12 } });
		await expect(m.signUp({ username: "dave", password: "short" })).rejects.toThrow(/at least/);
	});
});

describe("UsernameAuthModule.signIn", () => {
	let db: Database;
	let mod: UsernameAuthModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
		await mod.signUp({ username: "testuser", password: "CorrectPass1!" });
	});

	it("returns user and session on correct credentials", async () => {
		const result = await mod.signIn({ username: "testuser", password: "CorrectPass1!" });
		expect(result.user.username).toBe("testuser");
		expect(result.session.token).toBeTruthy();
	});

	it("throws on wrong password", async () => {
		await expect(mod.signIn({ username: "testuser", password: "WrongPass1!" })).rejects.toThrow(
			/Invalid username or password/,
		);
	});

	it("throws on unknown username", async () => {
		await expect(mod.signIn({ username: "nobody", password: "CorrectPass1!" })).rejects.toThrow(
			/Invalid username or password/,
		);
	});

	it("is case-insensitive for username by default", async () => {
		const result = await mod.signIn({ username: "TestUser", password: "CorrectPass1!" });
		expect(result.user.username).toBe("testuser");
	});
});

describe("UsernameAuthModule.changePassword", () => {
	let db: Database;
	let mod: UsernameAuthModule;
	let userId: string;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
		const result = await mod.signUp({ username: "passuser", password: "OldPass1!" });
		userId = result.user.id;
	});

	it("succeeds with correct current password", async () => {
		const result = await mod.changePassword(userId, "OldPass1!", "NewPass1!");
		expect(result.success).toBe(true);
	});

	it("throws on wrong current password", async () => {
		await expect(mod.changePassword(userId, "WrongPass1!", "NewPass1!")).rejects.toThrow(
			/Current password is incorrect/,
		);
	});

	it("new password works after change", async () => {
		await mod.changePassword(userId, "OldPass1!", "NewPass2!");
		const result = await mod.signIn({ username: "passuser", password: "NewPass2!" });
		expect(result.session.token).toBeTruthy();
	});
});

describe("UsernameAuthModule.changeUsername", () => {
	let db: Database;
	let mod: UsernameAuthModule;
	let userId: string;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
		const result = await mod.signUp({ username: "oldname", password: "Password1!" });
		userId = result.user.id;
	});

	it("succeeds and sign-in works with new username", async () => {
		await mod.changeUsername(userId, "newname");
		const result = await mod.signIn({ username: "newname", password: "Password1!" });
		expect(result.user.username).toBe("newname");
	});

	it("normalises new username to lowercase", async () => {
		const result = await mod.changeUsername(userId, "NewName");
		expect(result.success).toBe(true);
	});
});

describe("UsernameAuthModule.handleRequest", () => {
	let db: Database;
	let mod: UsernameAuthModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
	});

	it("POST /auth/username/sign-up returns 201", async () => {
		const req = new Request("https://app.example.com/auth/username/sign-up", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "newuser", password: "Password1!" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(201);
		const body = await res?.json();
		expect(body.user.username).toBe("newuser");
	});

	it("POST /auth/username/sign-up returns 400 when fields are missing", async () => {
		const req = new Request("https://app.example.com/auth/username/sign-up", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "missingpass" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(400);
	});

	it("POST /auth/username/sign-in returns 200 on correct credentials", async () => {
		await mod.signUp({ username: "loginuser", password: "Password1!" });
		const req = new Request("https://app.example.com/auth/username/sign-in", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "loginuser", password: "Password1!" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
	});

	it("POST /auth/username/sign-in returns 401 on bad password", async () => {
		await mod.signUp({ username: "badpassuser", password: "Password1!" });
		const req = new Request("https://app.example.com/auth/username/sign-in", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "badpassuser", password: "WrongPass!" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(401);
	});

	it("returns null for unmatched paths", async () => {
		const req = new Request("https://app.example.com/something-else", { method: "POST" });
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});

	it("returns null for non-POST requests", async () => {
		const req = new Request("https://app.example.com/auth/username/sign-up");
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});
});

describe("UsernameAuthModule.signIn: forcePasswordReset", () => {
	let db: Database;
	let mod: UsernameAuthModule;
	let userId: string;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
		const result = await mod.signUp({ username: "resetuser", password: "CorrectPass1!" });
		userId = result.user.id;
	});

	it("throws 'Password reset required' when forcePasswordReset=1", async () => {
		const { eq } = await import("drizzle-orm");
		const { users } = await import("../src/db/schema.js");
		await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, userId));

		await expect(mod.signIn({ username: "resetuser", password: "CorrectPass1!" })).rejects.toThrow(
			"Password reset required",
		);
	});

	it("signs in normally when forcePasswordReset=0", async () => {
		const { eq } = await import("drizzle-orm");
		const { users } = await import("../src/db/schema.js");
		await db.update(users).set({ forcePasswordReset: 0 }).where(eq(users.id, userId));

		const result = await mod.signIn({ username: "resetuser", password: "CorrectPass1!" });
		expect(result.session.token).toBeTruthy();
	});

	it("handleRequest returns 403 with PASSWORD_RESET_REQUIRED when forcePasswordReset=1", async () => {
		const { eq } = await import("drizzle-orm");
		const { users } = await import("../src/db/schema.js");
		await db.update(users).set({ forcePasswordReset: 1 }).where(eq(users.id, userId));

		const req = new Request("https://app.example.com/auth/username/sign-in", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ username: "resetuser", password: "CorrectPass1!" }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(403);
		const body = await res?.json();
		expect(body.error.code).toBe("PASSWORD_RESET_REQUIRED");
	});
});
