/** A parallel burst of guesses must be capped by reserving a slot before the password check. */

import { describe, expect, it } from "vitest";
import { createLoginLockout } from "../src/auth/login-lockout.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createSessionManager } from "../src/session/session.js";
import { memoryStorage } from "../src/storage/memory.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

describe("lockout reserves before verifying", () => {
	it("200 parallel guesses with maxFailures 10 perform about 10 password checks", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const sessions = createSessionManager({ secret: SECRET }, db);
		const mod = createUsernameAuthModule(
			{ pbkdf2Iterations: 1000, lockout: { maxFailures: 10 } },
			db,
			sessions,
			undefined,
			{ storage: memoryStorage() },
		);
		await mod.signUp({ username: "alice", password: "Password1!" });
		const results = await Promise.allSettled(
			Array.from({ length: 200 }, (_, i) =>
				mod.signIn({ username: "alice", password: `guess-${i}` }),
			),
		);
		const checked = results.filter(
			(r) =>
				r.status === "rejected" && (r.reason as Error).message === "Invalid username or password",
		).length;
		const refused = results.filter(
			(r) => r.status === "rejected" && (r.reason as Error).name === "LoginLockedError",
		).length;
		expect(checked).toBeLessThanOrEqual(10);
		expect(checked + refused).toBe(200);
	});

	it("a success refunds the reservation and serial failures still lock after maxFailures", async () => {
		const l = createLoginLockout({ maxFailures: 3, storage: memoryStorage() });
		for (let i = 0; i < 2; i++) {
			expect((await l.check("bob", null)).locked).toBe(false);
			await l.recordFailure("bob", null);
		}
		expect((await l.check("bob", null)).locked).toBe(false);
		await l.recordSuccess("bob", null);
		for (let i = 0; i < 3; i++) {
			expect((await l.check("bob", null)).locked).toBe(false);
			await l.recordFailure("bob", null);
		}
		expect((await l.check("bob", null)).locked).toBe(true);
	});

	it("the reservation does not let a locked account extend its own lock", async () => {
		const l = createLoginLockout({ maxFailures: 2, storage: memoryStorage() });
		for (let i = 0; i < 2; i++) {
			await l.check("carol", null);
			await l.recordFailure("carol", null);
		}
		const first = await l.check("carol", null);
		const second = await l.check("carol", null);
		expect(first.locked && second.locked).toBe(true);
		expect(second.retryAfterSeconds).toBeLessThanOrEqual(first.retryAfterSeconds);
	});
});
