/**
 * Regression for the HTTP review: username change-username and change-password act on the
 * signed-in session only, and change-password is a constant answer under the lockout.
 */

import { describe, expect, it } from "vitest";
import type { UsernameAuthModule } from "../src/auth/username.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createSessionManager } from "../src/session/session.js";
import { memoryStorage } from "../src/storage/memory.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function setup(lockout?: { maxFailures: number; lockoutSeconds: number }) {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const sessions = createSessionManager({ secret: SECRET }, db);
	const mod: UsernameAuthModule = createUsernameAuthModule(
		{ pbkdf2Iterations: 1000, ...(lockout && { lockout: { ...lockout, graceFailures: 100 } }) },
		db,
		sessions,
		undefined,
		{ storage: memoryStorage() },
	);
	const victim = await mod.signUp({ username: "alice", password: "Password1!" });
	const attacker = await mod.signUp({ username: "mallory", password: "Attacker1!" });
	return { mod, victim, attacker };
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
	return new Request(`http://app/auth/username/${path}`, {
		method: "POST",
		headers: { "content-type": "application/json", ...headers },
		body: JSON.stringify(body),
	});
}

describe("username change-username needs a session", () => {
	it("refuses an anonymous rename of another account by body userId", async () => {
		const { mod, victim } = await setup();
		const res = await mod.handleRequest(
			post("change-username", { userId: victim.user.id, newUsername: "pwned_alice" }),
		);
		expect(res?.status).toBe(401);
		const signedIn = await mod.signIn({ username: "alice", password: "Password1!" });
		expect(signedIn.user.id).toBe(victim.user.id);
	});

	it("renames the session user, ignoring a foreign body userId", async () => {
		const { mod, victim, attacker } = await setup();
		const res = await mod.handleRequest(
			post(
				"change-username",
				{ userId: victim.user.id, newUsername: "mallory2" },
				{ authorization: `Bearer ${attacker.session.token}` },
			),
		);
		expect(res?.status).toBe(200);
		// The victim keeps their name; the attacker's own account was renamed.
		expect((await mod.signIn({ username: "alice", password: "Password1!" })).user.id).toBe(
			victim.user.id,
		);
		expect((await mod.signIn({ username: "mallory2", password: "Attacker1!" })).user.id).toBe(
			attacker.user.id,
		);
	});

	it("refuses an invalid session token and a non JSON body", async () => {
		const { mod, attacker } = await setup();
		const bad = await mod.handleRequest(
			post("change-username", { newUsername: "zzz" }, { authorization: "Bearer not-a-token" }),
		);
		expect(bad?.status).toBe(401);
		const form = await mod.handleRequest(
			new Request("http://app/auth/username/change-username", {
				method: "POST",
				headers: {
					"content-type": "text/plain",
					cookie: `theauth_session=${attacker.session.token}`,
				},
				body: JSON.stringify({ newUsername: "csrf_name" }),
			}),
		);
		expect(form?.status).toBe(415);
	});
});

describe("username change-password needs a session and gives one answer", () => {
	it("refuses anonymous calls without revealing whether the userId exists", async () => {
		const { mod, victim } = await setup();
		for (const userId of [victim.user.id, "nope"]) {
			const res = await mod.handleRequest(
				post("change-password", { userId, current: "guess", newPassword: "whatever123" }),
			);
			expect(res?.status).toBe(401);
		}
	});

	it("changes only the session user's password and verifies the current one", async () => {
		const { mod, victim, attacker } = await setup();
		const auth = { authorization: `Bearer ${attacker.session.token}` };
		const wrong = await mod.handleRequest(
			post(
				"change-password",
				{ userId: victim.user.id, current: "Password1!", newPassword: "Hijacked123" },
				auth,
			),
		);
		// The victim's password is not the attacker's current password: refused.
		expect(wrong?.status).toBe(400);
		expect(((await wrong?.json()) as { error: string }).error).toBe(
			"Current password is incorrect",
		);
		await expect(mod.signIn({ username: "alice", password: "Password1!" })).resolves.toBeTruthy();

		const ok = await mod.handleRequest(
			post("change-password", { current: "Attacker1!", newPassword: "Attacker2!" }, auth),
		);
		expect(ok?.status).toBe(200);
		await expect(mod.signIn({ username: "mallory", password: "Attacker2!" })).resolves.toBeTruthy();
	});

	it("unknown account and wrong password throw the same error", async () => {
		const { mod, victim } = await setup();
		const unknown = await mod.changePassword("nope", "guess", "whatever123").catch((e) => e);
		const wrong = await mod.changePassword(victim.user.id, "guess", "whatever123").catch((e) => e);
		expect((unknown as Error).message).toBe((wrong as Error).message);
	});

	it("locks change-password guessing per account", async () => {
		const { mod, attacker } = await setup({ maxFailures: 3, lockoutSeconds: 60 });
		const auth = { authorization: `Bearer ${attacker.session.token}` };
		for (let i = 0; i < 3; i++) {
			const res = await mod.handleRequest(
				post("change-password", { current: "guess", newPassword: "whatever123" }, auth),
			);
			expect(res?.status).toBe(400);
		}
		const locked = await mod.handleRequest(
			post("change-password", { current: "Attacker1!", newPassword: "whatever123" }, auth),
		);
		expect(locked?.status).toBe(429);
	});
});
