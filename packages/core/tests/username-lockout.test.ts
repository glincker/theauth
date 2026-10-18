/** Lockout behavior of username sign-in: response shape, timing path and wiring. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LoginLockedError } from "../src/auth/login-lockout.js";
import type { UsernameAuthConfig, UsernameAuthModule } from "../src/auth/username.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createSessionManager } from "../src/session/session.js";
import { memoryStorage } from "../src/storage/memory.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const PROXY = { trustedHeader: "x-real-ip" };

async function setup(config: UsernameAuthConfig): Promise<UsernameAuthModule> {
	const db: Database = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const sessions = createSessionManager({ secret: SECRET }, db);
	const mod = createUsernameAuthModule(
		{ pbkdf2Iterations: 1000, trustedProxy: PROXY, ...config },
		db,
		sessions,
		undefined,
		{ storage: memoryStorage() },
	);
	await mod.signUp({ username: "alice", password: "Password1!" });
	return mod;
}

function req(username: string, password: string, ip: string): Request {
	return new Request("http://localhost/auth/username/sign-in", {
		method: "POST",
		headers: { "x-real-ip": ip, "content-type": "application/json" },
		body: JSON.stringify({ username, password }),
	});
}

async function wrong(mod: UsernameAuthModule, username: string, ip: string, n: number) {
	for (let i = 0; i < n; i++) {
		await mod
			.signIn({ username, password: "wrong-password" }, { request: req(username, "x", ip) })
			.catch(() => undefined);
	}
}

beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllEnvs();
});

describe("username sign-in lockout", () => {
	it("locks the account for the right password too, then unlocks after the window", async () => {
		const mod = await setup({
			lockout: { maxFailures: 3, lockoutSeconds: 60, graceFailures: 100 },
		});
		await wrong(mod, "alice", "1.1.1.1", 3);
		const ctx = { request: req("alice", "Password1!", "9.9.9.9") };
		await expect(
			mod.signIn({ username: "alice", password: "Password1!" }, ctx),
		).rejects.toBeInstanceOf(LoginLockedError);
		vi.advanceTimersByTime(61_000);
		const ok = await mod.signIn({ username: "alice", password: "Password1!" }, ctx);
		expect(ok.user.username).toBe("alice");
	});

	it("locks unknown usernames with an identical response", async () => {
		const mod = await setup({ lockout: { maxFailures: 3, graceFailures: 100 } });
		await wrong(mod, "alice", "1.1.1.1", 3);
		await wrong(mod, "nobody", "1.1.1.1", 3);
		const a = await mod.handleRequest(req("alice", "x", "2.2.2.2"));
		const b = await mod.handleRequest(req("nobody", "x", "2.2.2.2"));
		expect(a?.status).toBe(429);
		expect(b?.status).toBe(429);
		expect(await a?.json()).toEqual(await b?.json());
		expect(a?.headers.get("retry-after")).toBe(b?.headers.get("retry-after"));
	});

	it("keeps the 401 shape identical for wrong password and unknown user below the limit", async () => {
		const mod = await setup({ lockout: { maxFailures: 50, graceFailures: 100 } });
		const a = await mod.handleRequest(req("alice", "bad-password", "3.3.3.3"));
		const b = await mod.handleRequest(req("nobody", "bad-password", "3.3.3.3"));
		expect(a?.status).toBe(401);
		expect(b?.status).toBe(401);
		expect(await a?.json()).toEqual(await b?.json());
	});

	it("a successful sign-in clears the counters", async () => {
		const mod = await setup({ lockout: { maxFailures: 3, graceFailures: 100 } });
		await wrong(mod, "alice", "1.1.1.1", 2);
		await mod.signIn(
			{ username: "alice", password: "Password1!" },
			{ request: req("alice", "x", "1.1.1.1") },
		);
		await wrong(mod, "alice", "1.1.1.1", 2);
		const res = await mod.handleRequest(req("alice", "Password1!", "1.1.1.1"));
		expect(res?.status).toBe(200);
	});

	it("unlockAccount lifts a lock at once", async () => {
		const mod = await setup({ lockout: { maxFailures: 2, graceFailures: 100 } });
		await wrong(mod, "alice", "1.1.1.1", 2);
		expect((await mod.handleRequest(req("alice", "Password1!", "1.1.1.1")))?.status).toBe(429);
		await mod.unlockAccount("alice");
		expect((await mod.handleRequest(req("alice", "Password1!", "1.1.1.1")))?.status).toBe(200);
	});

	it("per IP backoff slows one IP without locking the owner out elsewhere", async () => {
		const mod = await setup({ lockout: { maxFailures: 1000, graceFailures: 2 } });
		await wrong(mod, "alice", "6.6.6.6", 4);
		expect((await mod.handleRequest(req("alice", "Password1!", "6.6.6.6")))?.status).toBe(429);
		expect((await mod.handleRequest(req("alice", "Password1!", "7.7.7.7")))?.status).toBe(200);
	});

	it("lockout: false disables it", async () => {
		const mod = await setup({ lockout: false });
		await wrong(mod, "alice", "1.1.1.1", 30);
		expect((await mod.handleRequest(req("alice", "Password1!", "1.1.1.1")))?.status).toBe(200);
	});

	it("THEAUTH_LOGIN_LOCKOUT_DISABLED disables it", async () => {
		vi.stubEnv("THEAUTH_LOGIN_LOCKOUT_DISABLED", "true");
		const mod = await setup({});
		await wrong(mod, "alice", "1.1.1.1", 30);
		expect((await mod.handleRequest(req("alice", "Password1!", "1.1.1.1")))?.status).toBe(200);
	});

	it("is on by default", async () => {
		const mod = await setup({ lockout: { graceFailures: 1000 } });
		await wrong(mod, "alice", "1.1.1.1", 10);
		expect((await mod.handleRequest(req("alice", "Password1!", "1.1.1.1")))?.status).toBe(429);
	});

	it("onLockout reports the account lock", async () => {
		const onLockout = vi.fn();
		const mod = await setup({ lockout: { maxFailures: 2, graceFailures: 100, onLockout } });
		await wrong(mod, "alice", "1.1.1.1", 2);
		expect(onLockout).toHaveBeenCalledWith(
			expect.objectContaining({ identifier: "alice", scope: "account" }),
		);
	});
});
