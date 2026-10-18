/** Tests for the progressive login lockout. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LockoutEvent } from "../src/auth/login-lockout.js";
import { createLoginLockout } from "../src/auth/login-lockout.js";
import { memoryStorage } from "../src/storage/memory.js";
import type { SecondaryStorage } from "../src/storage/types.js";

beforeEach(() => {
	vi.useFakeTimers();
	vi.setSystemTime(new Date("2026-10-17T00:00:00Z"));
});
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllEnvs();
});

async function fail(
	l: ReturnType<typeof createLoginLockout>,
	ident: string,
	ip: string | null,
	n: number,
): Promise<void> {
	for (let i = 0; i < n; i++) await l.recordFailure(ident, ip);
}

describe("account lockout", () => {
	it("locks after maxFailures from many IPs and unlocks after the duration", async () => {
		const l = createLoginLockout({ maxFailures: 5, lockoutSeconds: 60, graceFailures: 100 });
		for (let i = 0; i < 5; i++) await l.recordFailure("alice", `10.0.0.${i}`);
		const c = await l.check("alice", "10.0.0.99");
		expect(c.locked).toBe(true);
		expect(c.reason).toBe("account");
		expect(c.retryAfterSeconds).toBe(60);
		vi.advanceTimersByTime(61_000);
		expect((await l.check("alice", "10.0.0.99")).locked).toBe(false);
	});

	it("does not lock below the threshold", async () => {
		const l = createLoginLockout({ maxFailures: 5, graceFailures: 100 });
		await fail(l, "alice", "1.1.1.1", 4);
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(false);
	});

	it("forgets failures after the window", async () => {
		const l = createLoginLockout({ maxFailures: 3, failureWindowSeconds: 30, graceFailures: 100 });
		await fail(l, "alice", "1.1.1.1", 2);
		vi.advanceTimersByTime(31_000);
		await fail(l, "alice", "1.1.1.1", 2);
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(false);
	});

	it("treats an unknown username exactly like a known one", async () => {
		const l = createLoginLockout({ maxFailures: 3, graceFailures: 100 });
		await fail(l, "ghost-user", "1.1.1.1", 3);
		const c = await l.check("ghost-user", "2.2.2.2");
		expect(c).toEqual({ locked: true, retryAfterSeconds: 900, reason: "account" });
	});

	it("does not extend the lock while locked (bounded lockout)", async () => {
		const l = createLoginLockout({ maxFailures: 3, lockoutSeconds: 100, graceFailures: 100 });
		await fail(l, "alice", null, 3);
		vi.advanceTimersByTime(50_000);
		// Locked attempts are refused before being counted; the caller does not record them.
		const c = await l.check("alice", null);
		expect(c.retryAfterSeconds).toBe(50);
	});

	it("escalates repeat lockouts and caps them", async () => {
		const l = createLoginLockout({
			maxFailures: 2,
			lockoutSeconds: 10,
			maxLockoutSeconds: 35,
			graceFailures: 100,
		});
		const seen: number[] = [];
		for (let round = 0; round < 4; round++) {
			await fail(l, "alice", null, 2);
			const c = await l.check("alice", null);
			seen.push(c.retryAfterSeconds);
			vi.advanceTimersByTime((c.retryAfterSeconds + 1) * 1000);
		}
		expect(seen).toEqual([10, 20, 35, 35]);
	});

	it("clears counters on success", async () => {
		const l = createLoginLockout({ maxFailures: 3, graceFailures: 100 });
		await fail(l, "alice", "1.1.1.1", 2);
		await l.recordSuccess("alice", "1.1.1.1");
		await fail(l, "alice", "1.1.1.1", 2);
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(false);
	});

	it("unlock lifts an account lock and per-IP backoff", async () => {
		const storage = memoryStorage();
		const l = createLoginLockout({ maxFailures: 3, graceFailures: 1, storage });
		await fail(l, "alice", "1.1.1.1", 3);
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(true);
		await l.unlock("alice");
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(false);
	});
});

describe("per IP backoff", () => {
	it("starts after the grace failures, doubles, and caps", async () => {
		const l = createLoginLockout({
			maxFailures: 1000,
			graceFailures: 2,
			baseDelaySeconds: 2,
			maxDelaySeconds: 6,
		});
		await fail(l, "alice", "1.1.1.1", 2);
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(false);
		await l.recordFailure("alice", "1.1.1.1");
		expect((await l.check("alice", "1.1.1.1")).retryAfterSeconds).toBe(2);
		vi.advanceTimersByTime(3000);
		await l.recordFailure("alice", "1.1.1.1");
		expect((await l.check("alice", "1.1.1.1")).retryAfterSeconds).toBe(4);
		vi.advanceTimersByTime(5000);
		await l.recordFailure("alice", "1.1.1.1");
		expect((await l.check("alice", "1.1.1.1")).retryAfterSeconds).toBe(6);
	});

	it("does not delay a different IP for the same account", async () => {
		const l = createLoginLockout({ maxFailures: 1000, graceFailures: 1 });
		await fail(l, "alice", "1.1.1.1", 3);
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(true);
		expect((await l.check("alice", "9.9.9.9")).locked).toBe(false);
	});
});

describe("onLockout", () => {
	it("fires once per account lock with the details", async () => {
		const events: LockoutEvent[] = [];
		const l = createLoginLockout({
			maxFailures: 2,
			graceFailures: 100,
			onLockout: (e) => {
				events.push(e);
			},
		});
		await fail(l, "alice", "1.1.1.1", 2);
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			identifier: "alice",
			scope: "account",
			level: 1,
			ip: "1.1.1.1",
		});
	});

	it("a throwing hook never breaks recording", async () => {
		const l = createLoginLockout({
			maxFailures: 1,
			graceFailures: 100,
			onLockout: () => {
				throw new Error("boom");
			},
		});
		await l.recordFailure("alice", null);
		expect((await l.check("alice", null)).locked).toBe(true);
	});
});

describe("store errors", () => {
	function brokenStorage(): SecondaryStorage {
		const boom = async (): Promise<never> => {
			throw new Error("store down");
		};
		return { get: boom, set: boom, delete: boom, incr: boom };
	}

	it("fails open by default and warns at startup", async () => {
		const warn = vi.fn();
		const l = createLoginLockout({ storage: brokenStorage() }, { warn });
		expect(warn).toHaveBeenCalledWith(expect.stringContaining("fails open"), expect.anything());
		expect((await l.check("alice", "1.1.1.1")).locked).toBe(false);
		await expect(l.recordFailure("alice", "1.1.1.1")).resolves.toBeUndefined();
	});

	it("denies when failClosed is true", async () => {
		const warn = vi.fn();
		const l = createLoginLockout({ storage: brokenStorage(), failClosed: true }, { warn });
		expect(warn).not.toHaveBeenCalledWith(expect.stringContaining("fails open"), expect.anything());
		const c = await l.check("alice", "1.1.1.1");
		expect(c.locked).toBe(true);
		expect(c.reason).toBe("unavailable");
	});

	it("reads failClosed from the environment", async () => {
		vi.stubEnv("THEAUTH_LOGIN_LOCKOUT_FAIL_CLOSED", "true");
		const l = createLoginLockout({ storage: brokenStorage() });
		expect((await l.check("alice", null)).locked).toBe(true);
	});
});

describe("config", () => {
	it("reads thresholds from the environment and prefers explicit config", async () => {
		vi.stubEnv("THEAUTH_LOGIN_MAX_FAILURES", "2");
		const fromEnv = createLoginLockout({ graceFailures: 100 });
		await fail(fromEnv, "a", null, 2);
		expect((await fromEnv.check("a", null)).locked).toBe(true);
		const explicit = createLoginLockout({ maxFailures: 5, graceFailures: 100 });
		await fail(explicit, "a", null, 2);
		expect((await explicit.check("a", null)).locked).toBe(false);
	});

	it("rejects a non positive threshold", () => {
		expect(() => createLoginLockout({ maxFailures: 0 })).toThrow(/positive/);
	});
});
