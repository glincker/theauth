/**
 * Progressive login lockout, ported from the Go library's throttle package.
 *
 * Two independent counters, both kept in secondary storage (atomic `incr`, so they hold across instances when the store is shared):
 * - per account (any client IP): `maxFailures` failures inside `failureWindowSeconds` lock the account for `lockoutSeconds`. Each repeat lockout inside `strikeWindowSeconds` doubles the lock, capped at `maxLockoutSeconds`.
 * - per account plus client IP: after `graceFailures` misses the pair is delayed `baseDelaySeconds`, doubling per extra miss, capped at `maxDelaySeconds`.
 *
 * `check()` reserves an attempt slot with an atomic `incr` before the password is verified, so a parallel burst of N guesses performs at most `maxFailures` password checks, not N. A correct password refunds (clears) the reservation.
 *
 * Decisions come from stored counters only and are keyed by the submitted identifier, never by whether the account exists, so a real and an unknown username behave identically.
 *
 * Trade-off: a per-account lock lets an attacker who knows a username lock its owner out from any IP. The harm is bounded: attempts made while locked are refused before they are counted, so the lock never extends itself, the duration is capped by `maxLockoutSeconds`, escalation forgets after `strikeWindowSeconds`, and an admin can `unlock()` at once. A correct password from a client that is not locked clears the counters.
 */

import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";

export type LockoutScope = "account" | "ip";

export interface LockoutEvent {
	/** Normalised username that was locked. */
	identifier: string;
	scope: LockoutScope;
	/** Client IP when known (always set for `scope: "ip"`). */
	ip: string | null;
	/** Failures that triggered the lock. */
	failures: number;
	/** 1 for the first lockout, higher for repeats inside the strike window. */
	level: number;
	/** When the lock ends. */
	until: Date;
}

export interface LoginLockoutConfig {
	/** Failures per account inside the window that trigger a lockout. Default 10 (`THEAUTH_LOGIN_MAX_FAILURES`). */
	maxFailures?: number;
	/** Fixed window the failure counter lives in, seconds. Default 900 (`THEAUTH_LOGIN_FAILURE_WINDOW_SECONDS`). */
	failureWindowSeconds?: number;
	/** First lockout duration, seconds. Default 900 (`THEAUTH_LOGIN_LOCKOUT_SECONDS`). */
	lockoutSeconds?: number;
	/** Cap for escalated lockouts, seconds. Default 3600 (`THEAUTH_LOGIN_MAX_LOCKOUT_SECONDS`). */
	maxLockoutSeconds?: number;
	/** Repeat lockouts inside this window escalate, seconds. Default 86400. */
	strikeWindowSeconds?: number;
	/** Failures per (account, IP) before backoff starts. Default 3 (`THEAUTH_LOGIN_GRACE_FAILURES`). */
	graceFailures?: number;
	/** First per-IP delay, seconds, doubled per further failure. Default 1. */
	baseDelaySeconds?: number;
	/** Cap for the per-IP delay, seconds. Default 900. */
	maxDelaySeconds?: number;
	/** When the counter store errors: `false` (default) lets the attempt through, `true` refuses it. `THEAUTH_LOGIN_LOCKOUT_FAIL_CLOSED=true` sets it. */
	failClosed?: boolean;
	/** Counter storage. Defaults to the `rateLimit` secondary storage of `createTheAuth`, else process memory. */
	storage?: SecondaryStorage;
	/** Called after a lock is set. Errors are swallowed. For alerting and metrics. */
	onLockout?: (event: LockoutEvent) => void | Promise<void>;
}

export interface LockoutCheck {
	locked: boolean;
	retryAfterSeconds: number;
	/** `unavailable` when the store failed and `failClosed` is on. */
	reason?: LockoutScope | "unavailable";
}

export interface LoginLockout {
	check(identifier: string, ip: string | null): Promise<LockoutCheck>;
	recordFailure(identifier: string, ip: string | null): Promise<void>;
	recordSuccess(identifier: string, ip: string | null): Promise<void>;
	/** Admin override: clears the account lock, counters and escalation, and per-IP entries when the store can `list`. */
	unlock(identifier: string): Promise<void>;
}

export interface LockoutLogger {
	warn(message: string, fields?: Record<string, unknown>): void;
}

/** Thrown by `signIn` while a lockout or backoff is active. */
export class LoginLockedError extends Error {
	readonly retryAfterSeconds: number;
	readonly reason: LockoutScope | "unavailable";

	constructor(retryAfterSeconds: number, reason: LockoutScope | "unavailable") {
		super("Too many failed sign-in attempts");
		this.name = "LoginLockedError";
		this.retryAfterSeconds = retryAfterSeconds;
		this.reason = reason;
	}
}

function env(name: string): string | undefined {
	const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
	const value = proc?.env?.[name];
	return value === undefined || value === "" ? undefined : value;
}

function positive(configured: number | undefined, envName: string, fallback: number): number {
	const raw = configured ?? (env(envName) === undefined ? undefined : Number(env(envName)));
	if (raw === undefined) return fallback;
	if (!Number.isFinite(raw) || raw <= 0) {
		throw new Error(
			`Login lockout: ${envName} / config value must be a positive number, got ${raw}`,
		);
	}
	return Math.floor(raw);
}

/** True when `THEAUTH_LOGIN_LOCKOUT_DISABLED` turns lockout off. */
export function lockoutDisabledByEnv(): boolean {
	const v = env("THEAUTH_LOGIN_LOCKOUT_DISABLED");
	return v === "1" || v?.toLowerCase() === "true";
}

const MAX_IDENT_LENGTH = 128;

export function createLoginLockout(
	config: LoginLockoutConfig = {},
	logger?: LockoutLogger,
): LoginLockout {
	const maxFailures = positive(config.maxFailures, "THEAUTH_LOGIN_MAX_FAILURES", 10);
	const failureWindow = positive(
		config.failureWindowSeconds,
		"THEAUTH_LOGIN_FAILURE_WINDOW_SECONDS",
		900,
	);
	const lockSeconds = positive(config.lockoutSeconds, "THEAUTH_LOGIN_LOCKOUT_SECONDS", 900);
	const maxLockSeconds = Math.max(
		lockSeconds,
		positive(config.maxLockoutSeconds, "THEAUTH_LOGIN_MAX_LOCKOUT_SECONDS", 3600),
	);
	const strikeWindow = positive(
		config.strikeWindowSeconds,
		"THEAUTH_LOGIN_STRIKE_WINDOW_SECONDS",
		86_400,
	);
	const grace = positive(config.graceFailures, "THEAUTH_LOGIN_GRACE_FAILURES", 3);
	const baseDelay = positive(config.baseDelaySeconds, "THEAUTH_LOGIN_BASE_DELAY_SECONDS", 1);
	const maxDelay = Math.max(
		baseDelay,
		positive(config.maxDelaySeconds, "THEAUTH_LOGIN_MAX_DELAY_SECONDS", 900),
	);
	const failClosed =
		config.failClosed ?? env("THEAUTH_LOGIN_LOCKOUT_FAIL_CLOSED")?.toLowerCase() === "true";
	const storage = config.storage ?? memoryStorage();

	if (!failClosed) {
		logger?.warn(
			"login lockout fails open: a counter store error lets password sign-in attempts through unthrottled. Set username.lockout.failClosed to refuse them instead.",
			{ failClosed: false },
		);
	}

	const enc = (ident: string): string => encodeURIComponent(ident.slice(0, MAX_IDENT_LENGTH));
	const keys = {
		fail: (i: string) => `lockout:fail:${enc(i)}`,
		attempt: (i: string) => `lockout:attempt:${enc(i)}`,
		strike: (i: string) => `lockout:strike:${enc(i)}`,
		lock: (i: string) => `lockout:lock:${enc(i)}`,
		ipFail: (i: string, ip: string) => `lockout:ipfail:${enc(i)}:${ip}`,
		ipLock: (i: string, ip: string) => `lockout:iplock:${enc(i)}:${ip}`,
	};

	async function lockedUntil(key: string): Promise<number> {
		const raw = await storage.get(key);
		const until = raw === null ? 0 : Number(raw);
		return Number.isFinite(until) ? until : 0;
	}

	async function notify(event: LockoutEvent): Promise<void> {
		if (!config.onLockout) return;
		try {
			await config.onLockout(event);
		} catch (err) {
			logger?.warn("login lockout onLockout hook failed", {
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}

	function storeFailure(op: string, err: unknown): void {
		logger?.warn(`login lockout store error during ${op}`, {
			failClosed,
			error: err instanceof Error ? err.message : String(err),
		});
	}

	async function check(identifier: string, ip: string | null): Promise<LockoutCheck> {
		try {
			const now = Date.now();
			const accountUntil = await lockedUntil(keys.lock(identifier));
			const ipUntil = ip ? await lockedUntil(keys.ipLock(identifier, ip)) : 0;
			const until = Math.max(accountUntil, ipUntil);
			if (until <= now) {
				// Reserve an attempt slot BEFORE the password is checked (atomic incr), so a parallel burst
				// cannot all pass the check. `recordSuccess` refunds it; a failure keeps it.
				const slot = await storage.incr(keys.attempt(identifier), failureWindow);
				if (slot.count > maxFailures) {
					return {
						locked: true,
						retryAfterSeconds: Math.max(1, Math.ceil((slot.expiresAt - now) / 1000)),
						reason: "account",
					};
				}
				return { locked: false, retryAfterSeconds: 0 };
			}
			return {
				locked: true,
				retryAfterSeconds: Math.max(1, Math.ceil((until - now) / 1000)),
				reason: accountUntil >= ipUntil ? "account" : "ip",
			};
		} catch (err) {
			storeFailure("check", err);
			if (failClosed) return { locked: true, retryAfterSeconds: 30, reason: "unavailable" };
			return { locked: false, retryAfterSeconds: 0 };
		}
	}

	async function recordFailure(identifier: string, ip: string | null): Promise<void> {
		try {
			const now = Date.now();
			const acct = await storage.incr(keys.fail(identifier), failureWindow);
			// Exactly one concurrent failure crosses the threshold, so a lock and its strike are set once.
			if (acct.count === maxFailures) {
				const strike = await storage.incr(keys.strike(identifier), strikeWindow);
				const seconds = Math.min(lockSeconds * 2 ** Math.min(strike.count - 1, 30), maxLockSeconds);
				const until = now + seconds * 1000;
				// Reset the counter so the next window starts clean once the lock lapses.
				await storage.delete(keys.fail(identifier));
				await storage.delete(keys.attempt(identifier));
				await storage.set(keys.lock(identifier), String(until), seconds);
				await notify({
					identifier,
					scope: "account",
					ip,
					failures: acct.count,
					level: strike.count,
					until: new Date(until),
				});
			}
			if (ip) {
				const hit = await storage.incr(keys.ipFail(identifier, ip), failureWindow);
				const over = hit.count - grace;
				if (over > 0) {
					const seconds = Math.min(baseDelay * 2 ** Math.min(over - 1, 30), maxDelay);
					const until = now + seconds * 1000;
					await storage.set(keys.ipLock(identifier, ip), String(until), Math.ceil(seconds));
					if (over === 1) {
						await notify({
							identifier,
							scope: "ip",
							ip,
							failures: hit.count,
							level: 1,
							until: new Date(until),
						});
					}
				}
			}
		} catch (err) {
			// The attempt already failed its password check; there is nothing left to refuse.
			storeFailure("recordFailure", err);
		}
	}

	async function recordSuccess(identifier: string, ip: string | null): Promise<void> {
		try {
			await storage.delete(keys.fail(identifier));
			await storage.delete(keys.attempt(identifier));
			await storage.delete(keys.strike(identifier));
			if (ip) {
				await storage.delete(keys.ipFail(identifier, ip));
				await storage.delete(keys.ipLock(identifier, ip));
			}
		} catch (err) {
			storeFailure("recordSuccess", err);
		}
	}

	async function unlock(identifier: string): Promise<void> {
		await storage.delete(keys.lock(identifier));
		await storage.delete(keys.fail(identifier));
		await storage.delete(keys.attempt(identifier));
		await storage.delete(keys.strike(identifier));
		if (!storage.list) return;
		for (const prefix of [
			`lockout:ipfail:${enc(identifier)}:`,
			`lockout:iplock:${enc(identifier)}:`,
		]) {
			for (const key of await storage.list(prefix)) await storage.delete(key);
		}
	}

	return { check, recordFailure, recordSuccess, unlock };
}
