/**
 * Username + password authentication for TheAuth.
 * Usernames are normalised to lowercase by default. Passwords are hashed with scrypt before storage so a database breach does not expose credentials.
 *
 * @example
 * ```typescript
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   username: {
 *     password: { minLength: 8 },
 *   },
 * });
 *
 * const response = await theauth.username?.handleRequest(request);
 * if (response) return response;
 * ```
 */

import { and, eq } from "drizzle-orm";
import {
	generateId,
	pbkdf2Hash,
	pbkdf2NeedsRehash,
	pbkdf2Verify,
	resolvePbkdf2Iterations,
} from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { TrustedProxyConfig } from "./client-ip.js";
import { resolveClientIp } from "./client-ip.js";
import type { LockoutLogger, LoginLockout, LoginLockoutConfig } from "./login-lockout.js";
import { createLoginLockout, LoginLockedError, lockoutDisabledByEnv } from "./login-lockout.js";
import type { SignInGate } from "./sign-in-gate.js";
import { createSignInGate, SignInGateError } from "./sign-in-gate.js";
import { CHANGE_PASSWORD_REFUSED, createUsernameRequestHandler } from "./username-http.js";

export interface UsernameAuthConfig {
	/** Minimum username length (default: 3) */
	minUsernameLength?: number;
	/** Maximum username length (default: 32) */
	maxUsernameLength?: number;
	/** Allowed characters pattern (default: /^[a-zA-Z0-9_-]+$/) */
	allowedPattern?: RegExp;
	/** Whether usernames are case-sensitive (default: false, normalise to lowercase) */
	caseSensitive?: boolean;
	/** PBKDF2-SHA256 iteration target (default: `THEAUTH_PBKDF2_ITERATIONS` or 600000). Hashes below it are upgraded on successful sign-in. */
	pbkdf2Iterations?: number;
	password?: {
		/** Minimum password length (default: 8) */
		minLength?: number;
		/** Maximum password length (default: 128) */
		maxLength?: number;
	};
	/**
	 * Failed sign-in lockout (per account plus per client IP, progressive, with a cap). On by default: 10 failures per 15 minutes lock the account for 15 minutes, doubling per repeat up to 1 hour. `false` (or `THEAUTH_LOGIN_LOCKOUT_DISABLED=true`) turns it off. See `LoginLockoutConfig` for every threshold and its env override.
	 */
	lockout?: false | LoginLockoutConfig;
	/** How to find the client IP for the per-IP backoff. Without it the IP is unknown and only the per-account lockout applies. */
	trustedProxy?: TrustedProxyConfig;
}

/** Collaborators the lockout needs, supplied by `createTheAuth`. */
export interface UsernameAuthDeps {
	/** Counter store for lockout state, usually the `rateLimit` secondary storage. */
	storage?: SecondaryStorage;
	/** Receives the startup warning when lockout fails open. */
	logger?: LockoutLogger;
}

export interface UsernameAuthModule {
	signUp: (input: { username: string; password: string; name?: string }) => Promise<{
		user: { id: string; username: string; name: string | null };
		session: { token: string; expiresAt: Date };
	}>;
	/** Throws `SignInGateError` (message "Password reset required" or "Two-factor authentication required") with a challenge when the sign-in gate does not allow a session yet. */
	signIn: (
		input: { username: string; password: string; rememberMe?: boolean },
		context?: { request?: Request },
	) => Promise<{
		user: { id: string; username: string };
		session: { token: string; expiresAt: Date; rememberMe?: boolean };
	}>;
	/** Verifies `current` under the per-account lockout (keyed by user id) and the per-IP backoff. An unknown account and a wrong password throw the same error. */
	changePassword: (
		userId: string,
		current: string,
		newPassword: string,
		context?: { request?: Request },
	) => Promise<{ success: boolean }>;
	changeUsername: (userId: string, newUsername: string) => Promise<{ success: boolean }>;
	/** Admin override: lift the lockout and clear failure counters for a username. */
	unlockAccount: (username: string) => Promise<void>;
	/** Serves sign-up and sign-in publicly; change-username and change-password need a session and act on its user only. */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// Defaults

const DEFAULT_MIN_USERNAME = 3;
const DEFAULT_MAX_USERNAME = 32;
const DEFAULT_ALLOWED_PATTERN = /^[a-zA-Z0-9_-]+$/;
const DEFAULT_MIN_PASSWORD = 8;
const DEFAULT_MAX_PASSWORD = 128;

async function hashPassword(password: string, iterations: number): Promise<string> {
	return pbkdf2Hash(password, undefined, iterations);
}

async function verifyPassword(stored: string, candidate: string): Promise<boolean> {
	return pbkdf2Verify(candidate, stored);
}

export function createUsernameAuthModule(
	config: UsernameAuthConfig,
	db: Database,
	sessionManager: SessionManager,
	signInGate?: SignInGate,
	deps?: UsernameAuthDeps,
): UsernameAuthModule {
	const lockout: LoginLockout | null =
		config.lockout === false || lockoutDisabledByEnv()
			? null
			: createLoginLockout(
					{
						...config.lockout,
						...(deps?.storage && !config.lockout?.storage && { storage: deps.storage }),
					},
					deps?.logger,
				);
	const gate = signInGate ?? createSignInGate({ db });
	const minUsernameLen = config.minUsernameLength ?? DEFAULT_MIN_USERNAME;
	const maxUsernameLen = config.maxUsernameLength ?? DEFAULT_MAX_USERNAME;
	const allowedPattern = config.allowedPattern ?? DEFAULT_ALLOWED_PATTERN;
	const caseSensitive = config.caseSensitive ?? false;
	const minPasswordLen = config.password?.minLength ?? DEFAULT_MIN_PASSWORD;
	const maxPasswordLen = config.password?.maxLength ?? DEFAULT_MAX_PASSWORD;
	const iterationTarget = resolvePbkdf2Iterations(config.pbkdf2Iterations);
	let dummy: Promise<string> | null = null;
	const dummyHash = (): Promise<string> => {
		dummy ??= hashPassword(generateId(), iterationTarget);
		return dummy;
	};

	function normalise(username: string): string {
		return caseSensitive ? username : username.toLowerCase();
	}

	function validateUsername(username: string): string | null {
		if (username.length < minUsernameLen) {
			return `Username must be at least ${minUsernameLen} characters`;
		}
		if (username.length > maxUsernameLen) {
			return `Username must be at most ${maxUsernameLen} characters`;
		}
		if (!allowedPattern.test(username)) {
			return "Username contains invalid characters";
		}
		return null;
	}

	function validatePassword(password: string): string | null {
		if (password.length < minPasswordLen) {
			return `Password must be at least ${minPasswordLen} characters`;
		}
		if (password.length > maxPasswordLen) {
			return `Password must be at most ${maxPasswordLen} characters`;
		}
		return null;
	}

	async function signUp(input: { username: string; password: string; name?: string }): Promise<{
		user: { id: string; username: string; name: string | null };
		session: { token: string; expiresAt: Date };
	}> {
		const normalisedUsername = normalise(input.username.trim());

		const usernameError = validateUsername(normalisedUsername);
		if (usernameError) throw new Error(usernameError);

		const passwordError = validatePassword(input.password);
		if (passwordError) throw new Error(passwordError);

		const existing = await db
			.select({ id: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.username, normalisedUsername));

		if (existing[0]) throw new Error("Username already taken");

		const now = new Date();
		const userId = generateId();
		const passwordHash = await hashPassword(input.password, iterationTarget);

		await db.insert(users).values({
			id: userId,
			email: `${normalisedUsername}@username.local`,
			name: input.name ?? null,
			createdAt: now,
			updatedAt: now,
		});

		await db.insert(usernameAccounts).values({
			id: generateId(),
			userId,
			username: normalisedUsername,
			passwordHash,
			createdAt: now,
			updatedAt: now,
		});

		const { token, session } = await sessionManager.create(userId);

		return {
			user: { id: userId, username: normalisedUsername, name: input.name ?? null },
			session: { token, expiresAt: session.expiresAt },
		};
	}

	async function signIn(
		input: { username: string; password: string; rememberMe?: boolean },
		context?: { request?: Request },
	): Promise<{
		user: { id: string; username: string };
		session: { token: string; expiresAt: Date; rememberMe?: boolean };
	}> {
		const normalisedUsername = normalise(input.username.trim());
		const ip = context?.request ? resolveClientIp(context.request, config.trustedProxy) : null;

		// The lockout is keyed by the submitted name, never by whether the account exists.
		if (lockout) {
			const state = await lockout.check(normalisedUsername, ip);
			if (state.locked)
				throw new LoginLockedError(state.retryAfterSeconds, state.reason ?? "account");
		}

		const rows = await db
			.select()
			.from(usernameAccounts)
			.where(eq(usernameAccounts.username, normalisedUsername));

		const account = rows[0];
		if (!account) {
			// Spend the same hashing time so response time does not reveal which usernames exist.
			await verifyPassword(await dummyHash(), input.password);
			await lockout?.recordFailure(normalisedUsername, ip);
			throw new Error("Invalid username or password");
		}

		const valid = await verifyPassword(account.passwordHash, input.password);
		if (!valid) {
			await lockout?.recordFailure(normalisedUsername, ip);
			throw new Error("Invalid username or password");
		}
		await lockout?.recordSuccess(normalisedUsername, ip);

		if (pbkdf2NeedsRehash(account.passwordHash, iterationTarget)) {
			try {
				await db
					.update(usernameAccounts)
					.set({
						passwordHash: await hashPassword(input.password, iterationTarget),
						updatedAt: new Date(),
					})
					.where(eq(usernameAccounts.userId, account.userId));
			} catch {
				// A failed upgrade must never turn a correct password into a failed sign-in.
			}
		}

		const decision = await gate.evaluate({
			userId: account.userId,
			method: "password",
			...(context?.request && { request: context.request }),
		});
		if (decision.action !== "allow") throw new SignInGateError(decision);

		const { token, session } = await sessionManager.create(
			account.userId,
			undefined,
			input.rememberMe === undefined ? undefined : { rememberMe: input.rememberMe },
		);

		return {
			user: { id: account.userId, username: normalisedUsername },
			session: {
				token,
				expiresAt: session.expiresAt,
				...(session.rememberMe !== undefined && { rememberMe: session.rememberMe }),
			},
		};
	}

	async function changePassword(
		userId: string,
		current: string,
		newPassword: string,
		context?: { request?: Request },
	): Promise<{ success: boolean }> {
		const ip = context?.request ? resolveClientIp(context.request, config.trustedProxy) : null;
		// "uid:" cannot collide with a username key: ":" is outside the allowed pattern.
		const lockKey = `uid:${userId}`;
		if (lockout) {
			const state = await lockout.check(lockKey, ip);
			if (state.locked)
				throw new LoginLockedError(state.retryAfterSeconds, state.reason ?? "account");
		}

		const rows = await db
			.select()
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, userId));
		const account = rows[0];

		// Same hashing work and the same error whether or not the account exists.
		const valid = await verifyPassword(account?.passwordHash ?? (await dummyHash()), current);
		if (!account || !valid) {
			await lockout?.recordFailure(lockKey, ip);
			throw new Error(CHANGE_PASSWORD_REFUSED);
		}
		await lockout?.recordSuccess(lockKey, ip);

		const passwordError = validatePassword(newPassword);
		if (passwordError) throw new Error(passwordError);

		const newHash = await hashPassword(newPassword, iterationTarget);
		await db
			.update(usernameAccounts)
			.set({ passwordHash: newHash, updatedAt: new Date() })
			.where(eq(usernameAccounts.userId, userId));

		await gate.onPasswordChanged(userId);

		return { success: true };
	}

	// Lets the gate complete a forced password change for username accounts.
	gate.registerPasswordCredentialCheck(async (userId) => {
		const rows = await db
			.select({ id: usernameAccounts.id })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, userId));
		return rows.length > 0;
	});
	gate.registerPasswordChanger(async (userId, newPassword) => {
		const rows = await db
			.select({ id: usernameAccounts.id })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, userId));
		if (!rows[0]) return "no_account";
		const passwordError = validatePassword(newPassword);
		if (passwordError) return { error: passwordError };
		await db
			.update(usernameAccounts)
			.set({
				passwordHash: await hashPassword(newPassword, iterationTarget),
				updatedAt: new Date(),
			})
			.where(eq(usernameAccounts.userId, userId));
		return "changed";
	});

	async function changeUsername(
		userId: string,
		newUsername: string,
	): Promise<{ success: boolean }> {
		const normalised = normalise(newUsername.trim());

		const usernameError = validateUsername(normalised);
		if (usernameError) throw new Error(usernameError);

		const existing = await db
			.select({ id: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(and(eq(usernameAccounts.username, normalised)));

		if (existing[0] && existing[0].id !== userId) {
			throw new Error("Username already taken");
		}

		await db
			.update(usernameAccounts)
			.set({ username: normalised, updatedAt: new Date() })
			.where(eq(usernameAccounts.userId, userId));

		return { success: true };
	}

	const handleRequest = createUsernameRequestHandler(
		{ signUp, signIn, changePassword, changeUsername },
		sessionManager,
	);

	async function unlockAccount(username: string): Promise<void> {
		await lockout?.unlock(normalise(username.trim()));
	}

	return { signUp, signIn, changePassword, changeUsername, unlockAccount, handleRequest };
}
