/**
 * Email and password authentication on the core user table.
 *
 * Credentials live in the same `theauth_username_accounts` table the username module uses
 * (new rows are keyed `email:<address>` and found through the user), so password reset, the sign-in gate (forced password change,
 * two-factor) and `user.email` all keep working. Sessions are core sessions: the token is
 * accepted by `GET /auth/session`, `POST /auth/sign-out` and every adapter.
 *
 * Verification is on by default. A sign-up then creates no session and a sign-in is refused
 * (after the password check, so only the password holder learns the state) until the address
 * is verified. The HTTP layer answers a sign-up for a taken address exactly like a new one.
 *
 * @example
 * ```typescript
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   emailVerification: { sendVerificationEmail, verifyUrl: 'https://app.example.com/verify' },
 *   emailPassword: {},
 * });
 * ```
 */

import { eq } from "drizzle-orm";
import {
	generateId,
	pbkdf2Hash,
	pbkdf2NeedsRehash,
	pbkdf2Verify,
	resolvePbkdf2Iterations,
} from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import type { IdSource } from "../db/id-generation.js";
import { defaultIdSource } from "../db/id-generation.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import type { SessionManager } from "../session/session.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { TrustedProxyConfig } from "./client-ip.js";
import { resolveClientIp } from "./client-ip.js";
import type { EmailVerificationModule } from "./email-verification.js";
import type { LockoutLogger, LoginLockout, LoginLockoutConfig } from "./login-lockout.js";
import { createLoginLockout, LoginLockedError, lockoutDisabledByEnv } from "./login-lockout.js";
import { normalizeEmail } from "./normalize-email.js";
import type { SignInGate } from "./sign-in-gate.js";
import { createSignInGate, SignInGateError } from "./sign-in-gate.js";

export interface EmailPasswordConfig {
	/**
	 * Refuse sign-in until the address is verified, and create no session at sign-up.
	 * Default: true. Needs the `emailVerification` config to send the message. Set `false`
	 * only for development or when a different system already proved the address.
	 */
	requireVerification?: boolean;
	password?: {
		/** Minimum password length (default: 8) */
		minLength?: number;
		/** Maximum password length (default: 128) */
		maxLength?: number;
	};
	/** PBKDF2-SHA256 iteration target (default: `THEAUTH_PBKDF2_ITERATIONS` or 600000). */
	pbkdf2Iterations?: number;
	/** Failed sign-in lockout, same defaults and meaning as `username.lockout`. */
	lockout?: false | LoginLockoutConfig;
	/** How to find the client IP for the per-IP backoff. */
	trustedProxy?: TrustedProxyConfig;
}

/** Collaborators supplied by `createTheAuth`. */
export interface EmailPasswordDeps {
	storage?: SecondaryStorage;
	logger?: LockoutLogger;
	ids?: IdSource;
	databaseHooks?: DatabaseHookRunner;
	emailVerification?: EmailVerificationModule | null;
}

export type EmailPasswordErrorCode =
	| "INVALID_EMAIL"
	| "INVALID_PASSWORD"
	| "EMAIL_TAKEN"
	| "INVALID_CREDENTIALS"
	| "EMAIL_NOT_VERIFIED"
	| "INVALID_TOKEN";

/** A refusal the HTTP layer maps to a status. Messages are safe to show to the caller. */
export class EmailPasswordError extends Error {
	readonly code: EmailPasswordErrorCode;
	constructor(code: EmailPasswordErrorCode, message: string) {
		super(message);
		this.name = "EmailPasswordError";
		this.code = code;
	}
}

export interface EmailPasswordUser {
	id: string;
	email: string;
	name: string | null;
	emailVerified: boolean;
}

export interface EmailPasswordSession {
	token: string;
	expiresAt: Date;
	rememberMe?: boolean;
}

export type EmailSignUpResult =
	| { verificationRequired: true }
	| { verificationRequired: false; user: EmailPasswordUser; session: EmailPasswordSession };

export interface EmailPasswordModule {
	/** True when sign-in needs a verified address. */
	readonly requireVerification: boolean;
	/**
	 * Creates the account. With verification required it sends the message and returns
	 * `{ verificationRequired: true }` for a new and a taken address alike. Without it,
	 * a taken address throws `EMAIL_TAKEN` and a new one returns a session.
	 */
	signUp(input: { email: string; password: string; name?: string }): Promise<EmailSignUpResult>;
	/** Throws `EmailPasswordError`, `LoginLockedError` or `SignInGateError`. */
	signIn(
		input: { email: string; password: string; rememberMe?: boolean },
		context?: { request?: Request },
	): Promise<{ user: EmailPasswordUser; session: EmailPasswordSession }>;
	/** Consumes a verification token and marks the address verified. */
	verifyEmail(token: string): Promise<EmailPasswordUser>;
	/** Sends a new verification message when the address has an unverified account. Never reveals which. */
	resendVerification(email: string): Promise<void>;
	changePassword(
		userId: string,
		current: string,
		newPassword: string,
		context?: { request?: Request },
	): Promise<{ success: true }>;
	/** Marks the account's address verified, for flows that prove it (a completed password reset). */
	markVerified(userId: string): Promise<void>;
}

const KEY_PREFIX = "email:";
const MAX_EMAIL = 254;
const EMAIL_SHAPE = /^[^\s@]{1,64}@[^\s@.]+(?:\.[^\s@.]+)+$/;
const REFUSED = "Current password is incorrect";

/** The `theauth_username_accounts.username` value that holds an email credential. */
export function emailCredentialKey(email: string): string {
	return `${KEY_PREFIX}${normalizeEmail(email)}`;
}

export function createEmailPasswordModule(
	config: EmailPasswordConfig,
	db: Database,
	sessionManager: SessionManager,
	signInGate?: SignInGate,
	deps: EmailPasswordDeps = {},
): EmailPasswordModule {
	const requireVerification = config.requireVerification ?? true;
	if (requireVerification && !deps.emailVerification) {
		throw new Error(
			"[theauth] emailPassword requires the `emailVerification` config to send verification messages. Add it, or set `emailPassword.requireVerification: false` (development only).",
		);
	}
	const ids = deps.ids ?? defaultIdSource();
	const databaseHooks = deps.databaseHooks ?? createDatabaseHookRunner(undefined);
	const lockout: LoginLockout | null =
		config.lockout === false || lockoutDisabledByEnv()
			? null
			: createLoginLockout(
					{
						...config.lockout,
						...(deps.storage && !config.lockout?.storage && { storage: deps.storage }),
					},
					deps.logger,
				);
	const gate = signInGate ?? createSignInGate({ db });
	const minPasswordLen = config.password?.minLength ?? 8;
	const maxPasswordLen = config.password?.maxLength ?? 128;
	const iterationTarget = resolvePbkdf2Iterations(config.pbkdf2Iterations);
	let dummy: Promise<string> | null = null;
	const dummyHash = (): Promise<string> => {
		dummy ??= pbkdf2Hash(generateId(), undefined, iterationTarget);
		return dummy;
	};

	function validateEmail(email: string): void {
		if (email.length > MAX_EMAIL || !EMAIL_SHAPE.test(email)) {
			throw new EmailPasswordError("INVALID_EMAIL", "Enter a valid email address");
		}
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

	const toUser = (row: {
		id: string;
		email: string;
		name: string | null;
		emailVerified: number;
	}): EmailPasswordUser => ({
		id: row.id,
		email: row.email,
		name: row.name,
		emailVerified: row.emailVerified === 1,
	});

	async function userByEmail(email: string) {
		const rows = await db.select().from(users).where(eq(users.email, email));
		return rows[0];
	}

	async function accountOf(userId: string) {
		const rows = await db
			.select()
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, userId));
		return rows[0];
	}

	async function createUser(email: string, name: string | null, passwordHash: string) {
		const userId = ids.newId("user");
		const now = new Date();
		let storedEmail = email;
		let storedName = name;
		let storedMetadata: Record<string, unknown> | null = null;
		if (databaseHooks.has("user", "create")) {
			const hooked = await databaseHooks.before("user", "create", {
				id: userId,
				email: storedEmail,
				name: storedName,
				metadata: null,
			});
			storedEmail = hooked.email;
			storedName = hooked.name;
			storedMetadata = hooked.metadata;
		}
		await db.insert(users).values({
			id: userId,
			email: storedEmail,
			name: storedName,
			...(storedMetadata ? { metadata: storedMetadata } : {}),
			createdAt: now,
			updatedAt: now,
		});
		try {
			await db.insert(usernameAccounts).values({
				id: generateId(),
				userId,
				username: emailCredentialKey(storedEmail),
				passwordHash,
				createdAt: now,
				updatedAt: now,
			});
		} catch (err) {
			// Do not leave a user row that nobody can sign in to.
			await db.delete(users).where(eq(users.id, userId));
			throw err;
		}
		await databaseHooks.after("user", "create", {
			id: userId,
			email: storedEmail,
			name: storedName,
			metadata: storedMetadata,
		});
		return { userId, email: storedEmail, name: storedName };
	}

	async function signUp(input: {
		email: string;
		password: string;
		name?: string;
	}): Promise<EmailSignUpResult> {
		const email = normalizeEmail(input.email);
		validateEmail(email);
		const passwordError = validatePassword(input.password);
		if (passwordError) throw new EmailPasswordError("INVALID_PASSWORD", passwordError);

		// The same hashing work whether or not the address is taken.
		const passwordHash = await pbkdf2Hash(input.password, undefined, iterationTarget);
		const name = input.name?.trim() ? input.name.trim() : null;

		const existing = await userByEmail(email);
		if (existing) return taken(existing);

		let created: { userId: string } | null = null;
		try {
			created = await createUser(email, name, passwordHash);
		} catch (err) {
			// A concurrent sign-up for the same address lost the unique index race.
			const winner = await userByEmail(email);
			if (!winner) throw err;
			return taken(winner);
		}

		if (requireVerification) {
			await deps.emailVerification?.sendVerification(created.userId, email);
			return { verificationRequired: true };
		}
		const { token, session } = await sessionManager.create(created.userId, undefined, {
			authMethods: ["password"],
		});
		return {
			verificationRequired: false,
			user: { id: created.userId, email, name, emailVerified: false },
			session: { token, expiresAt: session.expiresAt },
		};
	}

	/**
	 * A sign-up for an address that already has a user. Never attaches a password to that
	 * user (it could be an OAuth account, or an account whose owner has not verified yet).
	 */
	async function taken(existing: {
		id: string;
		email: string;
		emailVerified: number;
	}): Promise<EmailSignUpResult> {
		if (!requireVerification) {
			throw new EmailPasswordError("EMAIL_TAKEN", "An account with this email already exists");
		}
		// An unverified password account gets a fresh message. Anything else gets none.
		const account = await accountOf(existing.id);
		if (existing.emailVerified !== 1 && account) {
			await deps.emailVerification?.sendVerification(existing.id, existing.email);
		}
		return { verificationRequired: true };
	}

	async function signIn(
		input: { email: string; password: string; rememberMe?: boolean },
		context?: { request?: Request },
	): Promise<{ user: EmailPasswordUser; session: EmailPasswordSession }> {
		const email = normalizeEmail(input.email);
		const key = emailCredentialKey(email);
		const ip = context?.request ? resolveClientIp(context.request, config.trustedProxy) : null;

		if (lockout) {
			const state = await lockout.check(key, ip);
			if (state.locked)
				throw new LoginLockedError(state.retryAfterSeconds, state.reason ?? "account");
		}

		// The credential is found through the user, so accounts imported with the plain
		// lowercased address as key (see `theauth migrate`) sign in the same way.
		const found = await userByEmail(email);
		const account = found ? await accountOf(found.id) : undefined;
		if (!found || !account) {
			await pbkdf2Verify(input.password, await dummyHash());
			await lockout?.recordFailure(key, ip);
			throw new EmailPasswordError("INVALID_CREDENTIALS", "Invalid email or password");
		}
		if (!(await pbkdf2Verify(input.password, account.passwordHash))) {
			await lockout?.recordFailure(key, ip);
			throw new EmailPasswordError("INVALID_CREDENTIALS", "Invalid email or password");
		}
		await lockout?.recordSuccess(key, ip);

		if (pbkdf2NeedsRehash(account.passwordHash, iterationTarget)) {
			try {
				await db
					.update(usernameAccounts)
					.set({
						passwordHash: await pbkdf2Hash(input.password, undefined, iterationTarget),
						updatedAt: new Date(),
					})
					.where(eq(usernameAccounts.userId, account.userId));
			} catch {
				// A failed upgrade must never turn a correct password into a failed sign-in.
			}
		}

		const user = found;
		if (requireVerification && user.emailVerified !== 1) {
			throw new EmailPasswordError(
				"EMAIL_NOT_VERIFIED",
				"Verify your email address before signing in",
			);
		}

		const decision = await gate.evaluate({
			userId: user.id,
			method: "password",
			...(context?.request && { request: context.request }),
		});
		if (decision.action !== "allow") throw new SignInGateError(decision);

		const { token, session } = await sessionManager.create(user.id, undefined, {
			authMethods: ["password"],
			...(input.rememberMe !== undefined && { rememberMe: input.rememberMe }),
		});
		return {
			user: toUser(user),
			session: {
				token,
				expiresAt: session.expiresAt,
				...(session.rememberMe !== undefined && { rememberMe: session.rememberMe }),
			},
		};
	}

	async function verifyEmail(token: string): Promise<EmailPasswordUser> {
		const result = await deps.emailVerification?.verify(token);
		if (!result?.success) {
			throw new EmailPasswordError("INVALID_TOKEN", "Invalid or expired verification token");
		}
		const user = (await db.select().from(users).where(eq(users.id, result.data.userId)))[0];
		if (!user)
			throw new EmailPasswordError("INVALID_TOKEN", "Invalid or expired verification token");
		return toUser(user);
	}

	async function resendVerification(email: string): Promise<void> {
		const normalized = normalizeEmail(email);
		const user = await userByEmail(normalized);
		if (!user || user.emailVerified === 1) return;
		if (!(await accountOf(user.id))) return;
		await deps.emailVerification?.sendVerification(user.id, normalized);
	}

	async function changePassword(
		userId: string,
		current: string,
		newPassword: string,
		context?: { request?: Request },
	): Promise<{ success: true }> {
		const ip = context?.request ? resolveClientIp(context.request, config.trustedProxy) : null;
		// "uid:" cannot collide with an email key: those start with "email:".
		const lockKey = `uid:${userId}`;
		if (lockout) {
			const state = await lockout.check(lockKey, ip);
			if (state.locked)
				throw new LoginLockedError(state.retryAfterSeconds, state.reason ?? "account");
		}
		const account = await accountOf(userId);
		const valid = await pbkdf2Verify(current, account?.passwordHash ?? (await dummyHash()));
		if (!account || !valid) {
			await lockout?.recordFailure(lockKey, ip);
			throw new EmailPasswordError("INVALID_CREDENTIALS", REFUSED);
		}
		await lockout?.recordSuccess(lockKey, ip);
		const passwordError = validatePassword(newPassword);
		if (passwordError) throw new EmailPasswordError("INVALID_PASSWORD", passwordError);
		await db
			.update(usernameAccounts)
			.set({
				passwordHash: await pbkdf2Hash(newPassword, undefined, iterationTarget),
				updatedAt: new Date(),
			})
			.where(eq(usernameAccounts.userId, userId));
		await gate.onPasswordChanged(userId);
		return { success: true };
	}

	async function markVerified(userId: string): Promise<void> {
		await db
			.update(users)
			.set({ emailVerified: 1, updatedAt: new Date() })
			.where(eq(users.id, userId));
	}

	// Lets the gate complete a forced password change for these accounts.
	gate.registerPasswordChanger(async (userId, newPassword) => {
		if (!(await accountOf(userId))) return "no_account";
		const passwordError = validatePassword(newPassword);
		if (passwordError) return { error: passwordError };
		await db
			.update(usernameAccounts)
			.set({
				passwordHash: await pbkdf2Hash(newPassword, undefined, iterationTarget),
				updatedAt: new Date(),
			})
			.where(eq(usernameAccounts.userId, userId));
		return "changed";
	});

	return {
		requireVerification,
		signUp,
		signIn,
		verifyEmail,
		resendVerification,
		changePassword,
		markVerified,
	};
}
