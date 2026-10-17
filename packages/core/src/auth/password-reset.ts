/**
 * Forgot-password and reset-password flows, built on the one-time token and username modules.
 *
 * @example
 * ```typescript
 * const auth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   username: { password: { minLength: 8 } },
 *   passwordReset: {
 *     sendResetEmail: async (email, token, resetUrl) => {
 *       await resend.emails.send({
 *         to: email,
 *         subject: 'Reset your password',
 *         html: `<a href="${resetUrl}">Reset password</a>`,
 *       });
 *     },
 *     resetUrl: 'https://app.example.com/reset-password',
 *   },
 * });
 *
 * // Forgot password (always succeeds, no email enumeration)
 * await theauth.passwordReset.requestReset('alice@example.com');
 *
 * // Reset password (from the link in the email)
 * const result = await theauth.passwordReset.resetPassword(token, 'new-password-123');
 * ```
 */

import { eq } from "drizzle-orm";
import { pbkdf2Hash } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { AuthError, Result, TheAuthError } from "../mcp/types.js";
import type { SessionManager } from "../session/session.js";
import { normalizeEmail } from "./normalize-email.js";
import type { OneTimeTokenModule } from "./one-time-token.js";
import type { OtpService } from "./otp.js";
import type { OtpChannel } from "./otp-senders.js";
import type { SignInGate } from "./sign-in-gate.js";

export type { AuthError, Result, TheAuthError };

export interface PasswordResetConfig {
	/** Sends the reset email. TheAuth builds the token and reset URL; you deliver the email. */
	sendResetEmail: (email: string, token: string, resetUrl: string) => Promise<void>;

	/** Reset page URL. The token is appended as `?token=<token>`. */
	resetUrl: string;

	/** Token TTL in seconds. Default: 3600 (1 hour). Keep it short: reset tokens are high-value targets. */
	tokenTtlSeconds?: number;

	/** Revoke all sessions on reset. Default: true, so an attacker holding a stolen session is kicked out too. */
	revokeSessionsOnReset?: boolean;

	/** Called after a reset changes the password (emits a Shared Signals credential-change event). Errors are swallowed. */
	onPasswordChanged?: (userId: string) => void | Promise<void>;

	/** Minimum new password length. Default: 8 (matches the username module). */
	minPasswordLength?: number;

	/** Maximum new password length. Default: 128 (matches the username module). */
	maxPasswordLength?: number;

	/** Optional code-based reset. When set, requestResetOtp and resetPasswordWithOtp are served on the `/otp` routes. */
	otp?: {
		service: OtpService;
		/** Delivery channel for the identifier (the account email). Default `"email"`. */
		channel?: OtpChannel;
	};
}

export interface PasswordResetModule {
	/** Requests a reset for an email. Always succeeds to prevent enumeration; no email is sent for unknown accounts. */
	requestReset(email: string): Promise<Result<{ sent: boolean }>>;

	/** Resets a password using a token from the reset email. The token is consumed on success. */
	resetPassword(token: string, newPassword: string): Promise<Result<{ userId: string }>>;

	/** Sends a reset code instead of a link. Requires `config.otp`. Enumeration-safe like requestReset. */
	requestResetOtp(email: string): Promise<Result<{ sent: boolean }>>;

	/** Resets a password with the emailed code. The code is consumed on a match. */
	resetPasswordWithOtp(
		email: string,
		code: string,
		newPassword: string,
	): Promise<Result<{ userId: string }>>;

	/**
	 * Handle HTTP requests for password reset endpoints.
	 * - POST /auth/forgot-password, { email }
	 * - POST /auth/reset-password, { token, password }
	 * - POST /auth/forgot-password/otp: { email } (only with `config.otp`)
	 * - POST /auth/reset-password/otp: { email, code, password } (only with `config.otp`)
	 */
	handleRequest(request: Request): Promise<Response | null>;
}

const DEFAULT_TOKEN_TTL_SECONDS = 3600; // 1 hour
const DEFAULT_MIN_PASSWORD = 8;
const DEFAULT_MAX_PASSWORD = 128;
const TOKEN_PURPOSE = "password-reset" as const;

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

export function createPasswordResetModule(
	config: PasswordResetConfig,
	db: Database,
	sessionManager: SessionManager,
	tokenModule: OneTimeTokenModule,
	signInGate?: SignInGate,
): PasswordResetModule {
	const tokenTtl = config.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
	const revokeOnReset = config.revokeSessionsOnReset ?? true;
	const minPasswordLen = config.minPasswordLength ?? DEFAULT_MIN_PASSWORD;
	const maxPasswordLen = config.maxPasswordLength ?? DEFAULT_MAX_PASSWORD;

	function validatePassword(password: string): string | null {
		if (password.length < minPasswordLen) {
			return `Password must be at least ${minPasswordLen} characters`;
		}
		if (password.length > maxPasswordLen) {
			return `Password must be at most ${maxPasswordLen} characters`;
		}
		return null;
	}

	async function requestReset(email: string): Promise<Result<{ sent: boolean }>> {
		if (typeof email !== "string" || email.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "email must not be empty") };
		}

		const normalizedEmail = normalizeEmail(email);

		const userRows = await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(eq(users.email, normalizedEmail));

		const user = userRows[0];
		if (!user) {
			// Don't reveal that the email doesn't exist
			return { success: true, data: { sent: false } };
		}

		// Verify this user has a username account (password-based auth).
		// If they signed up via magic link or OAuth only, there's no password to reset.
		const accountRows = await db
			.select({ userId: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, user.id));

		if (!accountRows[0]) {
			return { success: true, data: { sent: false } };
		}

		await tokenModule.revokeTokens(normalizedEmail, TOKEN_PURPOSE);

		const tokenResult = await tokenModule.createToken({
			purpose: TOKEN_PURPOSE,
			identifier: normalizedEmail,
			ttlSeconds: tokenTtl,
			metadata: { userId: user.id },
		});

		if (!tokenResult.success) {
			return {
				success: false,
				error: makeError("TOKEN_CREATION_FAILED", tokenResult.error.message),
			};
		}

		const resetUrl = `${config.resetUrl}?token=${tokenResult.data.token}`;

		// Not awaited, so response timing does not reveal whether the email exists.
		try {
			await config.sendResetEmail(normalizedEmail, tokenResult.data.token, resetUrl);
		} catch (err) {
			// Email failures are swallowed: the token exists and the user can request another reset.
			void err;
		}

		return { success: true, data: { sent: true } };
	}

	async function resetPassword(
		token: string,
		newPassword: string,
	): Promise<Result<{ userId: string }>> {
		if (typeof token !== "string" || token.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "token must not be empty") };
		}

		const passwordError = validatePassword(newPassword);
		if (passwordError) {
			return { success: false, error: makeError("INVALID_PASSWORD", passwordError) };
		}

		const validation = await tokenModule.validateToken(token, TOKEN_PURPOSE);
		if (!validation.success) {
			return {
				success: false,
				error: makeError("INVALID_TOKEN", "Invalid or expired reset token", {
					originalCode: validation.error.code,
				}),
			};
		}

		const email = validation.data.identifier;
		const userId = validation.data.metadata?.userId as string | undefined;

		return applyNewPassword(email, userId, newPassword);
	}

	async function applyNewPassword(
		email: string,
		userId: string | undefined,
		newPassword: string,
	): Promise<Result<{ userId: string }>> {
		let accountUserId: string;

		if (userId) {
			accountUserId = userId;
		} else {
			const userRows = await db.select({ id: users.id }).from(users).where(eq(users.email, email));

			const user = userRows[0];
			if (!user) {
				return {
					success: false,
					error: makeError("USER_NOT_FOUND", "User account not found"),
				};
			}
			accountUserId = user.id;
		}

		const accountRows = await db
			.select({ userId: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, accountUserId));

		if (!accountRows[0]) {
			return {
				success: false,
				error: makeError(
					"NO_PASSWORD_ACCOUNT",
					"This account does not use password authentication",
				),
			};
		}

		const newHash = await pbkdf2Hash(newPassword);
		await db
			.update(usernameAccounts)
			.set({ passwordHash: newHash, updatedAt: new Date() })
			.where(eq(usernameAccounts.userId, accountUserId));

		await db
			.update(users)
			.set({ forcePasswordReset: 0, updatedAt: new Date() })
			.where(eq(users.id, accountUserId));

		// A new password invalidates every trusted-device 2FA bypass.
		if (signInGate) await signInGate.onPasswordChanged(accountUserId);

		if (revokeOnReset) {
			await sessionManager.revokeAll(accountUserId);
		}

		await tokenModule.revokeTokens(email, TOKEN_PURPOSE);

		if (config.onPasswordChanged) {
			try {
				await config.onPasswordChanged(accountUserId);
			} catch {
				// A notification failure must not undo a completed reset.
			}
		}

		return { success: true, data: { userId: accountUserId } };
	}

	const otpConfig = config.otp;

	function otpNotConfigured<T>(): Result<T> {
		return {
			success: false,
			error: makeError("OTP_NOT_CONFIGURED", "passwordReset.otp is not configured"),
		};
	}

	async function requestResetOtp(email: string): Promise<Result<{ sent: boolean }>> {
		if (!otpConfig) return otpNotConfigured();
		if (typeof email !== "string" || email.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "email must not be empty") };
		}
		const normalizedEmail = email.trim().toLowerCase();

		const userRows = await db
			.select({ id: users.id })
			.from(users)
			.where(eq(users.email, normalizedEmail));
		const user = userRows[0];
		if (!user) return { success: true, data: { sent: false } };

		const accountRows = await db
			.select({ userId: usernameAccounts.userId })
			.from(usernameAccounts)
			.where(eq(usernameAccounts.userId, user.id));
		if (!accountRows[0]) return { success: true, data: { sent: false } };

		// Cooldown, lockout and delivery failures are swallowed so the caller cannot
		// tell a throttled known account from an unknown one.
		const sent = await otpConfig.service.send({
			purpose: "reset-password",
			channel: otpConfig.channel ?? "email",
			identifier: normalizedEmail,
		});
		return { success: true, data: { sent: sent.success } };
	}

	async function resetPasswordWithOtp(
		email: string,
		code: string,
		newPassword: string,
	): Promise<Result<{ userId: string }>> {
		if (!otpConfig) return otpNotConfigured();
		if (typeof email !== "string" || email.trim() === "" || typeof code !== "string" || !code) {
			return { success: false, error: makeError("INVALID_INPUT", "email and code are required") };
		}

		const passwordError = validatePassword(newPassword);
		if (passwordError) {
			return { success: false, error: makeError("INVALID_PASSWORD", passwordError) };
		}

		const normalizedEmail = email.trim().toLowerCase();
		const verified = await otpConfig.service.verify({
			purpose: "reset-password",
			identifier: normalizedEmail,
			code,
		});
		if (!verified.success) {
			return {
				success: false,
				error: makeError("INVALID_CODE", "Invalid or expired code", {
					locked: verified.error.code === "OTP_LOCKED",
				}),
			};
		}

		const result = await applyNewPassword(normalizedEmail, undefined, newPassword);
		if (!result.success) {
			return { success: false, error: makeError("INVALID_CODE", "Invalid or expired code") };
		}
		return result;
	}

	const HANDLED_PATHS = new Set(["/auth/forgot-password", "/auth/reset-password"]);
	if (otpConfig) {
		HANDLED_PATHS.add("/auth/forgot-password/otp");
		HANDLED_PATHS.add("/auth/reset-password/otp");
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		if (request.method !== "POST") return null;

		const url = new URL(request.url);
		const { pathname } = url;

		if (!HANDLED_PATHS.has(pathname)) return null;

		let body: unknown;
		try {
			body = await request.json();
		} catch {
			return jsonResponse({ error: "Invalid JSON body" }, 400);
		}

		const b = body as Record<string, unknown>;

		if (pathname === "/auth/forgot-password") {
			if (typeof b.email !== "string") {
				return jsonResponse({ error: "Missing required field: email" }, 400);
			}

			const result = await requestReset(b.email);
			// Always return 204 regardless of whether the email exists.
			// The `sent` field is only visible programmatically, not in the HTTP response.
			if (!result.success) {
				return jsonResponse({ error: result.error.message }, 500);
			}
			return new Response(null, { status: 204 });
		}

		if (pathname === "/auth/forgot-password/otp") {
			if (typeof b.email !== "string") {
				return jsonResponse({ error: "Missing required field: email" }, 400);
			}
			const result = await requestResetOtp(b.email);
			if (!result.success) return jsonResponse({ error: result.error.message }, 400);
			return new Response(null, { status: 204 });
		}

		if (pathname === "/auth/reset-password/otp") {
			if (
				typeof b.email !== "string" ||
				typeof b.code !== "string" ||
				typeof b.password !== "string"
			) {
				return jsonResponse({ error: "Missing required fields: email, code, password" }, 400);
			}
			const result = await resetPasswordWithOtp(b.email, b.code, b.password);
			if (!result.success) {
				if (result.error.details?.locked === true) {
					return jsonResponse({ error: "Too many attempts. Try again later." }, 429);
				}
				return jsonResponse({ error: result.error.message }, 400);
			}
			return new Response(null, { status: 204 });
		}

		if (pathname === "/auth/reset-password") {
			if (typeof b.token !== "string" || typeof b.password !== "string") {
				return jsonResponse({ error: "Missing required fields: token, password" }, 400);
			}

			const result = await resetPassword(b.token, b.password);
			if (!result.success) {
				// Don't reveal specific error details to the client
				return jsonResponse({ error: result.error.message }, 400);
			}

			return new Response(null, { status: 204 });
		}

		return null;
	}

	return {
		requestReset,
		resetPassword,
		requestResetOtp,
		resetPasswordWithOtp,
		handleRequest,
	};
}
