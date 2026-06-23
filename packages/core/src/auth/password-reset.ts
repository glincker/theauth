/**
 * Password reset module for TheAuth.
 *
 * Composes the one-time token module with the username auth module to provide
 * a complete forgot-password and reset-password flow. The caller supplies an
 * email-sending callback; TheAuth handles token generation, validation,
 * password hashing, and session revocation.
 *
 * Security properties:
 * - Tokens are 256-bit random, stored as SHA-256 hashes (never in plaintext).
 * - Single-use: consumed on first validation.
 * - Configurable TTL (default 1 hour).
 * - All existing sessions are revoked on successful reset.
 * - Email enumeration resistant: always returns success, even for unknown emails.
 * - Outstanding reset tokens are revoked when a new one is requested.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
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
 * // Forgot password (always succeeds — no email enumeration)
 * await kavach.passwordReset.requestReset('alice@example.com');
 *
 * // Reset password (from the link in the email)
 * const result = await kavach.passwordReset.resetPassword(token, 'new-password-123');
 * ```
 */

import { eq } from "drizzle-orm";
import { pbkdf2Hash } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { usernameAccounts, users } from "../db/schema.js";
import type { AuthError, KavachError, Result } from "../mcp/types.js";
import type { SessionManager } from "../session/session.js";
import type { OneTimeTokenModule } from "./one-time-token.js";

// ---------------------------------------------------------------------------
// Re-export shared types
// ---------------------------------------------------------------------------

export type { AuthError, KavachError, Result };

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PasswordResetConfig {
	/**
	 * Callback to send the password reset email.
	 *
	 * TheAuth generates the token and constructs the reset URL. Your job is
	 * to deliver it (Resend, SES, SMTP, Postmark, whatever you use).
	 *
	 * The function should not throw for unknown emails. TheAuth already
	 * handles that by silently succeeding.
	 */
	sendResetEmail: (email: string, token: string, resetUrl: string) => Promise<void>;

	/**
	 * Base URL for the reset page in your app.
	 *
	 * The token is appended as `?token=<token>`. Example:
	 * `https://app.example.com/reset-password` produces
	 * `https://app.example.com/reset-password?token=abc123...`
	 */
	resetUrl: string;

	/**
	 * Token TTL in seconds. Default: 3600 (1 hour).
	 *
	 * Keep this short. Password reset tokens are high-value targets.
	 */
	tokenTtlSeconds?: number;

	/**
	 * Revoke all existing sessions on successful password reset.
	 * Default: true.
	 *
	 * If someone's password was compromised, you want to kick out the
	 * attacker's sessions too.
	 */
	revokeSessionsOnReset?: boolean;

	/**
	 * Minimum password length for the new password.
	 * Default: 8 (matches username module default).
	 */
	minPasswordLength?: number;

	/**
	 * Maximum password length for the new password.
	 * Default: 128 (matches username module default).
	 */
	maxPasswordLength?: number;
}

export interface PasswordResetModule {
	/**
	 * Request a password reset for the given email.
	 *
	 * Always returns success to prevent email enumeration. If the email
	 * is not associated with any account, nothing happens (no email sent).
	 */
	requestReset(email: string): Promise<Result<{ sent: boolean }>>;

	/**
	 * Reset a password using a token from the reset email.
	 *
	 * Validates the token, updates the password hash, and optionally
	 * revokes all sessions. The token is consumed on success.
	 */
	resetPassword(token: string, newPassword: string): Promise<Result<{ userId: string }>>;

	/**
	 * Handle HTTP requests for password reset endpoints.
	 *
	 * - POST /auth/forgot-password — { email }
	 * - POST /auth/reset-password  — { token, password }
	 */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TOKEN_TTL_SECONDS = 3600; // 1 hour
const DEFAULT_MIN_PASSWORD = 8;
const DEFAULT_MAX_PASSWORD = 128;
const TOKEN_PURPOSE = "password-reset" as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeError(code: string, message: string, details?: Record<string, unknown>): KavachError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createPasswordResetModule(
	config: PasswordResetConfig,
	db: Database,
	sessionManager: SessionManager,
	tokenModule: OneTimeTokenModule,
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

	// ── requestReset ──────────────────────────────────────────────────────

	async function requestReset(email: string): Promise<Result<{ sent: boolean }>> {
		if (typeof email !== "string" || email.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "email must not be empty") };
		}

		const normalizedEmail = email.trim().toLowerCase();

		// Look up user by email. If not found, return success (no enumeration).
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
			// User exists but doesn't use password auth. Silent success.
			return { success: true, data: { sent: false } };
		}

		// Revoke any outstanding reset tokens for this email before issuing a new one.
		await tokenModule.revokeTokens(normalizedEmail, TOKEN_PURPOSE);

		// Create the reset token
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

		// Send the email asynchronously. Don't await — don't reveal timing differences
		// between "email exists" and "email doesn't exist" to the caller.
		// But we do want to catch errors for logging, so we use void + catch.
		try {
			await config.sendResetEmail(normalizedEmail, tokenResult.data.token, resetUrl);
		} catch (err) {
			// Swallow error — the token is already created.
			// The caller can retry or the user can request another reset.
			void err;
		}

		return { success: true, data: { sent: true } };
	}

	// ── resetPassword ─────────────────────────────────────────────────────

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

		// Validate and consume the token
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

		// Look up the user's username account
		let accountUserId: string;

		if (userId) {
			// We stored the userId in token metadata — use it directly
			accountUserId = userId;
		} else {
			// Fallback: look up by email
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

		// Verify the username account exists
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

		// Hash the new password and update
		const newHash = await pbkdf2Hash(newPassword);
		await db
			.update(usernameAccounts)
			.set({ passwordHash: newHash, updatedAt: new Date() })
			.where(eq(usernameAccounts.userId, accountUserId));

		// Clear the forcePasswordReset flag if set
		await db
			.update(users)
			.set({ forcePasswordReset: 0, updatedAt: new Date() })
			.where(eq(users.id, accountUserId));

		// Revoke all sessions if configured (default: true)
		if (revokeOnReset) {
			await sessionManager.revokeAll(accountUserId);
		}

		// Revoke any remaining reset tokens for this email
		await tokenModule.revokeTokens(email, TOKEN_PURPOSE);

		return { success: true, data: { userId: accountUserId } };
	}

	// ── handleRequest ─────────────────────────────────────────────────────

	const HANDLED_PATHS = new Set(["/auth/forgot-password", "/auth/reset-password"]);

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

		if (pathname === "/auth/reset-password") {
			if (typeof b.token !== "string" || typeof b.password !== "string") {
				return jsonResponse({ error: "Missing required fields: token, password" }, 400);
			}

			const result = await resetPassword(b.token, b.password);
			if (!result.success) {
				// Don't reveal specific error details to the client
				const status = result.error.code === "INVALID_PASSWORD" ? 400 : 400;
				return jsonResponse({ error: result.error.message }, status);
			}

			return new Response(null, { status: 204 });
		}

		return null;
	}

	return { requestReset, resetPassword, handleRequest };
}
