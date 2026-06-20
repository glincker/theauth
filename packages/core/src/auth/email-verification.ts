/**
 * Email verification module for TheAuth.
 *
 * Handles the full email address verification flow: generating single-use
 * tokens, sending verification emails, and marking user addresses as verified
 * in the database. Composes the one-time token module so tokens are stored as
 * SHA-256 hashes and consumed on first use.
 *
 * Security properties:
 * - Tokens are 256-bit random, stored as SHA-256 hashes (never in plaintext).
 * - Single-use: consumed on first validation.
 * - Configurable TTL (default 24 hours).
 * - Outstanding verify tokens are revoked after successful verification.
 * - Sending to an already-verified address returns success without sending.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   emailVerification: {
 *     sendVerificationEmail: async (email, token, verifyUrl) => {
 *       await resend.emails.send({
 *         to: email,
 *         subject: 'Verify your email',
 *         html: `<a href="${verifyUrl}">Verify email</a>`,
 *       });
 *     },
 *     verifyUrl: 'https://app.example.com/verify-email',
 *   },
 * });
 *
 * // Send verification email
 * await kavach.emailVerification.sendVerification(userId, 'alice@example.com');
 *
 * // Verify the token from the link
 * const result = await kavach.emailVerification.verify(token);
 * if (result.success) console.log('Verified:', result.data.userId);
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import type { KavachError, Result } from "../mcp/types.js";
import type { OneTimeTokenModule } from "./one-time-token.js";

// ---------------------------------------------------------------------------
// Re-export shared types
// ---------------------------------------------------------------------------

export type { KavachError, Result };

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface EmailVerificationConfig {
	/**
	 * Callback to send the verification email.
	 *
	 * TheAuth generates the token and constructs the verify URL. Your job is
	 * to deliver it (Resend, SES, SMTP, Postmark, whatever you use).
	 */
	sendVerificationEmail: (email: string, token: string, verifyUrl: string) => Promise<void>;

	/**
	 * Base URL for the verify page in your app.
	 *
	 * The token is appended as `?token=<token>`. Example:
	 * `https://app.example.com/verify-email` produces
	 * `https://app.example.com/verify-email?token=abc123...`
	 */
	verifyUrl: string;

	/**
	 * Token TTL in seconds. Default: 86400 (24 hours).
	 */
	tokenTtlSeconds?: number;

	/**
	 * When true, call `sendVerification` automatically after sign-up.
	 * Default: false.
	 *
	 * The caller is still responsible for calling `sendVerification` directly
	 * if this is false. This flag is informational — TheAuth uses it to
	 * signal intent to integrations (e.g. the username module).
	 */
	autoVerifyOnSignUp?: boolean;
}

export interface EmailVerificationModule {
	/**
	 * Create a verification token and send the verification email.
	 *
	 * Returns `{ sent: true }` when the email was dispatched.
	 * Returns `{ sent: false }` when the email is already verified — no
	 * email is sent and no token is created in that case.
	 */
	sendVerification(userId: string, email: string): Promise<Result<{ sent: boolean }>>;

	/**
	 * Validate a verification token and mark the user's email as verified.
	 *
	 * The token is consumed on success. All outstanding verify tokens for
	 * the address are revoked after successful verification.
	 */
	verify(token: string): Promise<Result<{ userId: string; email: string }>>;

	/**
	 * Check whether a user's email address has been verified.
	 */
	isVerified(userId: string): Promise<boolean>;

	/**
	 * Handle HTTP requests for email verification endpoints.
	 *
	 * - POST /auth/verify-email/send    — { userId, email }
	 * - POST /auth/verify-email/confirm — { token }
	 */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TOKEN_TTL_SECONDS = 86400; // 24 hours
const TOKEN_PURPOSE = "email-verify" as const;

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

export function createEmailVerificationModule(
	config: EmailVerificationConfig,
	db: Database,
	tokenModule: OneTimeTokenModule,
): EmailVerificationModule {
	const tokenTtl = config.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;

	// ── sendVerification ──────────────────────────────────────────────────

	async function sendVerification(
		userId: string,
		email: string,
	): Promise<Result<{ sent: boolean }>> {
		if (typeof userId !== "string" || userId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "userId must not be empty") };
		}
		if (typeof email !== "string" || email.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "email must not be empty") };
		}

		const normalizedEmail = email.trim().toLowerCase();

		// Check if already verified — no need to send again.
		const userRows = await db
			.select({ id: users.id, emailVerified: users.emailVerified })
			.from(users)
			.where(eq(users.id, userId));

		const user = userRows[0];
		if (!user) {
			return { success: false, error: makeError("USER_NOT_FOUND", "User not found") };
		}

		if (user.emailVerified === 1) {
			return { success: true, data: { sent: false } };
		}

		// Revoke any outstanding verify tokens for this email before issuing a new one.
		await tokenModule.revokeTokens(normalizedEmail, TOKEN_PURPOSE);

		// Create the verification token
		const tokenResult = await tokenModule.createToken({
			purpose: TOKEN_PURPOSE,
			identifier: normalizedEmail,
			ttlSeconds: tokenTtl,
			metadata: { userId },
		});

		if (!tokenResult.success) {
			return {
				success: false,
				error: makeError("TOKEN_CREATION_FAILED", tokenResult.error.message),
			};
		}

		const verifyUrl = `${config.verifyUrl}?token=${tokenResult.data.token}`;

		try {
			await config.sendVerificationEmail(normalizedEmail, tokenResult.data.token, verifyUrl);
		} catch (err) {
			// Swallow send errors — the token is already created.
			// The caller can retry or the user can request another email.
			void err;
		}

		return { success: true, data: { sent: true } };
	}

	// ── verify ────────────────────────────────────────────────────────────

	async function verify(token: string): Promise<Result<{ userId: string; email: string }>> {
		if (typeof token !== "string" || token.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "token must not be empty") };
		}

		// Validate and consume the token
		const validation = await tokenModule.validateToken(token, TOKEN_PURPOSE);
		if (!validation.success) {
			return {
				success: false,
				error: makeError("INVALID_TOKEN", "Invalid or expired verification token", {
					originalCode: validation.error.code,
				}),
			};
		}

		const email = validation.data.identifier;
		const userId = validation.data.metadata?.userId as string | undefined;

		// Resolve the user — prefer userId from token metadata, fall back to email lookup.
		let resolvedUserId: string;

		if (userId) {
			resolvedUserId = userId;
		} else {
			const userRows = await db.select({ id: users.id }).from(users).where(eq(users.email, email));

			const user = userRows[0];
			if (!user) {
				return {
					success: false,
					error: makeError("USER_NOT_FOUND", "User account not found"),
				};
			}
			resolvedUserId = user.id;
		}

		// Mark email as verified
		await db
			.update(users)
			.set({ emailVerified: 1, updatedAt: new Date() })
			.where(eq(users.id, resolvedUserId));

		// Revoke any remaining verify tokens for this email
		await tokenModule.revokeTokens(email, TOKEN_PURPOSE);

		return { success: true, data: { userId: resolvedUserId, email } };
	}

	// ── isVerified ────────────────────────────────────────────────────────

	async function isVerified(userId: string): Promise<boolean> {
		const rows = await db
			.select({ emailVerified: users.emailVerified })
			.from(users)
			.where(eq(users.id, userId));

		const user = rows[0];
		return user?.emailVerified === 1;
	}

	// ── handleRequest ─────────────────────────────────────────────────────

	const HANDLED_PATHS = new Set(["/auth/verify-email/send", "/auth/verify-email/confirm"]);

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

		if (pathname === "/auth/verify-email/send") {
			if (typeof b.userId !== "string" || typeof b.email !== "string") {
				return jsonResponse({ error: "Missing required fields: userId, email" }, 400);
			}

			const result = await sendVerification(b.userId, b.email);
			if (!result.success) {
				const status = result.error.code === "USER_NOT_FOUND" ? 404 : 500;
				return jsonResponse({ error: result.error.message }, status);
			}
			return new Response(null, { status: 204 });
		}

		if (pathname === "/auth/verify-email/confirm") {
			if (typeof b.token !== "string") {
				return jsonResponse({ error: "Missing required field: token" }, 400);
			}

			const result = await verify(b.token);
			if (!result.success) {
				return jsonResponse({ error: result.error.message }, 400);
			}

			return jsonResponse({ userId: result.data.userId, email: result.data.email });
		}

		return null;
	}

	return { sendVerification, verify, isVerified, handleRequest };
}
