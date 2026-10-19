/**
 * Email verification: single-use verification tokens, sent by email and consumed on confirmation.
 *
 * @example
 * ```typescript
 * const auth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
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
 * await theauth.emailVerification.sendVerification(userId, 'alice@example.com');
 *
 * // Verify the token from the link
 * const result = await theauth.emailVerification.verify(token);
 * if (result.success) console.log('Verified:', result.data.userId);
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import { withUserUpdate } from "../hooks/user-update-hooks.js";
import type { AuthError, Result, TheAuthError } from "../mcp/types.js";
import { normalizeEmail } from "./normalize-email.js";
import type { OneTimeTokenModule } from "./one-time-token.js";
import type { ModuleRequestDeps } from "./request-user.js";
import { authenticationRequired, requestUserId } from "./request-user.js";

export type { AuthError, Result, TheAuthError };

export interface EmailVerificationConfig {
	/** Sends the verification email. TheAuth builds the token and verify URL; you deliver the email. */
	sendVerificationEmail: (email: string, token: string, verifyUrl: string) => Promise<void>;

	/** Verify page URL in your app. The token is appended as `?token=<token>`. */
	verifyUrl: string;

	/** Token TTL in seconds. Default: 86400 (24 hours). */
	tokenTtlSeconds?: number;

	/** Send a verification email automatically after sign-up. Default: false. The caller still handles errors. */
	autoVerifyOnSignUp?: boolean;
}

export interface EmailVerificationModule {
	/** Creates a verification token and sends the email. Returns `{ sent: true }` when dispatched. */
	sendVerification(userId: string, email: string): Promise<Result<{ sent: boolean }>>;

	/** Validates a verification token and marks the email verified. The token is consumed on success. */
	verify(token: string): Promise<Result<{ userId: string; email: string }>>;

	/** Checks whether a user's email address has been verified. */
	isVerified(userId: string): Promise<boolean>;

	/** Handles the email verification HTTP endpoints (see the route list in the module header). */
	handleRequest(request: Request): Promise<Response | null>;
}

const DEFAULT_TOKEN_TTL_SECONDS = 86400; // 24 hours
const TOKEN_PURPOSE = "email-verify" as const;

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

export function createEmailVerificationModule(
	config: EmailVerificationConfig,
	db: Database,
	tokenModule: OneTimeTokenModule,
	deps: ModuleRequestDeps = {},
	databaseHooks: DatabaseHookRunner = createDatabaseHookRunner(undefined),
): EmailVerificationModule {
	const tokenTtl = config.tokenTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;

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

		const normalizedEmail = normalizeEmail(email);

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

		await tokenModule.revokeTokens(normalizedEmail, TOKEN_PURPOSE);

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
			// Send errors are swallowed: the token exists, and the user can request another email.
			void err;
		}

		return { success: true, data: { sent: true } };
	}

	async function verify(token: string): Promise<Result<{ userId: string; email: string }>> {
		if (typeof token !== "string" || token.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "token must not be empty") };
		}

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

		await withUserUpdate(databaseHooks, db, resolvedUserId, {}, async (hooked) => {
			await db
				.update(users)
				.set({ ...hooked, emailVerified: 1, updatedAt: new Date() })
				.where(eq(users.id, resolvedUserId));
		});

		await tokenModule.revokeTokens(email, TOKEN_PURPOSE);

		return { success: true, data: { userId: resolvedUserId, email } };
	}

	async function isVerified(userId: string): Promise<boolean> {
		const rows = await db
			.select({ emailVerified: users.emailVerified })
			.from(users)
			.where(eq(users.id, userId));

		const user = rows[0];
		return user?.emailVerified === 1;
	}

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
			// Sends for the signed-in user only. A body `userId` is ignored.
			const userId = await requestUserId(request, deps.resolveUser);
			if (!userId) return authenticationRequired();
			if (typeof b.email !== "string") {
				return jsonResponse({ error: "Missing required field: email" }, 400);
			}

			const result = await sendVerification(userId, b.email);
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
