/**
 * Email OTP authentication for TheAuth.
 * The code is hashed before storage so a database compromise does not leak valid codes.
 *
 * @example
 * ```typescript
 * const theauth = await createTheAuth({
 *   database: { provider: 'sqlite', url: 'theauth.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   emailOtp: {
 *     sendOtp: async (email, code) => {
 *       await resend.emails.send({ to: email, subject: `Your code: ${code}` });
 *     },
 *   },
 * });
 * ```
 */

import { and, eq, gt } from "drizzle-orm";
import { constantTimeEqual, fromHex, generateId, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { emailOtps, users } from "../db/schema.js";
import { singleUseFor } from "../db/store/for-database.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import type { SessionManager } from "../session/session.js";
import { normalizeEmail } from "./normalize-email.js";
import type { SignInGate } from "./sign-in-gate.js";
import { createSignInGate, SignInGateError, signInGateResponse } from "./sign-in-gate.js";

export interface EmailOtpConfig {
	/** Send the OTP code via email. */
	sendOtp: (email: string, code: string) => Promise<void>;
	/** Digit length of the generated code (default: 6) */
	codeLength?: number;
	/** Code expiry in seconds (default: 300 = 5 minutes) */
	codeExpiry?: number;
	/** Max verification attempts before the code is invalidated (default: 5) */
	maxAttempts?: number;
	/** Minimum seconds between sends to the same address (default: 0, disabled). A send inside the window returns `{ sent: false, retryAfter }`. */
	resendCooldownSeconds?: number;
}

export interface EmailOtpModule {
	/** Send a one-time code to the email. */
	sendCode: (email: string) => Promise<{ sent: boolean; retryAfter?: number }>;
	/**
	 * Verify an OTP code for the given email. Returns null when the code is wrong, expired, or max attempts exceeded. Throws `SignInGateError` when the sign-in gate requires a forced password change or a second factor first (gate method `email_otp`; the code is consumed, finish with the challenge on the error).
	 */
	verifyCode: (
		email: string,
		code: string,
		context?: { request?: Request },
	) => Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date };
	} | null>;
	/**
	 * Handle an incoming HTTP request.
	 * - `POST /auth/otp/send`, JSON body `{ email: string }`
	 * - `POST /auth/otp/verify`, JSON body `{ email: string; code: string }` Returns null when the path does not match.
	 */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// Defaults

const DEFAULT_CODE_LENGTH = 6;
const DEFAULT_CODE_EXPIRY_SECONDS = 300; // 5 minutes
const DEFAULT_MAX_ATTEMPTS = 5;

async function hashCode(code: string): Promise<string> {
	return sha256(code);
}

function generateNumericCode(length: number): string {
	// Build the code digit-by-digit using generateId entropy (avoid modulo bias).
	// Each hex digit maps to 0-15; we take digits 0-9 and retry for A-F.
	const digits: string[] = [];
	while (digits.length < length) {
		// generateId gives 32 hex chars, plenty of entropy per call.
		for (const char of generateId().replace(/-/g, "")) {
			if (digits.length >= length) break;
			const num = parseInt(char, 16);
			if (num < 10) digits.push(String(num));
		}
	}
	return digits.join("");
}

export function createEmailOtpModule(
	config: EmailOtpConfig,
	db: Database,
	sessionManager: SessionManager,
	signInGate?: SignInGate,
	databaseHooks: DatabaseHookRunner = createDatabaseHookRunner(undefined),
): EmailOtpModule {
	const gate = signInGate ?? createSignInGate({ db });
	const codeLength = config.codeLength ?? DEFAULT_CODE_LENGTH;
	const codeExpiry = config.codeExpiry ?? DEFAULT_CODE_EXPIRY_SECONDS;
	const maxAttempts = config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
	const resendCooldown = config.resendCooldownSeconds ?? 0;

	async function findOrCreateUser(email: string): Promise<{ id: string; email: string }> {
		const existing = await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(eq(users.email, email));

		if (existing[0]) return { id: existing[0].id, email: existing[0].email };

		const id = databaseHooks.newId("user");
		const now = new Date();
		let storedEmail = email;
		let storedName: string | null = null;
		let storedMetadata: Record<string, unknown> | null = null;
		if (databaseHooks.has("user", "create")) {
			const hooked = await databaseHooks.before("user", "create", {
				id,
				email,
				name: null,
				metadata: null,
			});
			storedEmail = hooked.email;
			storedName = hooked.name;
			storedMetadata = hooked.metadata;
		}
		await db.insert(users).values({
			id,
			email: storedEmail,
			name: storedName,
			...(storedMetadata ? { metadata: storedMetadata } : {}),
			createdAt: now,
			updatedAt: now,
		});
		await databaseHooks.after("user", "create", {
			id,
			email: storedEmail,
			name: storedName,
			metadata: storedMetadata,
		});

		return { id, email: storedEmail };
	}

	async function sendCode(rawEmail: string): Promise<{ sent: boolean; retryAfter?: number }> {
		const email = normalizeEmail(rawEmail);
		if (resendCooldown > 0) {
			const prior = await db.select().from(emailOtps).where(eq(emailOtps.email, email));
			const last = prior[0];
			if (last) {
				const wait = Math.ceil(
					(last.createdAt.getTime() + resendCooldown * 1000 - Date.now()) / 1000,
				);
				if (wait > 0) return { sent: false, retryAfter: wait };
			}
		}
		const code = generateNumericCode(codeLength);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + codeExpiry * 1000);

		// Delete any previous OTP records for this email before inserting a new one
		// so there is always at most one active record per address.
		await db.delete(emailOtps).where(eq(emailOtps.email, email));

		await db.insert(emailOtps).values({
			id: generateId(),
			email,
			codeHash: await hashCode(code),
			expiresAt,
			attempts: 0,
			createdAt: now,
		});

		await config.sendOtp(email, code);

		return { sent: true };
	}

	async function verifyCode(
		rawEmail: string,
		code: string,
		context?: { request?: Request },
	): Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date };
	} | null> {
		const email = normalizeEmail(rawEmail);
		const now = new Date();

		const rows = await db
			.select()
			.from(emailOtps)
			.where(and(eq(emailOtps.email, email), gt(emailOtps.expiresAt, now)));

		const record = rows[0];
		if (!record) return null;

		// Reserve an attempt with one conditional UPDATE. A read-then-write counter
		// lets N parallel guesses all observe the same count and skip the lockout.
		if (!(await singleUseFor(db).emailOtps.reserveAttempt(record.id, maxAttempts))) return null;

		const given = fromHex(await hashCode(code));
		const stored = fromHex(record.codeHash);
		if (!constantTimeEqual(given, stored)) return null;

		// Correct code: delete returns the row only to the one caller that removed it.
		if (!(await singleUseFor(db).emailOtps.consume(record.id))) return null;

		const user = await findOrCreateUser(email);
		const decision = await gate.evaluate({
			userId: user.id,
			method: "email_otp",
			...(context?.request && { request: context.request }),
		});
		if (decision.action !== "allow") throw new SignInGateError(decision);

		const { token: sessionToken, session } = await sessionManager.create(user.id, undefined, {
			authMethods: ["otp"],
		});

		return {
			user,
			session: { token: sessionToken, expiresAt: session.expiresAt },
		};
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		if (request.method !== "POST") return null;

		if (pathname === "/auth/otp/send") {
			let body: unknown;
			try {
				body = await request.json();
			} catch {
				return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			if (
				typeof body !== "object" ||
				body === null ||
				typeof (body as Record<string, unknown>).email !== "string"
			) {
				return new Response(JSON.stringify({ error: "Missing required field: email" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			const email = normalizeEmail(String((body as Record<string, unknown>).email));
			const result = await sendCode(email);
			return new Response(JSON.stringify(result), {
				status: result.sent ? 200 : 429,
				headers: {
					"Content-Type": "application/json",
					...(result.retryAfter !== undefined ? { "Retry-After": String(result.retryAfter) } : {}),
				},
			});
		}

		if (pathname === "/auth/otp/verify") {
			let body: unknown;
			try {
				body = await request.json();
			} catch {
				return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			const b = body as Record<string, unknown>;
			if (typeof b.email !== "string" || typeof b.code !== "string") {
				return new Response(JSON.stringify({ error: "Missing required fields: email, code" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}

			const email = normalizeEmail(b.email);
			let result: Awaited<ReturnType<typeof verifyCode>>;
			try {
				result = await verifyCode(email, b.code.trim(), { request });
			} catch (err) {
				if (err instanceof SignInGateError) return signInGateResponse(err);
				throw err;
			}

			if (!result) {
				return new Response(JSON.stringify({ error: "Invalid or expired OTP code" }), {
					status: 401,
					headers: { "Content-Type": "application/json" },
				});
			}

			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		return null;
	}

	return { sendCode, verifyCode, handleRequest };
}
