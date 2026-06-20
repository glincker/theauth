/**
 * Email OTP authentication for TheAuth.
 *
 * Sends a short numeric code to the user's email. The code is hashed before
 * storage so a database compromise does not leak valid codes. Brute-force is
 * limited by a configurable `maxAttempts` counter per code record.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
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
import { generateId, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { emailOtps, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface EmailOtpConfig {
	/** Send the OTP code via email. */
	sendOtp: (email: string, code: string) => Promise<void>;
	/** Digit length of the generated code (default: 6) */
	codeLength?: number;
	/** Code expiry in seconds (default: 300 = 5 minutes) */
	codeExpiry?: number;
	/** Max verification attempts before the code is invalidated (default: 5) */
	maxAttempts?: number;
}

export interface EmailOtpModule {
	/** Send a one-time code to the email. */
	sendCode: (email: string) => Promise<{ sent: boolean }>;
	/**
	 * Verify an OTP code for the given email.
	 * Returns null when the code is wrong, expired, or max attempts exceeded.
	 */
	verifyCode: (
		email: string,
		code: string,
	) => Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date };
	} | null>;
	/**
	 * Handle an incoming HTTP request.
	 *
	 * - `POST /auth/otp/send`   – JSON body `{ email: string }`
	 * - `POST /auth/otp/verify` – JSON body `{ email: string; code: string }`
	 *
	 * Returns null when the path does not match.
	 */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_CODE_LENGTH = 6;
const DEFAULT_CODE_EXPIRY_SECONDS = 300; // 5 minutes
const DEFAULT_MAX_ATTEMPTS = 5;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function hashCode(code: string): Promise<string> {
	return sha256(code);
}

function generateNumericCode(length: number): string {
	// Build the code digit-by-digit using generateId entropy (avoid modulo bias).
	// Each hex digit maps to 0-15; we take digits 0-9 and retry for A-F.
	const digits: string[] = [];
	while (digits.length < length) {
		// generateId gives 32 hex chars — plenty of entropy per call.
		for (const char of generateId().replace(/-/g, "")) {
			if (digits.length >= length) break;
			const num = parseInt(char, 16);
			if (num < 10) digits.push(String(num));
		}
	}
	return digits.join("");
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createEmailOtpModule(
	config: EmailOtpConfig,
	db: Database,
	sessionManager: SessionManager,
): EmailOtpModule {
	const codeLength = config.codeLength ?? DEFAULT_CODE_LENGTH;
	const codeExpiry = config.codeExpiry ?? DEFAULT_CODE_EXPIRY_SECONDS;
	const maxAttempts = config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;

	// ── helpers ─────────────────────────────────────────────────────────────

	async function findOrCreateUser(email: string): Promise<{ id: string; email: string }> {
		const existing = await db
			.select({ id: users.id, email: users.email })
			.from(users)
			.where(eq(users.email, email));

		if (existing[0]) return { id: existing[0].id, email: existing[0].email };

		const id = generateId();
		const now = new Date();
		await db.insert(users).values({
			id,
			email,
			createdAt: now,
			updatedAt: now,
		});

		return { id, email };
	}

	// ── public API ───────────────────────────────────────────────────────────

	async function sendCode(email: string): Promise<{ sent: boolean }> {
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
		email: string,
		code: string,
	): Promise<{
		user: { id: string; email: string };
		session: { token: string; expiresAt: Date };
	} | null> {
		const now = new Date();

		const rows = await db
			.select()
			.from(emailOtps)
			.where(and(eq(emailOtps.email, email), gt(emailOtps.expiresAt, now)));

		const record = rows[0];
		if (!record) return null;

		// Check attempt count before doing anything else.
		if (record.attempts >= maxAttempts) return null;

		// Increment attempts (do this before checking the code to prevent timing
		// attacks where an attacker probes whether the attempt counter is at max).
		await db
			.update(emailOtps)
			.set({ attempts: record.attempts + 1 })
			.where(eq(emailOtps.id, record.id));

		if ((await hashCode(code)) !== record.codeHash) return null;

		// Code is correct — remove the record to prevent re-use.
		await db.delete(emailOtps).where(eq(emailOtps.id, record.id));

		const user = await findOrCreateUser(email);
		const { token: sessionToken, session } = await sessionManager.create(user.id);

		return {
			user,
			session: { token: sessionToken, expiresAt: session.expiresAt },
		};
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname;

		if (request.method !== "POST") return null;

		// POST /auth/otp/send
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

			const email = String((body as Record<string, unknown>).email)
				.trim()
				.toLowerCase();
			const result = await sendCode(email);
			return new Response(JSON.stringify(result), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		// POST /auth/otp/verify
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

			const email = b.email.trim().toLowerCase();
			const result = await verifyCode(email, b.code.trim());

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
