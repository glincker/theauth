/**
 * Phone number (SMS OTP) authentication for TheAuth.
 *
 * Generates a short numeric code, hashes it with SHA-256 before storage, and
 * calls the caller-provided `sendSms` function. On verification the hash is
 * compared in constant time to prevent timing attacks.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: { session: { secret: process.env.SESSION_SECRET } },
 *   phone: {
 *     sendSms: async (phone, code) => {
 *       await twilio.messages.create({ to: phone, body: `Your code: ${code}` });
 *     },
 *   },
 * });
 * ```
 */

import { and, eq, gt } from "drizzle-orm";
import { constantTimeEqual, fromHex, generateId, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { phoneVerifications, users } from "../db/schema.js";
import type { SessionManager } from "../session/session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PhoneAuthConfig {
	/** Called to deliver the OTP code to the user via SMS. */
	sendSms: (phoneNumber: string, code: string) => Promise<void>;
	/** Digit length of the generated code (default: 6) */
	codeLength?: number;
	/** Code expiry in seconds (default: 300) */
	codeExpiry?: number;
	/** Max verification attempts before code is invalidated (default: 5) */
	maxAttempts?: number;
}

export interface PhoneAuthModule {
	/** Send a one-time code to the phone number. */
	sendCode: (phoneNumber: string) => Promise<{ sent: boolean }>;
	/**
	 * Verify the code for the given phone number.
	 * Returns null when the code is wrong, expired, or attempts exceeded.
	 */
	verifyCode: (
		phoneNumber: string,
		code: string,
	) => Promise<{
		user: { id: string; phone: string };
		session: { token: string; expiresAt: Date };
	} | null>;
	/**
	 * Handle an incoming HTTP request.
	 *
	 * - `POST /auth/phone/send-code`  – JSON body `{ phoneNumber: string }`
	 * - `POST /auth/phone/verify`     – JSON body `{ phoneNumber: string; code: string }`
	 *
	 * Returns null when the path does not match.
	 */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_CODE_LENGTH = 6;
const DEFAULT_CODE_EXPIRY_SECONDS = 300;
const DEFAULT_MAX_ATTEMPTS = 5;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function hashCode(code: string): Promise<string> {
	return sha256(code);
}

async function codesEqual(stored: string, candidate: string): Promise<boolean> {
	const a = fromHex(stored);
	const candidateHash = await hashCode(candidate);
	const b = fromHex(candidateHash);
	if (a.byteLength !== b.byteLength) return false;
	return constantTimeEqual(a, b);
}

function generateNumericCode(length: number): string {
	const digits: string[] = [];
	while (digits.length < length) {
		for (const char of generateId().replace(/-/g, "")) {
			if (digits.length >= length) break;
			const num = parseInt(char, 16);
			if (num < 10) digits.push(String(num));
		}
	}
	return digits.join("");
}

function normalisePhone(phone: string): string {
	// Remove all whitespace; caller is responsible for E.164 formatting
	return phone.replace(/\s+/g, "");
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

export function createPhoneAuthModule(
	config: PhoneAuthConfig,
	db: Database,
	sessionManager: SessionManager,
): PhoneAuthModule {
	const codeLength = config.codeLength ?? DEFAULT_CODE_LENGTH;
	const codeExpiry = config.codeExpiry ?? DEFAULT_CODE_EXPIRY_SECONDS;
	const maxAttempts = config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;

	async function findOrCreateUser(phone: string): Promise<{ id: string; phone: string }> {
		// Look up user by phone number stored in metadata
		const allUsers = await db.select({ id: users.id, metadata: users.metadata }).from(users);

		for (const u of allUsers) {
			if (u.metadata?.phone === phone) {
				return { id: u.id, phone };
			}
		}

		const id = generateId();
		const now = new Date();
		await db.insert(users).values({
			id,
			email: `${phone.replace(/\+/g, "")}@phone.local`,
			metadata: { phone },
			createdAt: now,
			updatedAt: now,
		});

		return { id, phone };
	}

	// ── public API ─────────────────────────────────────────────────────────

	async function sendCode(phoneNumber: string): Promise<{ sent: boolean }> {
		const phone = normalisePhone(phoneNumber);
		const code = generateNumericCode(codeLength);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + codeExpiry * 1000);

		// Replace any existing record for this phone number
		await db.delete(phoneVerifications).where(eq(phoneVerifications.phoneNumber, phone));

		await db.insert(phoneVerifications).values({
			id: generateId(),
			phoneNumber: phone,
			codeHash: await hashCode(code),
			attempts: 0,
			expiresAt,
			createdAt: now,
		});

		await config.sendSms(phone, code);

		return { sent: true };
	}

	async function verifyCode(
		phoneNumber: string,
		code: string,
	): Promise<{
		user: { id: string; phone: string };
		session: { token: string; expiresAt: Date };
	} | null> {
		const phone = normalisePhone(phoneNumber);
		const now = new Date();

		const rows = await db
			.select()
			.from(phoneVerifications)
			.where(and(eq(phoneVerifications.phoneNumber, phone), gt(phoneVerifications.expiresAt, now)));

		const record = rows[0];
		if (!record) return null;

		if (record.attempts >= maxAttempts) return null;

		// Increment attempts before checking — prevents timing probes
		await db
			.update(phoneVerifications)
			.set({ attempts: record.attempts + 1 })
			.where(eq(phoneVerifications.id, record.id));

		if (!(await codesEqual(record.codeHash, code))) return null;

		// Code verified — remove record to prevent re-use
		await db.delete(phoneVerifications).where(eq(phoneVerifications.id, record.id));

		const user = await findOrCreateUser(phone);
		const { token, session } = await sessionManager.create(user.id);

		return {
			user,
			session: { token, expiresAt: session.expiresAt },
		};
	}

	const HANDLED_PATHS = new Set(["/auth/phone/send-code", "/auth/phone/verify"]);

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

		if (pathname === "/auth/phone/send-code") {
			if (typeof b.phoneNumber !== "string") {
				return jsonResponse({ error: "Missing required field: phoneNumber" }, 400);
			}
			const result = await sendCode(b.phoneNumber);
			return jsonResponse(result);
		}

		if (pathname === "/auth/phone/verify") {
			if (typeof b.phoneNumber !== "string" || typeof b.code !== "string") {
				return jsonResponse({ error: "Missing required fields: phoneNumber, code" }, 400);
			}
			const result = await verifyCode(b.phoneNumber, b.code);
			if (!result) {
				return jsonResponse({ error: "Invalid or expired code" }, 401);
			}
			return jsonResponse(result);
		}

		return null;
	}

	return { sendCode, verifyCode, handleRequest };
}
