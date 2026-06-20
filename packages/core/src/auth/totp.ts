/**
 * TOTP two-factor authentication for TheAuth.
 *
 * Implements RFC 6238 (TOTP) and RFC 4226 (HOTP) from scratch using
 * the Web Crypto API — no external dependencies.
 *
 * Flow:
 *   1. `setup(userId)`  — generate secret + backup codes (not yet active)
 *   2. `enable(userId, code)` — verify the code, flip enabled = true
 *   3. `verify(userId, code)` — called on each login after password check
 *   4. `disable(userId, code)` — verify then delete the record
 */

import { eq } from "drizzle-orm";
import { hmacSha1Raw, randomBytes, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { totpRecords } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TotpConfig {
	/** App name shown in authenticator apps (default: "TheAuth") */
	appName?: string;
	/** TOTP period in seconds (default: 30) */
	period?: number;
	/** Number of backup codes to generate (default: 10) */
	backupCodeCount?: number;
	/** Accept codes from adjacent time periods for clock drift (default: 1) */
	window?: number;
}

export interface TotpSetup {
	/** Base32-encoded secret for the authenticator app */
	secret: string;
	/** otpauth:// URI for QR code generation */
	uri: string;
	/** One-time backup codes (shown once, store hashed) */
	backupCodes: string[];
}

export interface TotpModule {
	/** Generate a new TOTP secret for a user (doesn't enable 2FA yet) */
	setup: (userId: string) => Promise<TotpSetup>;
	/** Verify a TOTP code and enable 2FA for the user */
	enable: (userId: string, code: string) => Promise<{ enabled: boolean }>;
	/** Disable 2FA for a user */
	disable: (userId: string, code: string) => Promise<{ disabled: boolean }>;
	/** Verify a TOTP code (for login) */
	verify: (userId: string, code: string) => Promise<{ valid: boolean; usedBackupCode?: boolean }>;
	/** Check if a user has 2FA enabled */
	isEnabled: (userId: string) => Promise<boolean>;
	/** Regenerate backup codes */
	regenerateBackupCodes: (userId: string, code: string) => Promise<{ backupCodes: string[] }>;
	/** Handle HTTP request */
	handleRequest: (request: Request) => Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface BackupCodeEntry {
	hash: string;
	used: boolean;
}

// ---------------------------------------------------------------------------
// Base32 helpers (RFC 4648)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
	let bits = 0;
	let value = 0;
	let output = "";

	for (let i = 0; i < bytes.length; i++) {
		value = (value << 8) | (bytes[i] ?? 0);
		bits += 8;

		while (bits >= 5) {
			output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31] ?? "";
			bits -= 5;
		}
	}

	if (bits > 0) {
		output += BASE32_ALPHABET[(value << (5 - bits)) & 31] ?? "";
	}

	return output;
}

function base32Decode(encoded: string): Uint8Array {
	const str = encoded.toUpperCase().replace(/=+$/, "");
	let bits = 0;
	let value = 0;
	const output: number[] = [];

	for (let i = 0; i < str.length; i++) {
		const ch = str[i] ?? "";
		const idx = BASE32_ALPHABET.indexOf(ch);
		if (idx === -1) {
			throw new Error(`Invalid base32 character: ${ch}`);
		}
		value = (value << 5) | idx;
		bits += 5;

		if (bits >= 8) {
			output.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
	}

	return new Uint8Array(output);
}

// ---------------------------------------------------------------------------
// TOTP core (RFC 6238 / RFC 4226)
// ---------------------------------------------------------------------------

async function generateTotp(secret: Uint8Array, time: number, period: number): Promise<string> {
	const counter = Math.floor(time / period);

	// Convert counter to 8-byte big-endian buffer
	const counterBuffer = new Uint8Array(8);
	let remaining = counter;
	for (let i = 7; i >= 0; i--) {
		counterBuffer[i] = remaining & 0xff;
		remaining = Math.floor(remaining / 256);
	}

	// HMAC-SHA1(secret, counterBuffer)
	const digest = await hmacSha1Raw(secret, counterBuffer);

	// Dynamic truncation
	const offset = (digest[19] ?? 0) & 0xf;
	const code =
		((((digest[offset] ?? 0) & 0x7f) << 24) |
			(((digest[offset + 1] ?? 0) & 0xff) << 16) |
			(((digest[offset + 2] ?? 0) & 0xff) << 8) |
			((digest[offset + 3] ?? 0) & 0xff)) %
		1_000_000;

	return code.toString().padStart(6, "0");
}

async function verifyTotp(
	secret: Uint8Array,
	code: string,
	period: number,
	window: number,
): Promise<boolean> {
	const now = Math.floor(Date.now() / 1000);

	for (let delta = -window; delta <= window; delta++) {
		const expected = await generateTotp(secret, now + delta * period, period);
		if (expected === code) return true;
	}

	return false;
}

// ---------------------------------------------------------------------------
// Secret generation
// ---------------------------------------------------------------------------

function generateSecret(): string {
	const bytes = randomBytes(20);
	return base32Encode(bytes);
}

// ---------------------------------------------------------------------------
// Backup codes
// ---------------------------------------------------------------------------

const BACKUP_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I confusion

function generateBackupCode(): string {
	const bytes = randomBytes(8);
	let code = "";
	for (let i = 0; i < 8; i++) {
		const byte = bytes[i] ?? 0;
		code += BACKUP_CODE_CHARS[byte % BACKUP_CODE_CHARS.length] ?? "A";
	}
	return code;
}

async function hashBackupCode(code: string): Promise<string> {
	return sha256(code);
}

async function generateBackupCodes(
	count: number,
): Promise<{ plain: string[]; hashed: BackupCodeEntry[] }> {
	const plain: string[] = [];
	const hashed: BackupCodeEntry[] = [];

	for (let i = 0; i < count; i++) {
		const code = generateBackupCode();
		plain.push(code);
		hashed.push({ hash: await hashBackupCode(code), used: false });
	}

	return { plain, hashed };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function parseBody(request: Request): Promise<Record<string, unknown>> {
	try {
		return (await request.json()) as Record<string, unknown>;
	} catch {
		return {};
	}
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createTotpModule(config: TotpConfig, db: Database): TotpModule {
	const appName = config.appName ?? "TheAuth";
	const period = config.period ?? 30;
	const backupCodeCount = config.backupCodeCount ?? 10;
	const window = config.window ?? 1;

	// ── setup ────────────────────────────────────────────────────────────────

	async function setup(userId: string): Promise<TotpSetup> {
		const secretStr = generateSecret();
		const { plain, hashed } = await generateBackupCodes(backupCodeCount);

		const uri = `otpauth://totp/${encodeURIComponent(appName)}:${encodeURIComponent(userId)}?secret=${secretStr}&issuer=${encodeURIComponent(appName)}&algorithm=SHA1&digits=6&period=${period}`;

		const now = new Date();

		// Upsert: replace any existing (pending) record for this user
		const existing = await db.select().from(totpRecords).where(eq(totpRecords.userId, userId));

		if (existing.length > 0) {
			await db
				.update(totpRecords)
				.set({
					secret: secretStr,
					enabled: false,
					backupCodes: hashed,
					updatedAt: now,
				})
				.where(eq(totpRecords.userId, userId));
		} else {
			await db.insert(totpRecords).values({
				userId,
				secret: secretStr,
				enabled: false,
				backupCodes: hashed,
				createdAt: now,
				updatedAt: now,
			});
		}

		return { secret: secretStr, uri, backupCodes: plain };
	}

	// ── enable ───────────────────────────────────────────────────────────────

	async function enable(userId: string, code: string): Promise<{ enabled: boolean }> {
		const rows = await db.select().from(totpRecords).where(eq(totpRecords.userId, userId));

		const record = rows[0];
		if (!record) {
			return { enabled: false };
		}

		const secretBytes = base32Decode(record.secret);
		const valid = await verifyTotp(secretBytes, code, period, window);

		if (!valid) {
			return { enabled: false };
		}

		await db
			.update(totpRecords)
			.set({ enabled: true, updatedAt: new Date() })
			.where(eq(totpRecords.userId, userId));

		return { enabled: true };
	}

	// ── verify ───────────────────────────────────────────────────────────────

	async function verify(
		userId: string,
		code: string,
	): Promise<{ valid: boolean; usedBackupCode?: boolean }> {
		const rows = await db.select().from(totpRecords).where(eq(totpRecords.userId, userId));

		const record = rows[0];
		if (!record || !record.enabled) {
			return { valid: false };
		}

		// Try TOTP first
		const secretBytes = base32Decode(record.secret);
		if (await verifyTotp(secretBytes, code, period, window)) {
			return { valid: true };
		}

		// Try backup codes
		const codeHash = await hashBackupCode(code.toUpperCase());
		const backupCodes = record.backupCodes as BackupCodeEntry[];
		const matchIndex = backupCodes.findIndex((b) => b.hash === codeHash && !b.used);

		if (matchIndex === -1) {
			return { valid: false };
		}

		// Mark the backup code as used
		const updated = backupCodes.map((b, i) => (i === matchIndex ? { ...b, used: true } : b));

		await db
			.update(totpRecords)
			.set({ backupCodes: updated, updatedAt: new Date() })
			.where(eq(totpRecords.userId, userId));

		return { valid: true, usedBackupCode: true };
	}

	// ── disable ──────────────────────────────────────────────────────────────

	async function disable(userId: string, code: string): Promise<{ disabled: boolean }> {
		const result = await verify(userId, code);
		if (!result.valid) {
			return { disabled: false };
		}

		await db.delete(totpRecords).where(eq(totpRecords.userId, userId));
		return { disabled: true };
	}

	// ── isEnabled ────────────────────────────────────────────────────────────

	async function isEnabled(userId: string): Promise<boolean> {
		const rows = await db
			.select({ enabled: totpRecords.enabled })
			.from(totpRecords)
			.where(eq(totpRecords.userId, userId));

		return rows[0]?.enabled === true;
	}

	// ── regenerateBackupCodes ────────────────────────────────────────────────

	async function regenerateBackupCodes(
		userId: string,
		code: string,
	): Promise<{ backupCodes: string[] }> {
		const result = await verify(userId, code);
		if (!result.valid) {
			throw new Error("Invalid TOTP code — cannot regenerate backup codes");
		}

		const { plain, hashed } = await generateBackupCodes(backupCodeCount);

		await db
			.update(totpRecords)
			.set({ backupCodes: hashed, updatedAt: new Date() })
			.where(eq(totpRecords.userId, userId));

		return { backupCodes: plain };
	}

	// ── handleRequest ────────────────────────────────────────────────────────

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const path = url.pathname;
		const method = request.method.toUpperCase();

		if (method !== "POST") return null;

		if (path === "/auth/2fa/setup") {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			if (!userId) return jsonResponse({ error: "userId required" }, 400);

			try {
				const result = await setup(userId);
				return jsonResponse(result);
			} catch (err) {
				return jsonResponse({ error: err instanceof Error ? err.message : "Setup failed" }, 500);
			}
		}

		if (path === "/auth/2fa/enable") {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			const code = typeof body.code === "string" ? body.code : null;
			if (!userId || !code) return jsonResponse({ error: "userId and code required" }, 400);

			const result = await enable(userId, code);
			return jsonResponse(result);
		}

		if (path === "/auth/2fa/verify") {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			const code = typeof body.code === "string" ? body.code : null;
			if (!userId || !code) return jsonResponse({ error: "userId and code required" }, 400);

			const result = await verify(userId, code);
			return jsonResponse(result);
		}

		if (path === "/auth/2fa/disable") {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			const code = typeof body.code === "string" ? body.code : null;
			if (!userId || !code) return jsonResponse({ error: "userId and code required" }, 400);

			const result = await disable(userId, code);
			return jsonResponse(result);
		}

		if (path === "/auth/2fa/backup-codes") {
			const body = await parseBody(request);
			const userId = typeof body.userId === "string" ? body.userId : null;
			const code = typeof body.code === "string" ? body.code : null;
			if (!userId || !code) return jsonResponse({ error: "userId and code required" }, 400);

			try {
				const result = await regenerateBackupCodes(userId, code);
				return jsonResponse(result);
			} catch (err) {
				return jsonResponse(
					{ error: err instanceof Error ? err.message : "Failed to regenerate codes" },
					400,
				);
			}
		}

		return null;
	}

	return {
		setup,
		enable,
		disable,
		verify,
		isEnabled,
		regenerateBackupCodes,
		handleRequest,
	};
}
