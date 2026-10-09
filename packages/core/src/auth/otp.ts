/**
 * Unified one-time-password service for email and SMS.
 *
 * One service covers sign-in, email verification, password reset and 2FA
 * step-up. Codes are scoped by purpose and identifier, stored only as a keyed
 * hash, compared in constant time, and protected by a resend cooldown plus an
 * attempt lockout. State lives in a SecondaryStorage (memory by default, use
 * redis, KV or database storage for multi-instance deployments).
 *
 * Cooldown and attempt counting are read-modify-write on the storage, so two
 * simultaneous requests can race. The lockout still bounds guessing because a
 * code is deleted once the limit is reached.
 */

import {
	constantTimeEqual,
	fromHex,
	hmacSha256,
	randomBytes,
	sha256,
} from "../crypto/web-crypto.js";
import type { Result, TheAuthError } from "../mcp/types.js";
import { memoryStorage } from "../storage/memory.js";
import type { SecondaryStorage } from "../storage/types.js";
import type { OtpChannel, OtpPurpose, OtpSender } from "./otp-senders.js";

export interface OtpServiceConfig {
	senders: Partial<Record<OtpChannel, OtpSender>>;
	/** Where code state lives (default: in-memory, single process only). */
	storage?: SecondaryStorage;
	/** Secret used to key the code hash. Strongly recommended. */
	secret?: string;
	/** Digits per code (default 6, minimum 4, maximum 10). */
	codeLength?: number;
	/** Code lifetime in seconds (default 300). */
	expiresIn?: number;
	/** Wrong guesses allowed per code before lockout (default 5). */
	maxAttempts?: number;
	/** Lockout length in seconds once attempts are exhausted (default 900). */
	lockoutSeconds?: number;
	/** Minimum seconds between sends to the same identifier and purpose (default 60). */
	resendCooldownSeconds?: number;
}

export interface OtpSendInput {
	purpose: OtpPurpose;
	channel: OtpChannel;
	/** Email address or E.164 phone number. */
	identifier: string;
}

export interface OtpVerifyInput {
	purpose: OtpPurpose;
	identifier: string;
	code: string;
}

export interface OtpService {
	send(input: OtpSendInput): Promise<Result<{ expiresAt: Date }>>;
	/** Resolves with `{ verified: true }` and consumes the code on success. */
	verify(input: OtpVerifyInput): Promise<Result<{ verified: true }>>;
}

interface StoredCode {
	hash: string;
	expiresAt: number;
	attempts: number;
	sentAt: number;
}

function fail(
	code: string,
	message: string,
	retryAfter?: number,
): { success: false; error: TheAuthError } {
	return {
		success: false,
		error: { code, message, ...(retryAfter !== undefined ? { details: { retryAfter } } : {}) },
	};
}

/** Uniform digit string via rejection sampling (no modulo bias). */
export function generateOtpCode(length: number): string {
	let out = "";
	while (out.length < length) {
		for (const byte of randomBytes(length * 2)) {
			if (byte < 250 && out.length < length) out += String(byte % 10);
		}
	}
	return out;
}

export function createOtpService(config: OtpServiceConfig): OtpService {
	const storage = config.storage ?? memoryStorage();
	const length = Math.min(10, Math.max(4, config.codeLength ?? 6));
	const expiresIn = config.expiresIn ?? 300;
	const maxAttempts = config.maxAttempts ?? 5;
	const lockoutSeconds = config.lockoutSeconds ?? 900;
	const cooldown = config.resendCooldownSeconds ?? 60;

	async function keys(purpose: OtpPurpose, identifier: string) {
		const id = await sha256(`${purpose}\n${identifier.trim().toLowerCase()}`);
		return { code: `otp:code:${id}`, lock: `otp:lock:${id}` };
	}

	async function hashCode(purpose: OtpPurpose, identifier: string, code: string): Promise<string> {
		const material = `${purpose}\n${identifier.trim().toLowerCase()}\n${code}`;
		return config.secret ? hmacSha256(config.secret, material) : sha256(material);
	}

	async function lockRemaining(lockKey: string): Promise<number> {
		const raw = await storage.get(lockKey);
		if (raw === null) return 0;
		return Math.max(0, Math.ceil((Number(raw) - Date.now()) / 1000));
	}

	async function read(key: string): Promise<StoredCode | null> {
		const raw = await storage.get(key);
		if (raw === null) return null;
		try {
			return JSON.parse(raw) as StoredCode;
		} catch {
			return null;
		}
	}

	return {
		async send(input) {
			const sender = config.senders[input.channel];
			if (!sender) {
				return fail("OTP_CHANNEL_UNAVAILABLE", `No sender configured for ${input.channel}.`);
			}
			const k = await keys(input.purpose, input.identifier);

			const locked = await lockRemaining(k.lock);
			if (locked > 0) return fail("OTP_LOCKED", "Too many attempts. Try again later.", locked);

			const now = Date.now();
			const existing = await read(k.code);
			if (existing && cooldown > 0) {
				const wait = Math.ceil((existing.sentAt + cooldown * 1000 - now) / 1000);
				if (wait > 0) return fail("OTP_COOLDOWN", "A code was sent recently.", wait);
			}

			const code = generateOtpCode(length);
			const record: StoredCode = {
				hash: await hashCode(input.purpose, input.identifier, code),
				expiresAt: now + expiresIn * 1000,
				attempts: 0,
				sentAt: now,
			};
			await storage.set(k.code, JSON.stringify(record), expiresIn);

			try {
				await sender.send({
					channel: input.channel,
					to: input.identifier,
					code,
					purpose: input.purpose,
					expiresInSeconds: expiresIn,
				});
			} catch (error) {
				await storage.delete(k.code);
				return fail("OTP_SEND_FAILED", error instanceof Error ? error.message : "Delivery failed.");
			}
			return { success: true, data: { expiresAt: new Date(record.expiresAt) } };
		},

		async verify(input) {
			const k = await keys(input.purpose, input.identifier);

			const locked = await lockRemaining(k.lock);
			if (locked > 0) return fail("OTP_LOCKED", "Too many attempts. Try again later.", locked);

			const record = await read(k.code);
			if (!record || record.expiresAt <= Date.now()) {
				return fail("OTP_INVALID", "Invalid or expired code.");
			}

			const expected = fromHex(record.hash);
			const given = fromHex(await hashCode(input.purpose, input.identifier, input.code.trim()));
			if (!constantTimeEqual(expected, given)) {
				const attempts = record.attempts + 1;
				if (attempts >= maxAttempts) {
					await storage.delete(k.code);
					await storage.set(k.lock, String(Date.now() + lockoutSeconds * 1000), lockoutSeconds);
					return fail("OTP_LOCKED", "Too many attempts. Try again later.", lockoutSeconds);
				}
				const ttl = Math.max(1, Math.ceil((record.expiresAt - Date.now()) / 1000));
				await storage.set(k.code, JSON.stringify({ ...record, attempts }), ttl);
				return fail("OTP_INVALID", "Invalid or expired code.");
			}

			await storage.delete(k.code);
			return { success: true, data: { verified: true } };
		},
	};
}
