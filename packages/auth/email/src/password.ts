import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import type { PasswordConfig } from "./types.js";

const SCRYPT_KEYLEN = 64;
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

/** Hashes with scrypt. Returns "salt:hash", both hex-encoded. */
export function hashPassword(password: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const salt = randomBytes(16).toString("hex");
		scrypt(
			password,
			salt,
			SCRYPT_KEYLEN,
			{ N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
			(err, derivedKey) => {
				if (err) {
					reject(err);
					return;
				}
				resolve(`${salt}:${derivedKey.toString("hex")}`);
			},
		);
	});
}

/** Verifies against a stored hash. Uses timingSafeEqual to prevent timing attacks. */
export function verifyPassword(password: string, stored: string): Promise<boolean> {
	return new Promise((resolve, reject) => {
		const separatorIndex = stored.indexOf(":");
		if (separatorIndex === -1) {
			resolve(false);
			return;
		}

		const salt = stored.slice(0, separatorIndex);
		const hash = stored.slice(separatorIndex + 1);
		const expectedBuf = Buffer.from(hash, "hex");

		scrypt(
			password,
			salt,
			SCRYPT_KEYLEN,
			{ N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
			(err, derivedKey) => {
				if (err) {
					reject(err);
					return;
				}
				// Lengths must match before timingSafeEqual
				if (derivedKey.length !== expectedBuf.length) {
					resolve(false);
					return;
				}
				try {
					resolve(timingSafeEqual(derivedKey, expectedBuf));
				} catch {
					resolve(false);
				}
			},
		);
	});
}

export function validatePasswordStrength(
	password: string,
	config: PasswordConfig,
): { valid: boolean; reason?: string } {
	if (password.length < config.minLength) {
		return { valid: false, reason: `Password must be at least ${config.minLength} characters.` };
	}
	if (password.length > config.maxLength) {
		return { valid: false, reason: `Password must be at most ${config.maxLength} characters.` };
	}
	if (config.requireUppercase && !/[A-Z]/.test(password)) {
		return { valid: false, reason: "Password must contain at least one uppercase letter." };
	}
	if (config.requireNumber && !/[0-9]/.test(password)) {
		return { valid: false, reason: "Password must contain at least one number." };
	}
	if (config.requireSpecial && !/[^A-Za-z0-9]/.test(password)) {
		return { valid: false, reason: "Password must contain at least one special character." };
	}
	return { valid: true };
}
