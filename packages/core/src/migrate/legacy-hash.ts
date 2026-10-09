import { constantTimeEqual, pbkdf2Hash, pbkdf2Verify } from "../crypto/web-crypto.js";
import { base64ToBytes, decodeLegacyHash } from "./hash-format.js";
import { scrypt } from "./scrypt.js";
import type { LegacyHash, MigrationStore, Result } from "./types.js";
import { err, ok } from "./types.js";

/**
 * Verifiers for algorithms that need a library theauth does not ship (bcrypt, argon2).
 * Pass `bcryptjs.compare` or an argon2 `verify` wrapper here.
 */
export interface LegacyVerifiers {
	bcrypt?: (password: string, hash: string) => Promise<boolean>;
	argon2?: (password: string, hash: string) => Promise<boolean>;
}

const PBKDF2_HASH = {
	"pbkdf2-sha1": "SHA-1",
	"pbkdf2-sha256": "SHA-256",
	"pbkdf2-sha512": "SHA-512",
} as const;

const MAX_PBKDF2_ITERATIONS = 5_000_000;
const ENCODER = new TextEncoder();

async function pbkdf2Variant(
	password: string,
	legacy: LegacyHash,
	hash: "SHA-1" | "SHA-256" | "SHA-512",
): Promise<boolean> {
	const iterations = legacy.params?.iterations ?? 0;
	if (!legacy.salt || iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS) return false;
	const expected = base64ToBytes(legacy.hash);
	const key = await globalThis.crypto.subtle.importKey(
		"raw",
		ENCODER.encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);
	const bits = await globalThis.crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt: base64ToBytes(legacy.salt) as BufferSource, iterations, hash },
		key,
		expected.length * 8,
	);
	return constantTimeEqual(new Uint8Array(bits), expected);
}

/** Check a password against a legacy hash. `ok(false)` is a wrong password, an error is a gap. */
export async function verifyLegacyHash(
	password: string,
	legacy: LegacyHash,
	verifiers: LegacyVerifiers = {},
): Promise<Result<boolean>> {
	try {
		switch (legacy.algorithm) {
			case "bcrypt":
			case "argon2": {
				const fn = verifiers[legacy.algorithm];
				if (!fn) {
					return err(
						"VERIFIER_MISSING",
						`No ${legacy.algorithm} verifier configured. Pass one in verifiers.${legacy.algorithm}.`,
					);
				}
				return ok(await fn(password, legacy.hash));
			}
			case "pbkdf2-theauth":
				return ok(await pbkdf2Verify(password, legacy.hash));
			case "scrypt": {
				const { N = 0, r = 0, p = 0, nfkc = false } = legacy.params ?? {};
				if (!legacy.salt) return ok(false);
				const expected = base64ToBytes(legacy.hash);
				const input = nfkc ? password.normalize("NFKC") : password;
				const derived = await scrypt(ENCODER.encode(input), base64ToBytes(legacy.salt), {
					N,
					r,
					p,
					dkLen: expected.length,
				});
				if (!derived) return err("BAD_PARAMS", "scrypt parameters are out of range");
				return ok(constantTimeEqual(derived, expected));
			}
			default:
				return ok(await pbkdf2Variant(password, legacy, PBKDF2_HASH[legacy.algorithm]));
		}
	} catch (e) {
		return err("VERIFY_FAILED", e instanceof Error ? e.name : "verify failed");
	}
}

export interface LegacyAcceptedEvent {
	userId: string;
	algorithm: LegacyHash["algorithm"];
}

export interface LazyMigratorConfig {
	store: MigrationStore;
	verifiers?: LegacyVerifiers;
	/** Source name written to the migration ledger when a login upgrades a hash. */
	source?: string;
	/** Called after a legacy hash verified and the new hash was stored. Errors are swallowed. */
	onLegacyHashAccepted?: (event: LegacyAcceptedEvent) => void | Promise<void>;
	/** Defaults to theauth's PBKDF2. */
	rehash?: (password: string) => Promise<string>;
}

export interface LazyVerifyOutcome {
	valid: boolean;
	rehashed: boolean;
}

/**
 * Verify a password on login and upgrade a legacy hash in place. A rehash or hook
 * failure never turns a correct password into a failed login.
 */
export function createLazyPasswordMigrator(config: LazyMigratorConfig) {
	const { store, verifiers, onLegacyHashAccepted } = config;
	const rehash = config.rehash ?? ((pw: string) => pbkdf2Hash(pw));

	async function verify(userId: string, password: string): Promise<Result<LazyVerifyOutcome>> {
		const stored = await store.getPasswordHash(userId);
		if (!stored) return ok({ valid: false, rehashed: false });
		if (stored.startsWith("pbkdf2:")) {
			return ok({ valid: await pbkdf2Verify(password, stored), rehashed: false });
		}
		const legacy = decodeLegacyHash(stored);
		if (!legacy) return err("UNKNOWN_HASH", "Stored hash format is not recognised");
		const checked = await verifyLegacyHash(password, legacy, verifiers);
		if (!checked.success) return checked;
		if (!checked.data) return ok({ valid: false, rehashed: false });
		let rehashed = false;
		try {
			await store.setPasswordHash(userId, await rehash(password));
			rehashed = true;
		} catch {
			rehashed = false;
		}
		if (rehashed) {
			try {
				await store.recordMigration({
					userId,
					source: config.source ?? "unknown",
					status: "migrated",
					cohort: null,
					errorCode: null,
					at: new Date(),
				});
			} catch {
				// The ledger is for reporting only.
			}
		}
		if (rehashed && onLegacyHashAccepted) {
			try {
				await onLegacyHashAccepted({ userId, algorithm: legacy.algorithm });
			} catch {
				// A broken hook must not fail a correct login.
			}
		}
		return ok({ valid: true, rehashed });
	}

	return { verify };
}

export type LazyPasswordMigrator = ReturnType<typeof createLazyPasswordMigrator>;
