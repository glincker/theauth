/**
 * Web Crypto API utilities for TheAuth.
 *
 * This module uses ONLY the Web Crypto API (globalThis.crypto) which is
 * available natively in Cloudflare Workers, Deno, Bun, and Node 20+.
 * No `node:crypto` imports are used, making the core package edge-compatible.
 */

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const HEX_CHARS = "0123456789abcdef";

/** Encode a Uint8Array as a lowercase hex string. */
export function toHex(bytes: Uint8Array): string {
	let hex = "";
	for (let i = 0; i < bytes.length; i++) {
		const b = bytes[i] as number;
		hex += HEX_CHARS[b >> 4] as string;
		hex += HEX_CHARS[b & 0x0f] as string;
	}
	return hex;
}

/** Decode a hex string into a Uint8Array. */
export function fromHex(hex: string): Uint8Array {
	if (hex.length % 2 !== 0) {
		throw new Error("fromHex: hex string must have even length");
	}
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		const hi = parseInt(hex[i * 2] as string, 16);
		const lo = parseInt(hex[i * 2 + 1] as string, 16);
		if (Number.isNaN(hi) || Number.isNaN(lo)) {
			throw new Error(`fromHex: invalid hex character at position ${i * 2}`);
		}
		bytes[i] = (hi << 4) | lo;
	}
	return bytes;
}

/** Encode a Uint8Array as a base64url string (no padding). */
export function toBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] as number);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode a base64url string into a Uint8Array. */
export function fromBase64Url(b64: string): Uint8Array {
	// Restore standard base64
	let base64 = b64.replace(/-/g, "+").replace(/_/g, "/");
	// Add padding
	while (base64.length % 4 !== 0) {
		base64 += "=";
	}
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

// ---------------------------------------------------------------------------
// Random generation
// ---------------------------------------------------------------------------

/** Generate a v4 UUID using the globally available crypto.randomUUID(). */
export function generateId(): string {
	return globalThis.crypto.randomUUID();
}

/** Generate cryptographically secure random bytes as a Uint8Array. */
export function randomBytes(length: number): Uint8Array {
	const bytes = new Uint8Array(length);
	globalThis.crypto.getRandomValues(bytes);
	return bytes;
}

/** Generate cryptographically secure random bytes as a hex string. */
export function randomBytesHex(length: number): string {
	return toHex(randomBytes(length));
}

// ---------------------------------------------------------------------------
// Text encoding helper (internal)
// ---------------------------------------------------------------------------

const TEXT_ENCODER = new TextEncoder();

function toBytes(data: string | Uint8Array): ArrayBuffer {
	if (typeof data === "string") {
		const encoded = TEXT_ENCODER.encode(data);
		return (encoded.buffer as ArrayBuffer).slice(
			encoded.byteOffset,
			encoded.byteOffset + encoded.byteLength,
		);
	}
	return (data.buffer as ArrayBuffer).slice(data.byteOffset, data.byteOffset + data.byteLength);
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/** SHA-256 hash, returns hex string. */
export async function sha256(data: string | Uint8Array): Promise<string> {
	const digest = await globalThis.crypto.subtle.digest("SHA-256", toBytes(data));
	return toHex(new Uint8Array(digest));
}

/** SHA-256 hash, returns Uint8Array. */
export async function sha256Raw(data: string | Uint8Array): Promise<Uint8Array> {
	const digest = await globalThis.crypto.subtle.digest("SHA-256", toBytes(data));
	return new Uint8Array(digest);
}

/** SHA-1 hash, returns hex string. Needed for HIBP k-anonymity. */
export async function sha1(data: string | Uint8Array): Promise<string> {
	const digest = await globalThis.crypto.subtle.digest("SHA-1", toBytes(data));
	return toHex(new Uint8Array(digest));
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

/** Import a secret key for HMAC operations. */
export async function importHmacKey(
	key: string | Uint8Array,
	hash: "SHA-256" | "SHA-1" = "SHA-256",
): Promise<CryptoKey> {
	const keyData = typeof key === "string" ? TEXT_ENCODER.encode(key) : key;
	return globalThis.crypto.subtle.importKey(
		"raw",
		(keyData.buffer as ArrayBuffer).slice(
			keyData.byteOffset,
			keyData.byteOffset + keyData.byteLength,
		),
		{ name: "HMAC", hash: { name: hash } },
		false,
		["sign", "verify"],
	);
}

/** HMAC-SHA256 sign, returns hex string. */
export async function hmacSha256(
	key: string | Uint8Array,
	data: string | Uint8Array,
): Promise<string> {
	const cryptoKey = await importHmacKey(key, "SHA-256");
	const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, toBytes(data));
	return toHex(new Uint8Array(signature));
}

/** HMAC-SHA256 sign, returns Uint8Array. */
export async function hmacSha256Raw(
	key: string | Uint8Array,
	data: string | Uint8Array,
): Promise<Uint8Array> {
	const cryptoKey = await importHmacKey(key, "SHA-256");
	const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, toBytes(data));
	return new Uint8Array(signature);
}

/** HMAC-SHA1 sign, returns Uint8Array (needed for TOTP per RFC 6238). */
export async function hmacSha1Raw(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const cryptoKey = await importHmacKey(key, "SHA-1");
	const buf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, buf);
	return new Uint8Array(signature);
}

// ---------------------------------------------------------------------------
// PBKDF2 password hashing
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 100_000; // CF Workers caps at 100K; OWASP recommends 600K for Node.js
const PBKDF2_KEY_LENGTH = 64; // bytes
const PBKDF2_SALT_LENGTH = 32; // bytes

/**
 * Hash a password using PBKDF2-SHA256.
 *
 * Returns a string in the format: `pbkdf2:iterations:salt_hex:hash_hex`
 * which is safe to store in the database.
 */
export async function pbkdf2Hash(
	password: string,
	salt?: Uint8Array,
	iterations?: number,
): Promise<string> {
	const actualSalt = salt ?? randomBytes(PBKDF2_SALT_LENGTH);
	const actualIterations = iterations ?? PBKDF2_ITERATIONS;

	const keyMaterial = await globalThis.crypto.subtle.importKey(
		"raw",
		TEXT_ENCODER.encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);

	const saltBuf = (actualSalt.buffer as ArrayBuffer).slice(
		actualSalt.byteOffset,
		actualSalt.byteOffset + actualSalt.byteLength,
	);
	const derived = await globalThis.crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			salt: saltBuf,
			iterations: actualIterations,
			hash: "SHA-256",
		},
		keyMaterial,
		PBKDF2_KEY_LENGTH * 8,
	);

	return `pbkdf2:${actualIterations}:${toHex(actualSalt)}:${toHex(new Uint8Array(derived))}`;
}

/**
 * Verify a password against a stored PBKDF2 hash.
 *
 * Supports the `pbkdf2:iterations:salt:hash` format produced by `pbkdf2Hash`.
 */
export async function pbkdf2Verify(password: string, stored: string): Promise<boolean> {
	const parts = stored.split(":");
	if (parts.length !== 4 || parts[0] !== "pbkdf2") {
		return false;
	}

	const iterations = parseInt(parts[1] as string, 10);
	const salt = fromHex(parts[2] as string);
	const storedHash = fromHex(parts[3] as string);

	if (Number.isNaN(iterations)) return false;

	const keyMaterial = await globalThis.crypto.subtle.importKey(
		"raw",
		TEXT_ENCODER.encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);

	const saltBuf = (salt.buffer as ArrayBuffer).slice(
		salt.byteOffset,
		salt.byteOffset + salt.byteLength,
	);
	const derived = await globalThis.crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			salt: saltBuf,
			iterations,
			hash: "SHA-256",
		},
		keyMaterial,
		storedHash.length * 8,
	);

	return constantTimeEqual(new Uint8Array(derived), storedHash);
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/**
 * Constant-time comparison of two Uint8Arrays.
 * Returns false immediately if lengths differ (length is not secret).
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.byteLength !== b.byteLength) {
		return false;
	}
	let diff = 0;
	for (let i = 0; i < a.byteLength; i++) {
		diff |= (a[i] as number) ^ (b[i] as number);
	}
	return diff === 0;
}
