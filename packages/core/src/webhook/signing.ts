/**
 * HMAC-SHA256 webhook signing using the Web Crypto API.
 *
 * Edge-compatible — no Node.js `crypto` module required.
 *
 * Signature format: `sha256=<64-char-hex>`
 *
 * The signed message is: `${timestamp}.${rawBody}`
 * where `timestamp` is a Unix second string. This binds the signature to a
 * point in time so consumers can reject replays outside their tolerance window.
 */

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
	const enc = new TextEncoder();
	return crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"],
	);
}

async function computeHmac(key: CryptoKey, message: string): Promise<string> {
	const enc = new TextEncoder();
	const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
	return toHex(new Uint8Array(sig));
}

// ---------------------------------------------------------------------------
// Signing headers
// ---------------------------------------------------------------------------

export interface WebhookHeaders {
	"X-Kavach-Signature": string;
	"X-Kavach-Timestamp": string;
	"X-Kavach-Event": string;
	"X-Kavach-Delivery-Id": string;
}

/**
 * Generate all four required webhook headers for a single delivery.
 *
 * @param secret     - Endpoint signing secret
 * @param rawBody    - Serialised JSON payload (the exact string sent as body)
 * @param event      - Event type string
 * @param deliveryId - Unique delivery ID (pass `generateDeliveryId()`)
 * @param timestamp  - Unix seconds as a string (pass `currentTimestamp()`)
 */
export async function buildWebhookHeaders(
	secret: string,
	rawBody: string,
	event: string,
	deliveryId: string,
	timestamp: string,
): Promise<WebhookHeaders> {
	const key = await importHmacKey(secret);
	const hex = await computeHmac(key, `${timestamp}.${rawBody}`);

	return {
		"X-Kavach-Signature": `sha256=${hex}`,
		"X-Kavach-Timestamp": timestamp,
		"X-Kavach-Event": event,
		"X-Kavach-Delivery-Id": deliveryId,
	};
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random delivery ID (32 hex chars / 128 bits).
 */
export function generateDeliveryId(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);
	return toHex(bytes);
}

/**
 * Current Unix timestamp in whole seconds, as a string.
 * Used for `X-Kavach-Timestamp`.
 */
export function currentTimestamp(): string {
	return String(Math.floor(Date.now() / 1000));
}

// ---------------------------------------------------------------------------
// Verification helper for consumers
// ---------------------------------------------------------------------------

/**
 * Verify a webhook signature received by your endpoint.
 *
 * @param secret         - The shared secret for this endpoint
 * @param rawBody        - The raw request body string (do NOT parse first)
 * @param signature      - The `X-Kavach-Signature` header value (`sha256=…`)
 * @param timestamp      - The `X-Kavach-Timestamp` header value
 * @param maxAgeSeconds  - Reject requests older than this (default: 300 = 5 min)
 * @returns true if the signature is valid and the request is not a replay
 *
 * @example
 * ```typescript
 * import { verify } from '@glinr/theauth/webhook';
 *
 * const ok = await verify({
 *   secret: process.env.WEBHOOK_SECRET,
 *   rawBody: await request.text(),
 *   signature: request.headers.get('X-Kavach-Signature') ?? '',
 *   timestamp: request.headers.get('X-Kavach-Timestamp') ?? '',
 * });
 * if (!ok) return new Response('Forbidden', { status: 403 });
 * ```
 */
export async function verify({
	secret,
	rawBody,
	signature,
	timestamp,
	maxAgeSeconds = 300,
}: {
	secret: string;
	rawBody: string;
	signature: string;
	timestamp: string;
	maxAgeSeconds?: number;
}): Promise<boolean> {
	// Replay check
	const ts = Number(timestamp);
	if (!Number.isFinite(ts)) return false;
	const age = Math.floor(Date.now() / 1000) - ts;
	if (age > maxAgeSeconds || age < -60) return false;

	// Signature check
	if (!signature.startsWith("sha256=")) return false;
	const key = await importHmacKey(secret);
	const expectedHex = await computeHmac(key, `${timestamp}.${rawBody}`);
	const expected = `sha256=${expectedHex}`;

	// Constant-time comparison
	if (expected.length !== signature.length) return false;
	const enc = new TextEncoder();
	const a = enc.encode(expected);
	const b = enc.encode(signature);
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	}
	return diff === 0;
}
