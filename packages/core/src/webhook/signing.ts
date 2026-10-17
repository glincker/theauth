/**
 * HMAC-SHA256 webhook signing using the Web Crypto API.
 * Edge-compatible, no Node.js `crypto` module required. This binds the signature to a point in time so consumers can reject replays outside their tolerance window.
 */

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

export interface WebhookHeaders {
	"X-TheAuth-Signature": string;
	"X-TheAuth-Timestamp": string;
	"X-TheAuth-Event": string;
	"X-TheAuth-Delivery-Id": string;
}

/** Generate all four required webhook headers for a single delivery. */
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
		"X-TheAuth-Signature": `sha256=${hex}`,
		"X-TheAuth-Timestamp": timestamp,
		"X-TheAuth-Event": event,
		"X-TheAuth-Delivery-Id": deliveryId,
	};
}

/** Generate a cryptographically random delivery ID (32 hex chars / 128 bits). */
export function generateDeliveryId(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);
	return toHex(bytes);
}

/** Current Unix timestamp in whole seconds, as a string. Used for `X-TheAuth-Timestamp`. */
export function currentTimestamp(): string {
	return String(Math.floor(Date.now() / 1000));
}

/**
 * Verify a webhook signature received by your endpoint.
 *
 * @example
 * ```typescript
 * import { verify } from '@glinr/theauth/webhook';
 *
 * const ok = await verify({
 *   secret: process.env.WEBHOOK_SECRET,
 *   rawBody: await request.text(),
 *   signature: request.headers.get('X-TheAuth-Signature') ?? '',
 *   timestamp: request.headers.get('X-TheAuth-Timestamp') ?? '',
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

	if (!signature.startsWith("sha256=")) return false;
	const key = await importHmacKey(secret);
	const expectedHex = await computeHmac(key, `${timestamp}.${rawBody}`);
	const expected = `sha256=${expectedHex}`;

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
