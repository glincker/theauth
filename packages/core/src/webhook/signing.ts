/**
 * HMAC-SHA256 webhook signing using the Web Crypto API.
 * Edge-compatible, no Node.js `crypto` module required. This binds the signature to a point in time so consumers can reject replays outside their tolerance window.
 */

import type { SecretRingConfig } from "../crypto/secrets.js";
import { DEFAULT_MIN_SECRET_BYTES, SecretRing } from "../crypto/secrets.js";
import { fromHex, toHex } from "../crypto/web-crypto.js";

/**
 * Build the ring for a webhook secret. A plain string keeps the historical rules (any non-empty secret) so existing endpoints keep working. The array and `{ id, secret }` forms are the rotation API and enforce the 32 byte minimum.
 */
export function webhookSecretRing(secret: SecretRingConfig | SecretRing): SecretRing {
	if (secret instanceof SecretRing) return secret;
	return new SecretRing(secret, {
		label: "Webhooks",
		minBytes: typeof secret === "string" ? 1 : DEFAULT_MIN_SECRET_BYTES,
	});
}

export interface WebhookHeaders {
	"X-TheAuth-Signature": string;
	"X-TheAuth-Timestamp": string;
	"X-TheAuth-Event": string;
	"X-TheAuth-Delivery-Id": string;
	/** Present only when the current signing key was configured with an `id`. Receivers try that key first. */
	"X-TheAuth-Key-Id"?: string;
}

/** Generate the webhook headers for a single delivery. Signs with the first (current) secret of a ring. */
export async function buildWebhookHeaders(
	secret: SecretRingConfig | SecretRing,
	rawBody: string,
	event: string,
	deliveryId: string,
	timestamp: string,
): Promise<WebhookHeaders> {
	const { signature, kid } = await webhookSecretRing(secret).sign(`${timestamp}.${rawBody}`);

	return {
		"X-TheAuth-Signature": `sha256=${toHex(signature)}`,
		"X-TheAuth-Timestamp": timestamp,
		"X-TheAuth-Event": event,
		"X-TheAuth-Delivery-Id": deliveryId,
		...(kid === undefined ? {} : { "X-TheAuth-Key-Id": kid }),
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
 *   // During a rotation pass [newSecret, oldSecret].
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
	keyId,
	maxAgeSeconds = 300,
}: {
	/** One secret, or `[current, ...previous]` so deliveries signed before a rotation still verify. */
	secret: SecretRingConfig | SecretRing;
	/** Value of `X-TheAuth-Key-Id`, when present. Only changes which key is tried first. */
	keyId?: string;
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
	const hex = signature.slice("sha256=".length);
	if (!/^[0-9a-f]{64}$/i.test(hex)) return false;
	return webhookSecretRing(secret).verify(`${timestamp}.${rawBody}`, fromHex(hex), keyId);
}
