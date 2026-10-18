import type { StripeEvent } from "./stripe-types.js";

const STRIPE_API_BASE = "https://api.stripe.com/v1";
export const DEFAULT_API_VERSION = "2024-12-18.acacia";

/** Encode a plain object as application/x-www-form-urlencoded, supporting nested objects */
function formEncode(params: Record<string, unknown>, prefix = ""): string {
	const parts: string[] = [];

	for (const [key, value] of Object.entries(params)) {
		if (value === undefined || value === null) continue;

		const encodedKey = prefix ? `${prefix}[${encodeURIComponent(key)}]` : encodeURIComponent(key);

		if (typeof value === "object" && !Array.isArray(value)) {
			const nested = formEncode(value as Record<string, unknown>, encodedKey);
			if (nested) parts.push(nested);
		} else if (Array.isArray(value)) {
			for (const item of value) {
				parts.push(`${encodedKey}[]=${encodeURIComponent(String(item))}`);
			}
		} else {
			parts.push(`${encodedKey}=${encodeURIComponent(String(value))}`);
		}
	}

	return parts.join("&");
}

export async function stripeRequest<T>(
	secretKey: string,
	apiVersion: string,
	method: "GET" | "POST",
	path: string,
	body?: Record<string, unknown>,
): Promise<T> {
	const url = `${STRIPE_API_BASE}${path}`;
	const headers: Record<string, string> = {
		Authorization: `Bearer ${secretKey}`,
		"Stripe-Version": apiVersion,
	};

	let bodyStr: string | undefined;
	if (body && method === "POST") {
		headers["Content-Type"] = "application/x-www-form-urlencoded";
		bodyStr = formEncode(body);
	}

	const response = await fetch(url, {
		method,
		headers,
		body: bodyStr,
	});

	const json = (await response.json()) as { error?: { message: string } } & T;

	if (!response.ok) {
		const message = json.error?.message ?? `Stripe API error: ${response.status}`;
		throw new Error(message);
	}

	return json as T;
}

// Webhook signature verification (constant-time HMAC-SHA256)

export async function verifyWebhookSignature(
	payload: string,
	signatureHeader: string,
	webhookSecret: string,
): Promise<StripeEvent> {
	// Parse Stripe-Signature header: t=<timestamp>,v1=<sig1>,v1=<sig2>,...
	const parts: Record<string, string[]> = {};
	for (const part of signatureHeader.split(",")) {
		const eqIdx = part.indexOf("=");
		if (eqIdx === -1) continue;
		const k = part.slice(0, eqIdx);
		const v = part.slice(eqIdx + 1);
		if (!parts[k]) parts[k] = [];
		parts[k].push(v);
	}

	const timestamp = parts.t?.[0];
	const signatures = parts.v1 ?? [];

	if (!timestamp || signatures.length === 0) {
		throw new Error("Invalid Stripe-Signature header");
	}

	// Reject payloads older than 5 minutes
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - parseInt(timestamp, 10)) > 300) {
		throw new Error("Stripe webhook timestamp is too old");
	}

	const signedPayload = `${timestamp}.${payload}`;

	// Derive expected signature using Web Crypto API (avoids Buffer)
	const encoder = new TextEncoder();
	const keyData = encoder.encode(webhookSecret);
	const msgData = encoder.encode(signedPayload);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyData,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);

	const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, msgData);
	const expectedSig = Array.from(new Uint8Array(signatureBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

	// Constant-time comparison, compare against all v1 signatures
	let verified = false;
	for (const sig of signatures) {
		if (sig.length !== expectedSig.length) continue;

		// Encode both as Uint8Array and XOR all bytes (constant-time)
		const a = encoder.encode(sig);
		const b = encoder.encode(expectedSig);
		let diff = 0;
		for (let i = 0; i < a.length; i++) {
			diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
		}
		if (diff === 0) {
			verified = true;
			break;
		}
	}

	if (!verified) {
		throw new Error("Stripe webhook signature verification failed");
	}

	return JSON.parse(payload) as StripeEvent;
}
