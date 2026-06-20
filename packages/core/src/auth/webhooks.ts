/**
 * Webhook system for TheAuth.
 *
 * Fires signed HTTP POST requests to configured endpoints when auth events
 * occur. Payloads are signed with HMAC-SHA256 and sent with
 * `X-Kavach-Event`, `X-Kavach-Signature`, and `X-Kavach-Timestamp` headers.
 *
 * Delivery is fire-and-forget with exponential backoff retries (1s, 2s, 4s).
 * Failed deliveries after all retries are silently dropped so they never block
 * the auth operation that triggered them.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   webhooks: [{
 *     url: 'https://my-service.example.com/webhooks/kavach',
 *     secret: process.env.WEBHOOK_SECRET,
 *     events: ['user.created', 'session.created'],
 *   }],
 * });
 *
 * // Emit from anywhere in your app
 * kavach.webhooks?.emit('user.created', { userId: user.id });
 * ```
 */

import { hmacSha256 } from "../crypto/web-crypto.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type WebhookEvent =
	| "user.created"
	| "user.deleted"
	| "user.updated"
	| "session.created"
	| "session.revoked"
	| "agent.created"
	| "agent.revoked"
	| "agent.rotated"
	| "auth.sign-in"
	| "auth.sign-up"
	| "auth.password-reset"
	| "auth.email-verified";

export interface WebhookConfig {
	/** Destination URL for the webhook POST request. */
	url: string;
	/** HMAC signing secret — keep this private. */
	secret: string;
	/** Events this endpoint subscribes to. */
	events: WebhookEvent[];
	/** Retry count (default: 3) */
	retries?: number;
	/** Request timeout in milliseconds (default: 10000) */
	timeout?: number;
}

export interface WebhookModule {
	/** Fire a webhook for an event. Non-blocking — retries happen in background. */
	emit: (event: WebhookEvent, payload: Record<string, unknown>) => void;
	/** Register an additional webhook endpoint at runtime. */
	addEndpoint: (config: WebhookConfig) => void;
	/** Return a copy of all configured endpoints. */
	listEndpoints: () => WebhookConfig[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function signPayload(secret: string, timestamp: string, body: string): Promise<string> {
	const data = `${timestamp}.${body}`;
	return hmacSha256(secret, data);
}

async function deliverOnce(
	endpoint: WebhookConfig,
	event: WebhookEvent,
	body: string,
	timestamp: string,
): Promise<boolean> {
	const signature = await signPayload(endpoint.secret, timestamp, body);
	const timeout = endpoint.timeout ?? 10_000;

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeout);

	try {
		const response = await fetch(endpoint.url, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Kavach-Event": event,
				"X-Kavach-Signature": `sha256=${signature}`,
				"X-Kavach-Timestamp": timestamp,
			},
			body,
			signal: controller.signal,
		});
		return response.ok;
	} catch {
		return false;
	} finally {
		clearTimeout(timer);
	}
}

async function deliverWithRetry(
	endpoint: WebhookConfig,
	event: WebhookEvent,
	body: string,
	timestamp: string,
): Promise<void> {
	const maxRetries = endpoint.retries ?? 3;
	let attempt = 0;

	while (attempt <= maxRetries) {
		const success = await deliverOnce(endpoint, event, body, timestamp);
		if (success) return;

		attempt++;
		if (attempt <= maxRetries) {
			// Exponential backoff: 1s, 2s, 4s, …
			await new Promise<void>((resolve) => setTimeout(resolve, 1000 * 2 ** (attempt - 1)));
		}
	}
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createWebhookModule(configs: WebhookConfig[]): WebhookModule {
	const endpoints: WebhookConfig[] = [...configs];

	function emit(event: WebhookEvent, payload: Record<string, unknown>): void {
		const timestamp = Math.floor(Date.now() / 1000).toString();
		const body = JSON.stringify({ event, timestamp, data: payload });

		for (const endpoint of endpoints) {
			if (!endpoint.events.includes(event)) continue;
			// Fire and forget — intentionally not awaited
			void deliverWithRetry(endpoint, event, body, timestamp);
		}
	}

	function addEndpoint(config: WebhookConfig): void {
		endpoints.push(config);
	}

	function listEndpoints(): WebhookConfig[] {
		return [...endpoints];
	}

	return { emit, addEndpoint, listEndpoints };
}
