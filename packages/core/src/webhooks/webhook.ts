export type WebhookEvent =
	| "user.created"
	| "user.deleted"
	| "user.updated"
	| "agent.created"
	| "agent.revoked"
	| "agent.rotated"
	| "session.created"
	| "session.revoked"
	| "auth.login"
	| "auth.logout"
	| "auth.failed"
	| "delegation.created"
	| "delegation.revoked"
	| "org.created"
	| "org.member.added"
	| "org.member.removed";

export interface WebhookConfig {
	/** Signing secret for HMAC-SHA256 webhook signatures */
	secret: string;
	/** Max delivery attempts (default: 3) */
	maxRetries?: number;
	/** Timeout per delivery in ms (default: 10000) */
	timeoutMs?: number;
}

export interface WebhookSubscription {
	id: string;
	url: string;
	events: WebhookEvent[];
	active: boolean;
	createdAt: Date;
}

export interface WebhookModule {
	subscribe(url: string, events: WebhookEvent[]): Promise<WebhookSubscription>;
	unsubscribe(subscriptionId: string): Promise<void>;
	list(): Promise<WebhookSubscription[]>;
	/** Dispatch an event to all matching subscribers (fire-and-forget) */
	dispatch(event: WebhookEvent, payload: Record<string, unknown>): void;
	/** Test a webhook URL */
	test(subscriptionId: string): Promise<{ success: boolean; statusCode?: number; error?: string }>;
}

function generateId(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function signPayload(secret: string, body: string): Promise<string> {
	const encoder = new TextEncoder();
	const keyData = encoder.encode(secret);
	const messageData = encoder.encode(body);

	const key = await crypto.subtle.importKey(
		"raw",
		keyData,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);

	const signature = await crypto.subtle.sign("HMAC", key, messageData);
	const hex = Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, "0")).join(
		"",
	);
	return `sha256=${hex}`;
}

async function deliverWebhook(
	url: string,
	event: WebhookEvent,
	payload: Record<string, unknown>,
	deliveryId: string,
	timestamp: string,
	signature: string,
	timeoutMs: number,
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
	try {
		const response = await fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-theauth-event": event,
				"x-theauth-delivery": deliveryId,
				"x-theauth-timestamp": timestamp,
				"x-theauth-signature": signature,
			},
			body: JSON.stringify(payload),
			signal: AbortSignal.timeout(timeoutMs),
		});
		return { success: response.ok, statusCode: response.status };
	} catch (err) {
		return {
			success: false,
			error: err instanceof Error ? err.message : "Unknown error",
		};
	}
}

async function dispatchWithRetry(
	url: string,
	event: WebhookEvent,
	payload: Record<string, unknown>,
	config: Required<WebhookConfig>,
): Promise<void> {
	const deliveryId = generateId();
	const timestamp = new Date().toISOString();
	const body = JSON.stringify(payload);
	const signature = await signPayload(config.secret, body);

	const delays = [1000, 2000, 4000];

	for (let attempt = 0; attempt < config.maxRetries; attempt++) {
		if (attempt > 0) {
			await new Promise<void>((resolve) => setTimeout(resolve, delays[attempt - 1] ?? 4000));
		}

		const result = await deliverWebhook(
			url,
			event,
			payload,
			deliveryId,
			timestamp,
			signature,
			config.timeoutMs,
		);

		if (result.success) {
			return;
		}
	}
}

export function createWebhookModule(config: WebhookConfig): WebhookModule {
	const resolvedConfig: Required<WebhookConfig> = {
		secret: config.secret,
		maxRetries: config.maxRetries ?? 3,
		timeoutMs: config.timeoutMs ?? 10000,
	};

	const subscriptions = new Map<string, WebhookSubscription>();

	async function subscribe(url: string, events: WebhookEvent[]): Promise<WebhookSubscription> {
		const sub: WebhookSubscription = {
			id: generateId(),
			url,
			events,
			active: true,
			createdAt: new Date(),
		};
		subscriptions.set(sub.id, sub);
		return sub;
	}

	async function unsubscribe(subscriptionId: string): Promise<void> {
		subscriptions.delete(subscriptionId);
	}

	async function list(): Promise<WebhookSubscription[]> {
		return Array.from(subscriptions.values());
	}

	function dispatch(event: WebhookEvent, payload: Record<string, unknown>): void {
		const matching = Array.from(subscriptions.values()).filter(
			(sub) => sub.active && sub.events.includes(event),
		);

		for (const sub of matching) {
			// fire-and-forget
			void dispatchWithRetry(sub.url, event, payload, resolvedConfig);
		}
	}

	async function test(
		subscriptionId: string,
	): Promise<{ success: boolean; statusCode?: number; error?: string }> {
		const sub = subscriptions.get(subscriptionId);
		if (!sub) {
			return { success: false, error: "Subscription not found" };
		}

		const deliveryId = generateId();
		const timestamp = new Date().toISOString();
		const pingPayload = { event: "ping", subscriptionId, timestamp };
		const body = JSON.stringify(pingPayload);
		const signature = await signPayload(resolvedConfig.secret, body);

		return deliverWebhook(
			sub.url,
			"auth.login", // placeholder event type for test delivery
			pingPayload,
			deliveryId,
			timestamp,
			signature,
			resolvedConfig.timeoutMs,
		);
	}

	return { subscribe, unsubscribe, list, dispatch, test };
}

/**
 * Verify an incoming webhook signature.
 * Returns true if the signature matches the payload and secret.
 */
export async function verifyWebhookSignature(
	secret: string,
	rawBody: string,
	signature: string,
): Promise<boolean> {
	const expected = await signPayload(secret, rawBody);
	// Constant-time comparison
	if (expected.length !== signature.length) return false;
	const a = new TextEncoder().encode(expected);
	const b = new TextEncoder().encode(signature);
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	}
	return diff === 0;
}
