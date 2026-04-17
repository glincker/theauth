/**
 * Webhook system types.
 *
 * Event types align with the KavachOS auth event surface:
 * user, session, agent, permission, and organization lifecycle events.
 */

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

export type WebhookEventType =
	| "user.signIn"
	| "user.signUp"
	| "user.signOut"
	| "user.deleted"
	| "user.banned"
	| "user.unbanned"
	| "user.updated"
	| "session.created"
	| "session.revoked"
	| "session.refreshed"
	| "agent.created"
	| "agent.revoked"
	| "agent.rotated"
	| "agent.updated"
	| "permission.granted"
	| "permission.revoked"
	| "organization.created"
	| "organization.memberAdded";

// ---------------------------------------------------------------------------
// Delivery status
// ---------------------------------------------------------------------------

export type DeliveryStatus = "pending" | "success" | "failed" | "exhausted";

// ---------------------------------------------------------------------------
// Delivery record (tracks each attempt)
// ---------------------------------------------------------------------------

export interface DeliveryAttempt {
	/** Monotonically increasing attempt number (1-based) */
	attempt: number;
	/** Unix timestamp (ms) when this attempt was made */
	attemptedAt: number;
	/** HTTP status code, undefined on network error */
	statusCode?: number;
	/** Error message on network/timeout failure */
	error?: string;
	/** Whether this attempt succeeded */
	success: boolean;
}

export interface DeliveryRecord {
	/** Unique delivery ID — stable across retries for the same event dispatch */
	deliveryId: string;
	/** Target endpoint URL */
	url: string;
	/** Event type dispatched */
	event: string;
	/** Current delivery status */
	status: DeliveryStatus;
	/** All attempts in chronological order */
	attempts: DeliveryAttempt[];
	/** Unix timestamp (ms) when delivery was first attempted */
	createdAt: number;
	/** Unix timestamp (ms) of last status update */
	updatedAt: number;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface WebhookEndpointConfig {
	/** Destination URL for the POST */
	url: string;
	/** Events this endpoint subscribes to */
	events: WebhookEventType[];
	/** HMAC-SHA256 signing secret */
	secret: string;
}

export interface RetryConfig {
	/** Max delivery attempts including the first (default: 3) */
	maxAttempts?: number;
	/** Backoff strategy (currently only "exponential" is supported) */
	backoff?: "exponential";
	/** Per-attempt timeout in ms (default: 10_000) */
	timeout?: number;
	/** Base backoff in ms (default: 1000). Tests can pass 0 to skip waits. */
	backoffBaseMs?: number;
}

export interface WebhooksPluginConfig {
	/** Endpoint definitions */
	endpoints: WebhookEndpointConfig[];
	/** Retry + backoff settings */
	retry?: RetryConfig;
	/** Signing algorithm (only "hmac-sha256" is supported) */
	signing?: "hmac-sha256";
}

// ---------------------------------------------------------------------------
// Delivery engine interface
// ---------------------------------------------------------------------------

export interface DeliveryEngine {
	/**
	 * Deliver a webhook payload to a single endpoint.
	 * Returns the final delivery record after all attempts have completed.
	 */
	deliver(
		endpoint: WebhookEndpointConfig,
		event: string,
		payload: Record<string, unknown>,
	): Promise<DeliveryRecord>;
}
