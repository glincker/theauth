/**
 * Webhook plugin for TheAuth.
 *
 * Integrates the delivery engine and signing into a plugin that hooks into
 * auth events and dispatches signed HTTP POST requests.
 *
 * @example
 * ```typescript
 * import { createKavach } from '@glinr/theauth';
 * import { webhooks } from '@glinr/theauth/webhook';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   plugins: [
 *     webhooks({
 *       endpoints: [
 *         {
 *           url: 'https://myapp.com/hooks/auth',
 *           events: ['user.signIn', 'user.signUp', 'agent.created'],
 *           secret: process.env.WEBHOOK_SECRET,
 *         },
 *       ],
 *       retry: { maxAttempts: 3, backoff: 'exponential', timeout: 10_000 },
 *     }),
 *   ],
 * });
 * ```
 */

import { createDeliveryEngine } from "./delivery.js";
import type { DeliveryRecord, WebhookEndpointConfig, WebhooksPluginConfig } from "./types.js";

export { buildWebhookHeaders, currentTimestamp, generateDeliveryId, verify } from "./signing.js";
export type {
	DeliveryAttempt,
	DeliveryEngine,
	DeliveryRecord,
	DeliveryStatus,
	RetryConfig,
	WebhookEndpointConfig,
	WebhookEventType,
	WebhooksPluginConfig,
} from "./types.js";
// Re-export modules
export { createDeliveryEngine };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export interface WebhooksPlugin {
	/**
	 * Dispatch an event to all matching endpoints.
	 * Fire-and-forget — returns immediately; delivery happens in background.
	 */
	dispatch(event: string, payload: Record<string, unknown>): void;
	/**
	 * Dispatch and await all deliveries.
	 * Returns delivery records for all matching endpoints.
	 */
	dispatchAwait(event: string, payload: Record<string, unknown>): Promise<DeliveryRecord[]>;
}

/**
 * Create a webhooks plugin instance from a config object.
 *
 * Designed to be consumed by `createKavach({ plugins: [webhooks(config)] })`.
 */
export function webhooks(config: WebhooksPluginConfig): WebhooksPlugin {
	const engine = createDeliveryEngine(config.retry ?? {});
	const endpoints: WebhookEndpointConfig[] = [...config.endpoints];

	function matchingEndpoints(event: string): WebhookEndpointConfig[] {
		// Cast to string[] for the .includes() check — the endpoint filter is
		// intentionally permissive to support both typed and custom event strings.
		return endpoints.filter((ep) => (ep.events as string[]).includes(event));
	}

	function dispatch(event: string, payload: Record<string, unknown>): void {
		const targets = matchingEndpoints(event);
		for (const ep of targets) {
			void engine.deliver(ep, event, payload);
		}
	}

	async function dispatchAwait(
		event: string,
		payload: Record<string, unknown>,
	): Promise<DeliveryRecord[]> {
		const targets = matchingEndpoints(event);
		return Promise.all(targets.map((ep) => engine.deliver(ep, event, payload)));
	}

	return { dispatch, dispatchAwait };
}
