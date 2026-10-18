import type { McpCimdConfig, McpCimdEvent } from "./types-cimd.js";

/** Strips control characters and caps the length, so an attacker chosen client_id cannot forge log lines. */
export function safeEventId(value: string): string {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: the point is to remove them.
	return value.slice(0, 2048).replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");
}

/**
 * Deliver an event to the integrator's hook without ever affecting the caller: deferred to a microtask (never runs inline on the request path), synchronous throws and rejected promises from an async hook are swallowed.
 */
export function emitCimdHook(cfg: McpCimdConfig | undefined, event: McpCimdEvent): void {
	const hook = cfg?.onEvent;
	if (!hook) return;
	queueMicrotask(() => {
		try {
			const result: unknown = hook(event);
			if (result instanceof Promise) result.catch(() => undefined);
		} catch {
			// A throwing hook is the integrator's bug, not ours.
		}
	});
}
