import { attachBindingStore } from "./binding.js";
import { attachFreshnessDeps, invalidateFreshnessCache } from "./freshness.js";
import type { McpBindingStore, McpRevocationBus, McpRevocationStore } from "./revocation-types.js";
import type { McpAuthContext, Result } from "./types.js";

/** What `createMcpModule` wires together for revocation: the same stores feed the freshness layer, the binding resolver and the denylist. */
export interface McpRevocationWiring {
	revocations?: McpRevocationStore;
	bindings?: McpBindingStore;
	/** The instance's revocation bus (`auth.revocations`). */
	bus?: Pick<McpRevocationBus, "subscribe"> & Partial<Pick<McpRevocationBus, "subscribeClear">>;
}

/**
 * Attach the revocation collaborators to a context. The freshness layer subscribes to the bus, so a
 * revocation made on this instance drops its cached verdicts immediately; other instances see it
 * through the shared table (live mode on the next call, cached mode within the poll interval).
 */
export function wireRevocation(ctx: McpAuthContext, wiring: McpRevocationWiring): void {
	const bus = wiring.bus;
	attachFreshnessDeps(ctx, {
		...(wiring.revocations ? { revocations: wiring.revocations } : {}),
		...(wiring.bindings ? { bindings: wiring.bindings } : {}),
		...(bus ? { subscribe: (listener) => (bus.subscribeClear ?? bus.subscribe)(listener) } : {}),
	});
	if (wiring.bindings) attachBindingStore(ctx, wiring.bindings);
}

/** After a successful RFC 7009 revoke on this instance, drop cached verdicts so the next call re-reads the denylist. */
export function afterRevoke<T>(ctx: McpAuthContext, result: Result<T>): Result<T> {
	if (result.success) invalidateFreshnessCache(ctx);
	return result;
}
