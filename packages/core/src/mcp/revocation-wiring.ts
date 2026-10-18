import type { Database } from "../db/database.js";
import type { TheAuthLogger } from "../observability/types.js";
import type { SessionManager } from "../session/session.js";
import type { TheAuthConfig } from "../types.js";
import type { RevocationBus } from "./revocation-bus.js";
import { createRevocationBus, revocationRowExpiry } from "./revocation-bus.js";
import { createDbRevocationStore } from "./stores-db-revocation.js";

/**
 * Builds the one revocation bus for an instance. With `config.mcp` it writes to the shared
 * `McpRevocationStore` on `db`; without it the bus only notifies in-process listeners.
 */
export function createCoreRevocationBus(
	db: Database,
	config: TheAuthConfig,
	logger: TheAuthLogger,
): RevocationBus {
	return createRevocationBus({
		store: config.mcp ? createDbRevocationStore(db) : undefined,
		onRevoked: config.mcp?.revocation?.onRevoked,
		logger,
	});
}

/** `session.revokeAll(userId)` (sign out everywhere, ban) also revokes that user's MCP tokens, unless `revokeOnSignOutEverywhere` is false. Single session revokes are untouched: MCP tokens are not session bound. */
export function withMcpSignOutRevocation(
	sessions: SessionManager | null,
	bus: RevocationBus,
	config: TheAuthConfig,
): SessionManager | null {
	if (!sessions || !config.mcp || config.mcp.revocation?.revokeOnSignOutEverywhere === false) {
		return sessions;
	}
	return {
		...sessions,
		async revokeAll(userId) {
			await sessions.revokeAll(userId);
			const now = new Date();
			try {
				await bus.publish(
					{ kind: "sub", ids: [userId], revokedAt: now, reason: "session.revokeAll", userId },
					[
						{
							kind: "sub",
							id: userId,
							expiresAt: revocationRowExpiry(undefined, now),
							reason: "session.revokeAll",
						},
					],
				);
			} catch {
				// The bus reports its own failures; the sessions are already gone.
			}
		},
	};
}
