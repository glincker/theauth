import { createTheAuth } from "@glinr/theauth";

/** TheAuth instance type as returned by {@link initTheAuth}. */
export type GatewayTheAuth = Awaited<ReturnType<typeof createTheAuth>>;

/**
 * Create the TheAuth instance used by the gateway CLI.
 *
 * Agent features must be enabled explicitly: core only creates the agent,
 * audit, tenant, rate limit and budget tables when `agents` (or `did`) is
 * configured. Without it a fresh database has no agent tables and the first
 * agent call fails. `createTheAuth` runs `createTables` (including the legacy
 * table rename shim) at startup unless migrations are skipped.
 */
export async function initTheAuth(dbUrl: string): Promise<GatewayTheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: dbUrl },
		agents: { enabled: true },
	});
}
