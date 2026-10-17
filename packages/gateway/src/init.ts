import { createTheAuth } from "@glinr/theauth";
import { createMcpModule } from "@glinr/theauth/mcp";
import type { GatewayMcpConfig } from "./types.js";

export type GatewayTheAuth = Awaited<ReturnType<typeof createTheAuth>>;

/**
 * Creates the TheAuth instance for the gateway CLI. Agent tables exist only when `agents` (or `did`)
 * is configured. Without it, the first agent call fails on a fresh database.
 */
export async function initTheAuth(dbUrl: string): Promise<GatewayTheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: dbUrl },
		agents: { enabled: true },
	});
}

/**
 * Validation-only MCP module for the CLI. It verifies access tokens signed with
 * the shared HS256 secret and issues nothing: every storage callback is inert.
 * It cannot see revocations made at your authorization server, so tokens stay
 * valid until `exp`. Use embedded mode with a `jtiDenylist` if you need more.
 */
export function buildMcpValidator(opts: {
	issuer: string;
	signingSecret: string;
}): GatewayMcpConfig["auth"] {
	return createMcpModule({
		config: {
			enabled: true,
			issuer: opts.issuer,
			baseUrl: opts.issuer,
			signingSecret: opts.signingSecret,
		},
		storeClient: async () => undefined,
		findClient: async () => null,
		storeAuthorizationCode: async () => undefined,
		consumeAuthorizationCode: async () => null,
		storeToken: async () => undefined,
		findTokenByRefreshToken: async () => null,
		revokeToken: async () => undefined,
		resolveUserId: async () => null,
	});
}
