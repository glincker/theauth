import type { Database } from "../db/database.js";
import { createTokenFamilyStore } from "../session/token-family.js";
import { createDbDelegationStore } from "./delegation-check.js";
import { createDbClientStore } from "./stores-db-clients.js";
import type { McpTokenStoreOptions } from "./stores-db-tokens.js";
import { createDbTokenStore } from "./stores-db-tokens.js";
import type {
	McpAccessToken,
	McpAuthContext,
	McpAuthorizationCode,
	McpClient,
	McpDelegationStore,
	McpTokenFamilyStore,
} from "./types.js";

/**
 * Everything the MCP authorization server persists. Pass it (or any subset) to `createMcpModule`; the database implementation is {@link createMcpStores}.
 */
export interface McpStores {
	storeClient: (client: McpClient) => Promise<void>;
	findClient: (clientId: string) => Promise<McpClient | null>;
	/** Single use: of two concurrent callers exactly one receives the code. */
	storeAuthorizationCode: (code: McpAuthorizationCode) => Promise<void>;
	consumeAuthorizationCode: (code: string) => Promise<McpAuthorizationCode | null>;
	storeToken: (token: McpAccessToken) => Promise<void>;
	findTokenByRefreshToken: (refreshToken: string) => Promise<McpAccessToken | null>;
	revokeToken: (accessToken: string) => Promise<void>;
	updateClientSecret: NonNullable<McpAuthContext["updateClientSecret"]>;
	revokeTokenFamily: NonNullable<McpAuthContext["revokeTokenFamily"]>;
	/** Bind a client to an agent, or clear the binding with null. */
	setClientAgent: NonNullable<McpAuthContext["setClientAgent"]>;
	/** Refresh token families with reuse detection, shared by every instance on the database. */
	tokenFamilies: McpTokenFamilyStore;
	/** Live delegation links (`theauth.delegate()` records). Opt in with `config.delegationStore`. */
	delegationStore: McpDelegationStore;
}

export type McpStoresOptions = McpTokenStoreOptions;

/**
 * MCP stores backed by the TheAuth database, so several instances share clients, codes, tokens and refresh families, and a restart loses nothing. Needs the `theauth_oauth_*` tables (created when `mcp` is configured) and, for refresh token families, the session family tables (also created with `mcp`).
 *
 * @example
 * ```ts
 * const mcp = createMcpModule({ auth, config, resolveUserId }); // same as { ...createMcpStores(auth.db) }
 * ```
 */
export function createMcpStores(db: Database, options: McpStoresOptions = {}): McpStores {
	return {
		...createDbClientStore(db),
		...createDbTokenStore(db, options),
		tokenFamilies: createTokenFamilyStore(db),
		delegationStore: createDbDelegationStore(db),
	};
}
