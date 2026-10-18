import type { Database } from "../db/database.js";
import { createTokenFamilyStore } from "../session/token-family.js";
import { createDbDelegationStore } from "./delegation-check.js";
import type { McpBindingStore, McpRevocationStore } from "./revocation-types.js";
import { createDbBindingStore } from "./stores-db-binding.js";
import { createDbBlockStore } from "./stores-db-blocks.js";
import type { McpClientStore } from "./stores-db-clients.js";
import { createDbClientStore } from "./stores-db-clients.js";
import { createDbRevocationStore } from "./stores-db-revocation.js";
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
import type { McpClientBlockStore } from "./types-cimd.js";

/**
 * Everything the MCP authorization server persists. Pass it (or any subset) to `createMcpModule`; the database implementation is {@link createMcpStores}.
 */
export interface McpStores {
	/** `preserveAdminState` makes a cache refresh keep an existing row's `disabled`, `disabledReason` and agent binding. */
	storeClient: McpClientStore["storeClient"];
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
	/** Admin disable or enable of a stored client. */
	setClientDisabled: McpClientStore["setClientDisabled"];
	/** Deletes the client's token rows and returns their jtis for a denylist. */
	revokeClientTokens: McpClientStore["revokeClientTokens"];
	/** Admin blocks by exact client_id URL or by host. */
	blocks: McpClientBlockStore;
	/** Refresh token families with reuse detection, shared by every instance on the database. */
	tokenFamilies: McpTokenFamilyStore;
	/** Live delegation links (`theauth.delegate()` records). Opt in with `config.delegationStore`. */
	delegationStore: McpDelegationStore;
	/** Shared revocation list (migration 0007). Becomes `config.jtiDenylist` by default, so a revoke on one instance is refused on all. */
	revocations: McpRevocationStore;
	/** Every stored CIMD client_id, so a host block can revoke that host's tokens. */
	listCimdClientIds: NonNullable<McpAuthContext["listCimdClientIds"]>;
	/** Count of CIMD clients never consented to; enables the `maxUnconsentedClients` cap. */
	countUnconsentedCimdClients?: McpAuthContext["countUnconsentedCimdClients"];
	/** Deletes unconsented CIMD clients not updated since the given date. */
	deleteStaleUnconsentedCimdClients?: McpAuthContext["deleteStaleUnconsentedCimdClients"];
	/** Delegation and agent rows behind the `theauth_dlg` token binding. */
	bindings: McpBindingStore;
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
		blocks: createDbBlockStore(db),
		...createDbTokenStore(db, options),
		tokenFamilies: createTokenFamilyStore(db),
		delegationStore: createDbDelegationStore(db),
		revocations: createDbRevocationStore(db),
		bindings: createDbBindingStore(db),
	};
}
