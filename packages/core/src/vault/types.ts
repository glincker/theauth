import type { OAuthProvider } from "../auth/oauth/types.js";
import type { Database } from "../db/database.js";
import type { SecondaryStorage } from "../storage/types.js";

/** Symmetric keys, base64url encoded, 32 bytes each. Keep old keys until rotateKeys() ran. */
export interface VaultKeyConfig {
	keys: Record<string, string>;
	activeKeyId: string;
}

export interface VaultProviderConfig {
	/** Existing OAuth provider, reused for authorize URL, code exchange and profile lookup. */
	provider: OAuthProvider;
	clientId: string;
	clientSecret: string;
}

export interface TokenVaultConfig {
	db: Database;
	keys: VaultKeyConfig;
	providers: Record<string, VaultProviderConfig>;
	/** Used for the refresh lock. Must be shared across instances in multi-node setups. */
	storage: SecondaryStorage;
	/** Injectable for tests. */
	fetch?: typeof fetch;
	now?: () => number;
	/** Refresh when the token expires within this many seconds. Default 60. */
	expirySkewSeconds?: number;
	/** Lock TTL in seconds. Default 15. */
	lockTtlSeconds?: number;
	/** How long a waiter polls for another refresh to finish, ms. Default 5000. */
	lockWaitMs?: number;
}

export interface VaultError {
	code: string;
	message: string;
	details?: Record<string, unknown>;
}

export type VaultResult<T> = { success: true; data: T } | { success: false; error: VaultError };

export interface GetAccessTokenInput {
	agentId: string;
	userId: string;
	provider: string;
	scopes: string[];
}

export interface VaultAccessToken {
	accessToken: string;
	tokenType: string;
	/** Unix ms, or null when the provider did not report an expiry. */
	expiresAt: number | null;
	/** The scopes the caller asked for (always a subset of consent and connection). */
	scopes: string[];
}

export interface StoreConnectionInput {
	userId: string;
	tenantId?: string | null;
	provider: string;
	providerAccountId: string;
	accessToken: string;
	refreshToken?: string;
	expiresInSeconds?: number;
	scopes: string[];
}

export interface VaultConnectionInfo {
	id: string;
	userId: string;
	tenantId: string | null;
	provider: string;
	providerAccountId: string;
	scopes: string[];
	status: "active" | "needs_reauth" | "revoked";
	expiresAt: Date | null;
}

export interface GrantConsentInput {
	userId: string;
	agentId: string;
	tenantId?: string | null;
	provider: string;
	scopes: string[];
	delegationChainId?: string;
	expiresAt?: Date;
}

export interface TokenVault {
	storeConnection(input: StoreConnectionInput): Promise<VaultConnectionInfo>;
	listConnections(userId: string, tenantId?: string | null): Promise<VaultConnectionInfo[]>;
	disconnect(userId: string, provider: string, tenantId?: string | null): Promise<void>;
	grantConsent(input: GrantConsentInput): Promise<{ id: string }>;
	revokeConsent(consentId: string, userId: string): Promise<void>;
	revokeForAgent(agentId: string): Promise<number>;
	/** Call after revoking a delegation chain. Reads also re-check the chain, so this is belt and braces. */
	revokeForDelegation(chainId: string): Promise<number>;
	getAccessToken(input: GetAccessTokenInput): Promise<VaultResult<VaultAccessToken>>;
	/** Re-encrypt every row with the active key. Returns rows rewritten. */
	rotateKeys(): Promise<{ rotated: number }>;
}
