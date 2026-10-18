import { z } from "zod";
import type { Result } from "../mcp/types.js";

export const TrustLevelSchema = z.enum(["full", "limited", "verify-only"]);

export const TrustedInstanceSchema = z.object({
	instanceId: z.string().min(1),
	instanceUrl: z.string().url(),
	publicKey: z.custom<JsonWebKey>().optional(),
	trustLevel: TrustLevelSchema.optional(),
});

export const FederationConfigSchema = z.object({
	instanceId: z.string().min(1),
	instanceUrl: z.string().min(1),
	signingKey: z.custom<CryptoKey>(
		(val) => val instanceof CryptoKey,
		"signingKey must be a CryptoKey",
	),
	trustedInstances: z.array(TrustedInstanceSchema).optional(),
	autoTrust: z.boolean().optional(),
	tokenTtlSeconds: z.number().int().positive().optional(),
});

export type TrustLevel = z.infer<typeof TrustLevelSchema>;

export interface TrustedInstance {
	instanceId: string;
	instanceUrl: string;
	publicKey?: JsonWebKey;
	trustLevel?: TrustLevel;
}

export interface FederationConfig {
	instanceId: string;
	instanceUrl: string;
	/** EdDSA private key for signing federation tokens */
	signingKey: CryptoKey;
	trustedInstances?: TrustedInstance[];
	/** Trust any TheAuth instance (dev mode only) */
	autoTrust?: boolean;
	/** Federation token lifetime in seconds. Default: 300 (5 minutes). */
	tokenTtlSeconds?: number;
}

export interface FederationToken {
	token: string;
	expiresAt: Date;
	agentId: string;
	sourceInstance: string;
}

export interface FederatedAgent {
	agentId: string;
	sourceInstance: string;
	sourceInstanceUrl: string;
	permissions: string[];
	/** Trust level (0-1) from the source instance */
	trustScore: number;
	delegationScope: string[];
	verifiedAt: Date;
	credential?: string;
}

export interface InstanceIdentity {
	instanceId: string;
	instanceUrl: string;
	/** Public key in JWK format for verifying federation tokens */
	publicKeyJwk: JsonWebKey;
	protocolVersion: string;
	features: string[];
}

export interface IssueFederationTokenInput {
	agentId: string;
	/** Optional target instance ID (audience restriction) */
	targetInstance?: string;
	permissions?: string[];
	/** Agent trust score (0-1) */
	trustScore?: number;
	delegationScope?: string[];
	credential?: string;
}

/** The well-known document served at /.well-known/theauth-federation.json */
export interface FederationWellKnown {
	instanceId: string;
	instanceUrl: string;
	publicKeyJwk: JsonWebKey;
	protocolVersion: string;
	features: string[];
}

export interface FederationModule {
	issueFederationToken(input: IssueFederationTokenInput): Promise<Result<FederationToken>>;
	verifyFederationToken(token: string): Promise<Result<FederatedAgent>>;
	/** Get this instance's identity (for the well-known endpoint) */
	getInstanceIdentity(): Promise<InstanceIdentity>;
	addTrustedInstance(instance: TrustedInstance): Result<void>;
	removeTrustedInstance(instanceId: string): Result<void>;
	listTrustedInstances(): TrustedInstance[];
	discoverInstance(
		url: string,
		fetchFn?: typeof globalThis.fetch,
	): Promise<Result<TrustedInstance>>;
}
