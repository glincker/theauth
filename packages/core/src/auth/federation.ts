/**
 * Agent identity federation for TheAuth.
 *
 * Allows an agent created in one TheAuth instance (Service A) to
 * authenticate at another TheAuth instance (Service B) without
 * re-registration. The agent's identity, trust score, permissions,
 * and delegation scope travel with the federation token.
 *
 * Federation tokens are short-lived JWTs signed by the source instance.
 * The target instance verifies them by fetching the source's public key
 * from `/.well-known/kavach-federation.json`. Optionally, a Verifiable
 * Credential can be embedded for offline verification.
 *
 * @example
 * ```typescript
 * import { createFederationModule } from '@glinr/theauth/auth';
 * import { generateKeyPair, exportJWK } from 'jose';
 *
 * const { publicKey, privateKey } = await generateKeyPair('EdDSA');
 *
 * const federation = createFederationModule({
 *   instanceId: 'instance-a',
 *   instanceUrl: 'https://a.example.com',
 *   signingKey: privateKey,
 * });
 *
 * // Issue a token for an agent to carry to Service B
 * const result = await federation.issueFederationToken('agent-123');
 * ```
 */

import * as jose from "jose";
import { z } from "zod";
import { generateId } from "../crypto/web-crypto.js";
import type { KavachError, Result } from "../mcp/types.js";

// ─── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_TOKEN_TTL_SECONDS = 300;
const WELL_KNOWN_PATH = "/.well-known/kavach-federation.json";
const FEDERATION_TOKEN_TYPE = "kavach-federation+jwt";

// ─── Zod Schemas ────────────────────────────────────────────────────────────

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

// ─── Public Types ───────────────────────────────────────────────────────────

export type TrustLevel = z.infer<typeof TrustLevelSchema>;

export interface TrustedInstance {
	instanceId: string;
	instanceUrl: string;
	publicKey?: JsonWebKey;
	trustLevel?: TrustLevel;
}

export interface FederationConfig {
	/** Unique identifier for this TheAuth instance */
	instanceId: string;
	/** Public URL of this instance */
	instanceUrl: string;
	/** EdDSA private key for signing federation tokens */
	signingKey: CryptoKey;
	/** Pre-configured trusted instances */
	trustedInstances?: TrustedInstance[];
	/** Trust any TheAuth instance (dev mode only) */
	autoTrust?: boolean;
	/** Federation token lifetime in seconds. Default: 300 (5 minutes). */
	tokenTtlSeconds?: number;
}

export interface FederationToken {
	/** Signed JWT */
	token: string;
	/** Token expiration */
	expiresAt: Date;
	/** Agent this token was issued for */
	agentId: string;
	/** Source instance ID */
	sourceInstance: string;
}

export interface FederatedAgent {
	/** Agent ID from the source instance */
	agentId: string;
	/** Instance that issued this agent's identity */
	sourceInstance: string;
	/** Source instance URL */
	sourceInstanceUrl: string;
	/** Permissions carried by the token */
	permissions: string[];
	/** Trust level (0-1) from the source instance */
	trustScore: number;
	/** Delegation scope, if any */
	delegationScope: string[];
	/** When this token was verified */
	verifiedAt: Date;
	/** Embedded Verifiable Credential JWT, if present */
	credential?: string;
}

export interface InstanceIdentity {
	/** This instance's ID */
	instanceId: string;
	/** This instance's URL */
	instanceUrl: string;
	/** Public key in JWK format for verifying federation tokens */
	publicKeyJwk: JsonWebKey;
	/** Protocol version */
	protocolVersion: string;
	/** Supported features */
	features: string[];
}

export interface IssueFederationTokenInput {
	/** Agent ID to issue the token for */
	agentId: string;
	/** Optional target instance ID (audience restriction) */
	targetInstance?: string;
	/** Agent permissions to include in the token */
	permissions?: string[];
	/** Agent trust score (0-1) */
	trustScore?: number;
	/** Delegation scope */
	delegationScope?: string[];
	/** Optional VC JWT to embed */
	credential?: string;
}

/** The well-known document served at /.well-known/kavach-federation.json */
export interface FederationWellKnown {
	instanceId: string;
	instanceUrl: string;
	publicKeyJwk: JsonWebKey;
	protocolVersion: string;
	features: string[];
}

export interface FederationModule {
	/** Issue a federation token for an agent to use at another service */
	issueFederationToken(input: IssueFederationTokenInput): Promise<Result<FederationToken>>;
	/** Verify a federation token from another TheAuth instance */
	verifyFederationToken(token: string): Promise<Result<FederatedAgent>>;
	/** Get this instance's identity (for the well-known endpoint) */
	getInstanceIdentity(): Promise<InstanceIdentity>;
	/** Add a trusted instance */
	addTrustedInstance(instance: TrustedInstance): Result<void>;
	/** Remove a trusted instance by ID */
	removeTrustedInstance(instanceId: string): Result<void>;
	/** List all trusted instances */
	listTrustedInstances(): TrustedInstance[];
	/** Discover another instance via its well-known URL */
	discoverInstance(
		url: string,
		fetchFn?: typeof globalThis.fetch,
	): Promise<Result<TrustedInstance>>;
}

// ─── JWT Claims ─────────────────────────────────────────────────────────────

interface FederationJwtPayload {
	/** Source instance ID */
	kavach_instance: string;
	/** Source instance URL */
	kavach_instance_url: string;
	/** Agent permissions */
	permissions: string[];
	/** Agent trust score */
	trust_score: number;
	/** Delegation scope */
	delegation_scope: string[];
	/** Embedded VC JWT */
	credential?: string;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeError(code: string, message: string, details?: Record<string, unknown>): KavachError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

// ─── Factory ────────────────────────────────────────────────────────────────

/**
 * Create a federation module for cross-instance agent identity.
 *
 * The module signs short-lived JWTs that carry agent identity, permissions,
 * and trust score. Remote instances verify these tokens using the source's
 * public key, fetched from the well-known endpoint or pre-configured.
 */
export function createFederationModule(config: FederationConfig): FederationModule {
	const parsed = FederationConfigSchema.safeParse(config);
	if (!parsed.success) {
		throw new Error(
			`Invalid FederationConfig: ${parsed.error.errors.map((e) => e.message).join(", ")}`,
		);
	}

	const {
		instanceId,
		instanceUrl,
		signingKey,
		autoTrust = false,
		tokenTtlSeconds = DEFAULT_TOKEN_TTL_SECONDS,
	} = config;

	// Mutable trust store
	const trustedInstances = new Map<string, TrustedInstance>();
	if (config.trustedInstances) {
		for (const inst of config.trustedInstances) {
			trustedInstances.set(inst.instanceId, inst);
		}
	}

	// Cache the public JWK export
	let publicJwkCache: JsonWebKey | undefined;

	async function getPublicJwk(): Promise<JsonWebKey> {
		if (!publicJwkCache) {
			const exported = await jose.exportJWK(signingKey);
			// Strip private components
			const { d, ...publicComponents } = exported;
			publicJwkCache = { ...publicComponents, alg: "EdDSA", use: "sig" };
		}
		return publicJwkCache;
	}

	// ── issueFederationToken ──────────────────────────────────────────────

	async function issueFederationToken(
		input: IssueFederationTokenInput,
	): Promise<Result<FederationToken>> {
		const {
			agentId,
			targetInstance,
			permissions = [],
			trustScore = 0,
			delegationScope = [],
			credential,
		} = input;

		if (!agentId || agentId.trim() === "") {
			return {
				success: false,
				error: makeError("FEDERATION_INVALID_INPUT", "agentId is required"),
			};
		}

		if (trustScore < 0 || trustScore > 1) {
			return {
				success: false,
				error: makeError("FEDERATION_INVALID_INPUT", "trustScore must be between 0 and 1"),
			};
		}

		try {
			const now = Math.floor(Date.now() / 1000);
			const exp = now + tokenTtlSeconds;

			const payload: FederationJwtPayload = {
				kavach_instance: instanceId,
				kavach_instance_url: instanceUrl,
				permissions,
				trust_score: trustScore,
				delegation_scope: delegationScope,
				...(credential !== undefined ? { credential } : {}),
			};

			const builder = new jose.SignJWT(payload as unknown as Record<string, unknown>)
				.setProtectedHeader({
					alg: "EdDSA",
					typ: FEDERATION_TOKEN_TYPE,
				})
				.setIssuer(instanceId)
				.setSubject(agentId)
				.setIssuedAt(now)
				.setExpirationTime(exp)
				.setJti(generateId());

			if (targetInstance) {
				builder.setAudience(targetInstance);
			}

			const token = await builder.sign(signingKey);
			const expiresAt = new Date(exp * 1000);

			return {
				success: true,
				data: {
					token,
					expiresAt,
					agentId,
					sourceInstance: instanceId,
				},
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"FEDERATION_SIGN_FAILED",
					err instanceof Error ? err.message : "Failed to sign federation token",
				),
			};
		}
	}

	// ── verifyFederationToken ────────────────────────────────────────────

	async function verifyFederationToken(token: string): Promise<Result<FederatedAgent>> {
		if (!token || token.trim() === "") {
			return {
				success: false,
				error: makeError("FEDERATION_INVALID_TOKEN", "Token is required"),
			};
		}

		// Decode without verification first to extract the issuer (source instance)
		let sourceInstanceId: string;
		try {
			const decoded = jose.decodeJwt(token);
			if (typeof decoded.iss !== "string" || decoded.iss === "") {
				return {
					success: false,
					error: makeError("FEDERATION_NO_ISSUER", "Token does not contain an iss claim"),
				};
			}
			sourceInstanceId = decoded.iss;
		} catch {
			return {
				success: false,
				error: makeError("FEDERATION_INVALID_TOKEN", "Token is not a valid JWT"),
			};
		}

		// Check trust
		const trusted = trustedInstances.get(sourceInstanceId);
		if (!trusted && !autoTrust) {
			return {
				success: false,
				error: makeError(
					"FEDERATION_UNTRUSTED_INSTANCE",
					`Instance "${sourceInstanceId}" is not trusted`,
					{ sourceInstanceId },
				),
			};
		}

		// Get the public key
		const publicKeyJwk: JsonWebKey | undefined = trusted?.publicKey;

		// If no pre-configured key and we're in auto-trust, we need a key
		// from somewhere. In real usage, discoverInstance should be called
		// first. For auto-trust, we attempt to decode with any provided key.
		if (!publicKeyJwk) {
			return {
				success: false,
				error: makeError(
					"FEDERATION_NO_PUBLIC_KEY",
					`No public key available for instance "${sourceInstanceId}". Use discoverInstance() first or configure the key.`,
					{ sourceInstanceId },
				),
			};
		}

		try {
			const key = await jose.importJWK(publicKeyJwk, "EdDSA");
			const verifyOptions: jose.JWTVerifyOptions = {
				issuer: sourceInstanceId,
			};

			const { payload } = await jose.jwtVerify(token, key, verifyOptions);

			// Check audience if we're the target
			if (payload.aud) {
				const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
				if (!audiences.includes(instanceId)) {
					return {
						success: false,
						error: makeError(
							"FEDERATION_AUDIENCE_MISMATCH",
							"Token was not issued for this instance",
							{ expected: instanceId, got: payload.aud },
						),
					};
				}
			}

			const agentId = payload.sub;
			if (!agentId) {
				return {
					success: false,
					error: makeError("FEDERATION_NO_SUBJECT", "Token does not contain a sub claim"),
				};
			}

			const claims = payload as unknown as FederationJwtPayload;
			let permissions = claims.permissions ?? [];
			const trustScore = claims.trust_score ?? 0;
			const delegationScope = claims.delegation_scope ?? [];
			const credential = claims.credential;

			// Apply trust level downgrade for 'limited' trust
			const trustLevel = trusted?.trustLevel ?? "full";
			if (trustLevel === "limited") {
				// Downgrade: strip write permissions, cap trust score at 0.5
				permissions = permissions.filter((p) => !p.includes("write") && !p.includes("admin"));
			}

			if (trustLevel === "verify-only") {
				// Only verify identity, strip all permissions
				permissions = [];
			}

			const effectiveTrustScore =
				trustLevel === "limited"
					? Math.min(trustScore, 0.5)
					: trustLevel === "verify-only"
						? 0
						: trustScore;

			return {
				success: true,
				data: {
					agentId,
					sourceInstance: sourceInstanceId,
					sourceInstanceUrl: claims.kavach_instance_url ?? "",
					permissions,
					trustScore: effectiveTrustScore,
					delegationScope,
					verifiedAt: new Date(),
					...(credential !== undefined ? { credential } : {}),
				},
			};
		} catch (err) {
			if (err instanceof jose.errors.JWTExpired) {
				return {
					success: false,
					error: makeError("FEDERATION_TOKEN_EXPIRED", "Federation token has expired"),
				};
			}
			return {
				success: false,
				error: makeError(
					"FEDERATION_VERIFY_FAILED",
					err instanceof Error ? err.message : "Failed to verify federation token",
				),
			};
		}
	}

	// ── getInstanceIdentity ─────────────────────────────────────────────

	async function getInstanceIdentity(): Promise<InstanceIdentity> {
		const publicKeyJwk = await getPublicJwk();
		return {
			instanceId,
			instanceUrl,
			publicKeyJwk,
			protocolVersion: "1.0",
			features: ["federation-tokens", "vc-embedding", "auto-discovery"],
		};
	}

	// ── Trust management ────────────────────────────────────────────────

	function addTrustedInstance(instance: TrustedInstance): Result<void> {
		const validated = TrustedInstanceSchema.safeParse(instance);
		if (!validated.success) {
			return {
				success: false,
				error: makeError(
					"FEDERATION_INVALID_INSTANCE",
					validated.error.errors.map((e) => e.message).join(", "),
				),
			};
		}

		trustedInstances.set(instance.instanceId, instance);
		return { success: true, data: undefined };
	}

	function removeTrustedInstance(id: string): Result<void> {
		if (!trustedInstances.has(id)) {
			return {
				success: false,
				error: makeError(
					"FEDERATION_INSTANCE_NOT_FOUND",
					`Instance "${id}" not found in trusted list`,
				),
			};
		}
		trustedInstances.delete(id);
		return { success: true, data: undefined };
	}

	function listTrustedInstances(): TrustedInstance[] {
		return [...trustedInstances.values()];
	}

	// ── Discovery ───────────────────────────────────────────────────────

	async function discoverInstance(
		url: string,
		fetchFn: typeof globalThis.fetch = globalThis.fetch,
	): Promise<Result<TrustedInstance>> {
		const wellKnownUrl = url.replace(/\/+$/, "") + WELL_KNOWN_PATH;

		try {
			const response = await fetchFn(wellKnownUrl);
			if (!response.ok) {
				return {
					success: false,
					error: makeError(
						"FEDERATION_DISCOVERY_FAILED",
						`Failed to fetch well-known document: HTTP ${String(response.status)}`,
						{ url: wellKnownUrl, status: response.status },
					),
				};
			}

			const body = (await response.json()) as FederationWellKnown;

			if (!body.instanceId || !body.publicKeyJwk) {
				return {
					success: false,
					error: makeError(
						"FEDERATION_DISCOVERY_INVALID",
						"Well-known document is missing required fields (instanceId, publicKeyJwk)",
					),
				};
			}

			const discovered: TrustedInstance = {
				instanceId: body.instanceId,
				instanceUrl: body.instanceUrl ?? url,
				publicKey: body.publicKeyJwk,
				trustLevel: "verify-only", // Default to verify-only until explicitly upgraded
			};

			return { success: true, data: discovered };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"FEDERATION_DISCOVERY_FAILED",
					err instanceof Error ? err.message : "Failed to discover instance",
					{ url: wellKnownUrl },
				),
			};
		}
	}

	return {
		issueFederationToken,
		verifyFederationToken,
		getInstanceIdentity,
		addTrustedInstance,
		removeTrustedInstance,
		listTrustedInstances,
		discoverInstance,
	};
}
