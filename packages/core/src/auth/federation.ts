/**
 * Agent identity federation: lets an agent from one TheAuth instance authenticate at another via signed tokens.
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
import { generateId } from "../crypto/web-crypto.js";
import type { Result, TheAuthError } from "../mcp/types.js";
import { trimTrailingSlashes } from "../trim-slashes.js";
import type {
	FederatedAgent,
	FederationConfig,
	FederationModule,
	FederationToken,
	FederationWellKnown,
	InstanceIdentity,
	IssueFederationTokenInput,
	TrustedInstance,
} from "./federation-types.js";
import { FederationConfigSchema, TrustedInstanceSchema } from "./federation-types.js";

export * from "./federation-types.js";

const DEFAULT_TOKEN_TTL_SECONDS = 300;
const WELL_KNOWN_PATH = "/.well-known/theauth-federation.json";
const FEDERATION_TOKEN_TYPE = "theauth-federation+jwt";

interface FederationJwtPayload {
	theauth_instance: string;
	theauth_instance_url: string;
	permissions: string[];
	trust_score: number;
	delegation_scope: string[];
	credential?: string;
}

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

/** Creates a federation module that signs short-lived JWTs carrying agent identity. */
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

	const trustedInstances = new Map<string, TrustedInstance>();
	if (config.trustedInstances) {
		for (const inst of config.trustedInstances) {
			trustedInstances.set(inst.instanceId, inst);
		}
	}

	let publicJwkCache: JsonWebKey | undefined;

	async function getPublicJwk(): Promise<JsonWebKey> {
		if (!publicJwkCache) {
			const exported = await jose.exportJWK(signingKey);
			const { d, ...publicComponents } = exported;
			publicJwkCache = { ...publicComponents, alg: "EdDSA", use: "sig" };
		}
		return publicJwkCache;
	}

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
				theauth_instance: instanceId,
				theauth_instance_url: instanceUrl,
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

			const trustLevel = trusted?.trustLevel ?? "full";
			if (trustLevel === "limited") {
				permissions = permissions.filter((p) => !p.includes("write") && !p.includes("admin"));
			}

			if (trustLevel === "verify-only") {
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
					sourceInstanceUrl: claims.theauth_instance_url ?? "",
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

	async function discoverInstance(
		url: string,
		fetchFn: typeof globalThis.fetch = globalThis.fetch,
	): Promise<Result<TrustedInstance>> {
		const wellKnownUrl = trimTrailingSlashes(url) + WELL_KNOWN_PATH;

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
