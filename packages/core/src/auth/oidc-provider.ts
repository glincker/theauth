/**
 * OpenID Connect provider: turns TheAuth into an identity provider for external applications.
 *
 * @example
 * ```typescript
 * import { generateKeyPair } from 'jose';
 * import { createOidcProviderModule } from '@glinr/theauth/auth';
 *
 * const { privateKey } = await generateKeyPair('RS256');
 * const oidc = createOidcProviderModule(
 *   {
 *     issuer: 'https://auth.example.com',
 *     signingKey: privateKey,
 *   },
 *   db,
 *   getUserClaims,
 * );
 *
 * // Register a client
 * const client = await oidc.registerClient({
 *   clientName: 'My App',
 *   redirectUris: ['https://app.example.com/callback'],
 * });
 *
 * // Discovery
 * const doc = oidc.getDiscoveryDocument();
 * ```
 */

import { eq } from "drizzle-orm";
import * as jose from "jose";
import { z } from "zod";
import { generateId, randomBytesHex, sha256, sha256Raw } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { oidcAuthCodes, oidcClients, oidcRefreshTokens } from "../db/schema.js";
import type { AuthError, Result, TheAuthError } from "../mcp/types.js";
import type { OidcLogoutConfig, OidcLogoutModule, OidcSidIndex } from "./oidc-logout.js";
import { createOidcLogoutModule, createOidcSidIndex } from "./oidc-logout.js";

export type { AuthError, Result, TheAuthError };

export interface OidcProviderConfig {
	/** Issuer identifier, e.g. "https://auth.example.com". Must be a URL. */
	issuer: string;
	/** Private key used to sign ID tokens and access tokens (RSA or EC). */
	signingKey: CryptoKey | jose.JWK;
	/** JWT signing algorithm. Default: 'RS256'. */
	signingAlgorithm?: string;
	/** Access token lifetime in seconds. Default: 3600 (1 hour). */
	accessTokenTtl?: number;
	/** Refresh token lifetime in seconds. Default: 2592000 (30 days). */
	refreshTokenTtl?: number;
	/** Authorization code lifetime in seconds. Default: 600 (10 minutes). */
	authCodeTtl?: number;
	/** ID token lifetime in seconds. Default: 3600 (1 hour). */
	idTokenTtl?: number;
	/** Scopes this provider supports. Default: ['openid', 'profile', 'email']. */
	supportedScopes?: string[];
	/** Opt in to RP-initiated logout and back-channel logout fan-out. Adds the logout fields to discovery. */
	logout?: OidcLogoutConfig;
}

export interface RegisterClientInput {
	clientName: string;
	redirectUris: string[];
	grantTypes?: string[];
	responseTypes?: string[];
	scopes?: string[];
	tokenEndpointAuthMethod?: string;
	/** Allowlist for `post_logout_redirect_uri` (needs `config.logout`). */
	postLogoutRedirectUris?: string[];
	/** Client endpoint that receives back-channel logout tokens (needs `config.logout`). */
	backchannelLogoutUri?: string;
}

export interface OidcClient {
	clientId: string;
	clientSecret: string | null;
	clientName: string;
	redirectUris: string[];
	grantTypes: string[];
	responseTypes: string[];
	scopes: string[];
	tokenEndpointAuthMethod: string;
	createdAt: Date;
}

export interface AuthorizeParams {
	clientId: string;
	redirectUri: string;
	responseType: string;
	scope: string;
	state?: string;
	nonce?: string;
	codeChallenge?: string;
	codeChallengeMethod?: string;
	/** The authenticated user's ID. Must be resolved before calling authorize. */
	userId: string;
	/** Provider session id of the signed-in user. With `config.logout` it is indexed so session revoke and logout can notify this client. */
	sessionId?: string;
}

export interface TokenParams {
	grantType: string;
	code?: string;
	redirectUri?: string;
	codeVerifier?: string;
	refreshToken?: string;
	clientId: string;
	clientSecret?: string;
}

export interface TokenResponse {
	accessToken: string;
	idToken: string;
	refreshToken: string;
	tokenType: "Bearer";
	expiresIn: number;
}

export interface UserInfoClaims {
	sub: string;
	email?: string;
	name?: string;
	picture?: string;
	emailVerified?: boolean;
}

export interface AccessTokenClaims {
	sub: string;
	iss: string;
	aud: string;
	exp: number;
	iat: number;
	jti: string;
	scope: string;
	clientId: string;
}

export interface OidcDiscoveryDocument {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint: string;
	jwks_uri: string;
	registration_endpoint: string;
	scopes_supported: string[];
	response_types_supported: string[];
	grant_types_supported: string[];
	subject_types_supported: string[];
	id_token_signing_alg_values_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	claims_supported: string[];
	code_challenge_methods_supported: string[];
	end_session_endpoint?: string;
	backchannel_logout_supported?: boolean;
	backchannel_logout_session_supported?: boolean;
}

export interface JsonWebKeySet {
	keys: jose.JWK[];
}

/** Callback to resolve user claims for ID tokens and the userinfo endpoint. */
export type GetUserClaimsFn = (userId: string, scopes: string[]) => Promise<UserInfoClaims>;

export interface OidcProviderModule {
	registerClient(input: RegisterClientInput): Promise<Result<OidcClient>>;
	getClient(clientId: string): Promise<Result<OidcClient>>;
	deleteClient(clientId: string): Promise<Result<void>>;
	authorize(params: AuthorizeParams): Promise<Result<{ code: string; state?: string }>>;
	exchangeToken(params: TokenParams): Promise<Result<TokenResponse>>;
	getUserInfo(accessToken: string): Promise<Result<UserInfoClaims>>;
	getDiscoveryDocument(): OidcDiscoveryDocument;
	getJwks(): Promise<JsonWebKeySet>;
	validateAccessToken(token: string): Promise<Result<AccessTokenClaims>>;
	/** Present when `config.logout` was provided. */
	logout?: OidcLogoutModule;
}

const registerClientSchema = z.object({
	clientName: z.string().min(1, "clientName must not be empty"),
	redirectUris: z.array(z.string().url()).min(1, "at least one redirectUri is required"),
	grantTypes: z
		.array(z.enum(["authorization_code", "refresh_token"]))
		.default(["authorization_code", "refresh_token"])
		.optional(),
	responseTypes: z
		.array(z.enum(["code"]))
		.default(["code"])
		.optional(),
	scopes: z.array(z.string()).optional(),
	tokenEndpointAuthMethod: z
		.enum(["client_secret_post", "client_secret_basic"])
		.default("client_secret_post")
		.optional(),
	postLogoutRedirectUris: z.array(z.string().url()).optional(),
	backchannelLogoutUri: z.string().url().optional(),
});

const authorizeSchema = z.object({
	clientId: z.string().min(1),
	redirectUri: z.string().min(1),
	responseType: z.literal("code"),
	scope: z.string().min(1),
	state: z.string().optional(),
	nonce: z.string().optional(),
	codeChallenge: z.string().optional(),
	codeChallengeMethod: z.enum(["S256"]).optional(),
	userId: z.string().min(1),
	sessionId: z.string().min(1).optional(),
});

const tokenSchema = z.discriminatedUnion("grantType", [
	z.object({
		grantType: z.literal("authorization_code"),
		code: z.string().min(1),
		redirectUri: z.string().min(1),
		codeVerifier: z.string().optional(),
		clientId: z.string().min(1),
		clientSecret: z.string().optional(),
	}),
	z.object({
		grantType: z.literal("refresh_token"),
		refreshToken: z.string().min(1),
		clientId: z.string().min(1),
		clientSecret: z.string().optional(),
	}),
]);

const DEFAULT_ACCESS_TOKEN_TTL = 3600;
const DEFAULT_REFRESH_TOKEN_TTL = 86400 * 30;
const DEFAULT_AUTH_CODE_TTL = 600;
const DEFAULT_ID_TOKEN_TTL = 3600;
const DEFAULT_SIGNING_ALG = "RS256";
const DEFAULT_SCOPES = ["openid", "profile", "email"];
const CLIENT_ID_BYTE_LENGTH = 16;
const CLIENT_SECRET_BYTE_LENGTH = 32;
const AUTH_CODE_BYTE_LENGTH = 32;
const REFRESH_TOKEN_BYTE_LENGTH = 32;

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function generateRandomHex(bytes: number): string {
	return randomBytesHex(bytes);
}

async function hashSecret(raw: string): Promise<string> {
	return sha256(raw);
}

async function computeS256Challenge(codeVerifier: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(codeVerifier);
	const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
	return jose.base64url.encode(new Uint8Array(digest));
}

/** Creates an OIDC provider module that turns TheAuth into an identity provider. */
export function createOidcProviderModule(
	config: OidcProviderConfig,
	db: Database,
	getUserClaims: GetUserClaimsFn,
): OidcProviderModule {
	const issuer = config.issuer;
	const signingAlg = config.signingAlgorithm ?? DEFAULT_SIGNING_ALG;
	const accessTokenTtl = config.accessTokenTtl ?? DEFAULT_ACCESS_TOKEN_TTL;
	const refreshTokenTtl = config.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL;
	const authCodeTtl = config.authCodeTtl ?? DEFAULT_AUTH_CODE_TTL;
	const idTokenTtl = config.idTokenTtl ?? DEFAULT_ID_TOKEN_TTL;
	const supportedScopes = config.supportedScopes ?? DEFAULT_SCOPES;

	let signingKeyPromise: Promise<CryptoKey> | undefined;
	let publicJwkPromise: Promise<jose.JWK> | undefined;

	async function getSigningKey(): Promise<CryptoKey> {
		if (!signingKeyPromise) {
			signingKeyPromise = (async () => {
				if (config.signingKey instanceof CryptoKey) {
					return config.signingKey;
				}
				const imported = await jose.importJWK(config.signingKey as jose.JWK, signingAlg);
				return imported as CryptoKey;
			})();
		}
		return signingKeyPromise;
	}

	async function getPublicJwk(): Promise<jose.JWK> {
		if (!publicJwkPromise) {
			publicJwkPromise = (async () => {
				let jwk: jose.JWK;
				if (config.signingKey instanceof CryptoKey) {
					jwk = await jose.exportJWK(config.signingKey);
				} else {
					jwk = { ...(config.signingKey as jose.JWK) };
				}
				const { d, p, q, dp, dq, qi, k, ...publicComponents } = jwk;
				return { ...publicComponents, alg: signingAlg, use: "sig", kid: "theauth-oidc-1" };
			})();
		}
		return publicJwkPromise;
	}

	const logout: OidcLogoutModule | undefined = config.logout
		? createOidcLogoutModule({
				db,
				issuer,
				signingAlg,
				kid: "theauth-oidc-1",
				getSigningKey,
				getPublicJwk,
				importPublicKey: async (jwk) => {
					const key = await jose.importJWK(jwk, signingAlg);
					return key;
				},
				config: config.logout,
			})
		: undefined;
	const sidIndex: OidcSidIndex | undefined = config.logout
		? createOidcSidIndex(db, issuer, config.logout.indexTtlSeconds)
		: undefined;

	async function registerClient(input: RegisterClientInput): Promise<Result<OidcClient>> {
		const parsed = registerClientSchema.safeParse(input);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("INVALID_INPUT", parsed.error.errors[0]?.message ?? "Invalid input", {
					issues: parsed.error.errors,
				}),
			};
		}

		const {
			clientName,
			redirectUris,
			grantTypes = ["authorization_code", "refresh_token"],
			responseTypes = ["code"],
			scopes = supportedScopes,
			tokenEndpointAuthMethod = "client_secret_post",
			postLogoutRedirectUris,
			backchannelLogoutUri,
		} = parsed.data;

		if ((postLogoutRedirectUris || backchannelLogoutUri) && !logout) {
			return {
				success: false,
				error: makeError(
					"LOGOUT_NOT_ENABLED",
					"postLogoutRedirectUris and backchannelLogoutUri need config.logout",
				),
			};
		}

		const clientId = generateRandomHex(CLIENT_ID_BYTE_LENGTH);
		const rawSecret = generateRandomHex(CLIENT_SECRET_BYTE_LENGTH);
		const secretHash = await hashSecret(rawSecret);
		const now = new Date();

		try {
			await db.insert(oidcClients).values({
				id: generateId(),
				clientId,
				clientSecretHash: secretHash,
				clientName,
				redirectUris,
				grantTypes,
				responseTypes,
				scopes,
				tokenEndpointAuthMethod,
				createdAt: now,
				updatedAt: now,
			});

			if (logout && (postLogoutRedirectUris || backchannelLogoutUri)) {
				try {
					await logout.setClientLogoutConfig(clientId, {
						postLogoutRedirectUris: postLogoutRedirectUris ?? [],
						backchannelLogoutUri: backchannelLogoutUri ?? null,
					});
				} catch (err) {
					await db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
					return {
						success: false,
						error: makeError(
							"INVALID_INPUT",
							err instanceof Error ? err.message : "Invalid logout configuration",
						),
					};
				}
			}

			return {
				success: true,
				data: {
					clientId,
					clientSecret: rawSecret,
					clientName,
					redirectUris,
					grantTypes,
					responseTypes,
					scopes,
					tokenEndpointAuthMethod,
					createdAt: now,
				},
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CLIENT_REGISTRATION_FAILED",
					err instanceof Error ? err.message : "Failed to register client",
				),
			};
		}
	}

	async function getClient(clientId: string): Promise<Result<OidcClient>> {
		if (!clientId || clientId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "clientId must not be empty") };
		}

		const rows = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId));

		const row = rows[0];
		if (!row) {
			return { success: false, error: makeError("CLIENT_NOT_FOUND", "Client not found") };
		}

		return {
			success: true,
			data: {
				clientId: row.clientId,
				clientSecret: null, // Never return the hashed secret
				clientName: row.clientName,
				redirectUris: row.redirectUris,
				grantTypes: row.grantTypes,
				responseTypes: row.responseTypes,
				scopes: row.scopes,
				tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
				createdAt: row.createdAt,
			},
		};
	}

	async function deleteClient(clientId: string): Promise<Result<void>> {
		if (!clientId || clientId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "clientId must not be empty") };
		}

		const rows = await db
			.select({ id: oidcClients.id })
			.from(oidcClients)
			.where(eq(oidcClients.clientId, clientId));

		if (rows.length === 0) {
			return { success: false, error: makeError("CLIENT_NOT_FOUND", "Client not found") };
		}

		try {
			await db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
			if (logout) await logout.deleteClientLogoutConfig(clientId);
			return { success: true, data: undefined };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CLIENT_DELETE_FAILED",
					err instanceof Error ? err.message : "Failed to delete client",
				),
			};
		}
	}

	async function authorize(
		params: AuthorizeParams,
	): Promise<Result<{ code: string; state?: string }>> {
		const parsed = authorizeSchema.safeParse(params);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("INVALID_INPUT", parsed.error.errors[0]?.message ?? "Invalid input", {
					issues: parsed.error.errors,
				}),
			};
		}

		const {
			clientId,
			redirectUri,
			scope,
			state,
			nonce,
			codeChallenge,
			codeChallengeMethod,
			userId,
			sessionId,
		} = parsed.data;

		const clientRows = await db
			.select()
			.from(oidcClients)
			.where(eq(oidcClients.clientId, clientId));

		const client = clientRows[0];
		if (!client) {
			return { success: false, error: makeError("CLIENT_NOT_FOUND", "Client not found") };
		}

		if (!client.redirectUris.includes(redirectUri)) {
			return {
				success: false,
				error: makeError("INVALID_REDIRECT_URI", "redirect_uri is not registered for this client"),
			};
		}

		const requestedScopes = scope.split(" ").filter(Boolean);
		for (const s of requestedScopes) {
			if (!supportedScopes.includes(s)) {
				return {
					success: false,
					error: makeError("INVALID_SCOPE", `Scope "${s}" is not supported`, {
						supported: supportedScopes,
					}),
				};
			}
		}

		const code = generateRandomHex(AUTH_CODE_BYTE_LENGTH);
		const codeHash = await hashSecret(code);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + authCodeTtl * 1000);

		try {
			await db.insert(oidcAuthCodes).values({
				id: generateId(),
				codeHash,
				clientId,
				userId,
				redirectUri,
				scopes: scope,
				nonce: nonce ?? null,
				codeChallenge: codeChallenge ?? null,
				codeChallengeMethod: codeChallengeMethod ?? null,
				used: false,
				expiresAt,
				createdAt: now,
			});

			if (sidIndex) {
				await sidIndex.record({ userId, clientId, codeHash, ...(sessionId && { sessionId }) });
			}

			return {
				success: true,
				data: { code, ...(state !== undefined ? { state } : {}) },
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"AUTHORIZE_FAILED",
					err instanceof Error ? err.message : "Failed to create authorization code",
				),
			};
		}
	}

	async function exchangeToken(params: TokenParams): Promise<Result<TokenResponse>> {
		const parsed = tokenSchema.safeParse(params);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("INVALID_INPUT", parsed.error.errors[0]?.message ?? "Invalid input", {
					issues: parsed.error.errors,
				}),
			};
		}

		const data = parsed.data;

		if (data.grantType === "authorization_code") {
			return handleAuthCodeGrant(data);
		}

		return handleRefreshGrant(data);
	}

	async function handleAuthCodeGrant(data: {
		grantType: "authorization_code";
		code: string;
		redirectUri: string;
		codeVerifier?: string;
		clientId: string;
		clientSecret?: string;
	}): Promise<Result<TokenResponse>> {
		const { code, redirectUri, codeVerifier, clientId, clientSecret } = data;
		const codeHash = await hashSecret(code);

		const codeRows = await db
			.select()
			.from(oidcAuthCodes)
			.where(eq(oidcAuthCodes.codeHash, codeHash));

		const authCode = codeRows[0];
		if (!authCode) {
			return { success: false, error: makeError("INVALID_CODE", "Authorization code not found") };
		}

		if (authCode.used) {
			return {
				success: false,
				error: makeError("CODE_ALREADY_USED", "Authorization code has already been used"),
			};
		}

		if (authCode.expiresAt <= new Date()) {
			return {
				success: false,
				error: makeError("CODE_EXPIRED", "Authorization code has expired"),
			};
		}

		// Mark as used immediately to prevent replay
		await db.update(oidcAuthCodes).set({ used: true }).where(eq(oidcAuthCodes.id, authCode.id));

		if (authCode.clientId !== clientId) {
			return {
				success: false,
				error: makeError("CLIENT_MISMATCH", "client_id does not match the code"),
			};
		}

		const clientResult = await authenticateClient(clientId, clientSecret);
		if (!clientResult.success) {
			return clientResult;
		}

		if (authCode.redirectUri !== redirectUri) {
			return {
				success: false,
				error: makeError("REDIRECT_URI_MISMATCH", "redirect_uri does not match"),
			};
		}

		if (authCode.codeChallenge) {
			if (!codeVerifier) {
				return {
					success: false,
					error: makeError("PKCE_REQUIRED", "code_verifier is required"),
				};
			}
			const computedChallenge = await computeS256Challenge(codeVerifier);
			if (computedChallenge !== authCode.codeChallenge) {
				return {
					success: false,
					error: makeError("PKCE_MISMATCH", "code_verifier does not match code_challenge"),
				};
			}
		}

		const scopes = authCode.scopes.split(" ").filter(Boolean);
		const sid = sidIndex ? await sidIndex.forCode(codeHash) : null;
		return generateTokenSet(authCode.userId, clientId, scopes, authCode.nonce, sid);
	}

	async function handleRefreshGrant(data: {
		grantType: "refresh_token";
		refreshToken: string;
		clientId: string;
		clientSecret?: string;
	}): Promise<Result<TokenResponse>> {
		const { refreshToken, clientId, clientSecret } = data;
		const tokenHash = await hashSecret(refreshToken);

		const clientResult = await authenticateClient(clientId, clientSecret);
		if (!clientResult.success) {
			return clientResult;
		}

		const rows = await db
			.select()
			.from(oidcRefreshTokens)
			.where(eq(oidcRefreshTokens.tokenHash, tokenHash));

		const record = rows[0];
		if (!record) {
			return {
				success: false,
				error: makeError("INVALID_REFRESH_TOKEN", "Refresh token not found"),
			};
		}

		if (record.clientId !== clientId) {
			return {
				success: false,
				error: makeError("CLIENT_MISMATCH", "client_id does not match the refresh token"),
			};
		}

		if (record.expiresAt <= new Date()) {
			return {
				success: false,
				error: makeError("REFRESH_TOKEN_EXPIRED", "Refresh token has expired"),
			};
		}

		if (record.revoked) {
			return {
				success: false,
				error: makeError("REFRESH_TOKEN_REVOKED", "Refresh token has been revoked"),
			};
		}

		await db
			.update(oidcRefreshTokens)
			.set({ revoked: true })
			.where(eq(oidcRefreshTokens.id, record.id));

		const scopes = record.scopes.split(" ").filter(Boolean);
		const sid = sidIndex ? await sidIndex.latest(record.userId, clientId) : null;
		return generateTokenSet(record.userId, clientId, scopes, null, sid);
	}

	async function authenticateClient(
		clientId: string,
		clientSecret?: string,
	): Promise<Result<{ verified: true }>> {
		const rows = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId));

		const client = rows[0];
		if (!client) {
			return { success: false, error: makeError("CLIENT_NOT_FOUND", "Client not found") };
		}

		if (client.clientSecretHash) {
			if (!clientSecret) {
				return {
					success: false,
					error: makeError("CLIENT_AUTH_REQUIRED", "client_secret is required"),
				};
			}
			if ((await hashSecret(clientSecret)) !== client.clientSecretHash) {
				return {
					success: false,
					error: makeError("INVALID_CLIENT_SECRET", "Invalid client credentials"),
				};
			}
		}

		return { success: true, data: { verified: true } };
	}

	async function generateTokenSet(
		userId: string,
		clientId: string,
		scopes: string[],
		nonce: string | null,
		sid: string | null = null,
	): Promise<Result<TokenResponse>> {
		const key = await getSigningKey();
		const now = Math.floor(Date.now() / 1000);
		const jti = generateId();

		const accessTokenBuilder = new jose.SignJWT({
			scope: scopes.join(" "),
			client_id: clientId,
		})
			.setProtectedHeader({ alg: signingAlg, kid: "theauth-oidc-1" })
			.setIssuer(issuer)
			.setSubject(userId)
			.setAudience(clientId)
			.setIssuedAt(now)
			.setExpirationTime(now + accessTokenTtl)
			.setJti(jti);

		const accessToken = await accessTokenBuilder.sign(key);

		const userClaims = await getUserClaims(userId, scopes);
		const idTokenPayload: Record<string, unknown> = {
			...userClaims,
			azp: clientId,
		};
		if (nonce) {
			idTokenPayload.nonce = nonce;
		}
		if (sid) {
			idTokenPayload.sid = sid;
		}
		const atHashBuffer = await sha256Raw(accessToken);
		const atHashHalf = atHashBuffer.subarray(0, atHashBuffer.length / 2);
		idTokenPayload.at_hash = jose.base64url.encode(atHashHalf);

		const idToken = await new jose.SignJWT(idTokenPayload)
			.setProtectedHeader({ alg: signingAlg, kid: "theauth-oidc-1" })
			.setIssuer(issuer)
			.setSubject(userId)
			.setAudience(clientId)
			.setIssuedAt(now)
			.setExpirationTime(now + idTokenTtl)
			.sign(key);

		const rawRefreshToken = generateRandomHex(REFRESH_TOKEN_BYTE_LENGTH);
		const refreshTokenHash = await hashSecret(rawRefreshToken);
		const refreshExpiresAt = new Date((now + refreshTokenTtl) * 1000);

		try {
			await db.insert(oidcRefreshTokens).values({
				id: generateId(),
				tokenHash: refreshTokenHash,
				clientId,
				userId,
				scopes: scopes.join(" "),
				revoked: false,
				expiresAt: refreshExpiresAt,
				createdAt: new Date(),
			});
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"TOKEN_GENERATION_FAILED",
					err instanceof Error ? err.message : "Failed to store refresh token",
				),
			};
		}

		return {
			success: true,
			data: {
				accessToken,
				idToken,
				refreshToken: rawRefreshToken,
				tokenType: "Bearer",
				expiresIn: accessTokenTtl,
			},
		};
	}

	async function getUserInfo(accessToken: string): Promise<Result<UserInfoClaims>> {
		const validation = await validateAccessToken(accessToken);
		if (!validation.success) {
			return validation;
		}

		const { sub, scope } = validation.data;
		const scopes = scope.split(" ").filter(Boolean);

		try {
			const claims = await getUserClaims(sub, scopes);
			return { success: true, data: claims };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"USERINFO_FAILED",
					err instanceof Error ? err.message : "Failed to retrieve user info",
				),
			};
		}
	}

	function getDiscoveryDocument(): OidcDiscoveryDocument {
		return {
			issuer,
			authorization_endpoint: `${issuer}/authorize`,
			token_endpoint: `${issuer}/token`,
			userinfo_endpoint: `${issuer}/userinfo`,
			jwks_uri: `${issuer}/.well-known/jwks.json`,
			registration_endpoint: `${issuer}/register`,
			scopes_supported: supportedScopes,
			response_types_supported: ["code"],
			grant_types_supported: ["authorization_code", "refresh_token"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: [signingAlg],
			token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
			claims_supported: [
				"sub",
				"iss",
				"aud",
				"exp",
				"iat",
				"nonce",
				"email",
				"name",
				"picture",
				"email_verified",
			],
			code_challenge_methods_supported: ["S256"],
			...(logout && {
				end_session_endpoint: logout.endSessionEndpoint,
				backchannel_logout_supported: true,
				backchannel_logout_session_supported: true,
			}),
		};
	}

	async function getJwks(): Promise<JsonWebKeySet> {
		const publicJwk = await getPublicJwk();
		return { keys: [publicJwk] };
	}

	async function validateAccessToken(token: string): Promise<Result<AccessTokenClaims>> {
		if (!token || token.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "token must not be empty") };
		}

		try {
			const publicJwk = await getPublicJwk();
			const key = await jose.importJWK(publicJwk, signingAlg);
			const { payload } = await jose.jwtVerify(token, key, {
				issuer,
			});

			return {
				success: true,
				data: {
					sub: payload.sub as string,
					iss: payload.iss as string,
					aud: payload.aud as string,
					exp: payload.exp as number,
					iat: payload.iat as number,
					jti: payload.jti as string,
					scope: (payload as Record<string, unknown>).scope as string,
					clientId: (payload as Record<string, unknown>).client_id as string,
				},
			};
		} catch (err) {
			if (err instanceof jose.errors.JWTExpired) {
				return { success: false, error: makeError("TOKEN_EXPIRED", "Access token has expired") };
			}
			return {
				success: false,
				error: makeError(
					"TOKEN_VALIDATION_FAILED",
					err instanceof Error ? err.message : "Failed to validate access token",
				),
			};
		}
	}

	return {
		registerClient,
		getClient,
		deleteClient,
		authorize,
		exchangeToken,
		getUserInfo,
		getDiscoveryDocument,
		getJwks,
		validateAccessToken,
		...(logout && { logout }),
	};
}
