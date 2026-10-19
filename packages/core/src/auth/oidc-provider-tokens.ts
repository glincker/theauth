import { and, eq } from "drizzle-orm";
import * as jose from "jose";
import { generateId, sha256Raw } from "../crypto/web-crypto.js";
import { oidcAuthCodes, oidcClients, oidcRefreshTokens } from "../db/schema.js";
import { singleUseFor } from "../db/store/for-database.js";
import type { Result } from "../mcp/types.js";
import type { createOidcDiscovery } from "./oidc-provider-discovery.js";
import {
	AUTH_CODE_BYTE_LENGTH,
	authorizeSchema,
	computeS256Challenge,
	generateRandomHex,
	hashSecret,
	makeError,
	REFRESH_TOKEN_BYTE_LENGTH,
	tokenSchema,
} from "./oidc-provider-helpers.js";
import type { createOidcKeys } from "./oidc-provider-keys.js";
import type {
	AuthorizeParams,
	OidcProviderContext,
	TokenParams,
	TokenResponse,
	UserInfoClaims,
} from "./oidc-provider-types.js";

/** Authorization, token exchange and userinfo for the OIDC provider. */
export function createOidcTokens(
	ctx: OidcProviderContext &
		Pick<ReturnType<typeof createOidcKeys>, "getSigningKey"> &
		Pick<ReturnType<typeof createOidcDiscovery>, "validateAccessToken">,
) {
	const {
		db,
		getUserClaims,
		issuer,
		signingAlg,
		accessTokenTtl,
		refreshTokenTtl,
		authCodeTtl,
		idTokenTtl,
		supportedScopes,
		sidIndex,
		getSigningKey,
		validateAccessToken,
	} = ctx;

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

		// Claim the code with one conditional UPDATE so two concurrent exchanges cannot both mint
		// tokens (RFC 6749 section 4.1.2: a code is used once). The loser sees zero changed rows.
		if (!(await singleUseFor(db).oidcAuthCodes.markUsed(authCode.id))) {
			return {
				success: false,
				error: makeError("CODE_ALREADY_USED", "Authorization code has already been used"),
			};
		}

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
		return generateTokenSet(authCode.userId, clientId, scopes, authCode.nonce, sid, null);
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
			// A rotated token came back: assume it leaked and end the whole family (RFC 9700 4.14.2).
			await revokeFamily(record);
			return {
				success: false,
				error: makeError("REFRESH_TOKEN_REVOKED", "Refresh token has been revoked"),
			};
		}

		// Rotate with one conditional UPDATE: of two concurrent refreshes only one flips revoked.
		if (!(await singleUseFor(db).oidcRefreshTokens.rotate(record.id))) {
			// Lost the rotation race to another request with the same token, which is a reuse too.
			await revokeFamily(record);
			return {
				success: false,
				error: makeError("REFRESH_TOKEN_REVOKED", "Refresh token has been revoked"),
			};
		}

		const scopes = record.scopes.split(" ").filter(Boolean);
		const sid = sidIndex ? await sidIndex.latest(record.userId, clientId) : null;
		return generateTokenSet(
			record.userId,
			clientId,
			scopes,
			null,
			sid,
			record.familyId ?? record.id,
		);
	}

	/** Revoke every refresh token in the family. Tokens from before migration 0012 have no family, so fall back to user and client. */
	async function revokeFamily(record: {
		userId: string;
		clientId: string;
		familyId: string | null;
	}): Promise<void> {
		const scope = record.familyId
			? eq(oidcRefreshTokens.familyId, record.familyId)
			: and(
					eq(oidcRefreshTokens.userId, record.userId),
					eq(oidcRefreshTokens.clientId, record.clientId),
				);
		await db.update(oidcRefreshTokens).set({ revoked: true }).where(scope);
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
		sid: string | null,
		familyId: string | null,
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

		const refreshId = generateId();
		try {
			await db.insert(oidcRefreshTokens).values({
				id: refreshId,
				familyId: familyId ?? refreshId,
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

	return {
		authorize,
		exchangeToken,
		getUserInfo,
	};
}
