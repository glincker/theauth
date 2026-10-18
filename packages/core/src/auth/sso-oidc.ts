/** OIDC discovery and the authorization code flow for SSO connections. */

import { eq } from "drizzle-orm";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { sha256Raw, toHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { ssoConnections } from "../db/schema.js";
import { uint8ArrayToBase64Url } from "./sso-encoding.js";
import type { RateLimiter } from "./sso-rate-limit.js";
import type { OidcProvider, SsoAuditEvent, SsoModule } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";

interface OidcDiscoveryResponse {
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	userinfo_endpoint?: string;
}

async function fetchOidcDiscovery(issuer: string): Promise<OidcDiscoveryResponse> {
	const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
	const res = await fetch(url);
	if (!res.ok) {
		throw new SsoError(
			SSO_ERROR.OIDC_DISCOVERY_FAILED,
			`OIDC discovery failed: HTTP ${res.status}`,
		);
	}
	return res.json() as Promise<OidcDiscoveryResponse>;
}

interface OidcTokenResponse {
	access_token: string;
	id_token: string;
	token_type: string;
	expires_in?: number;
}

export function createOidcFlow(ctx: {
	db: Database;
	oidcProviders: Map<string, OidcProvider>;
	rateLimiter: RateLimiter;
	emitAudit: (event: Omit<SsoAuditEvent, "timestamp">) => void;
}): Pick<SsoModule, "getOidcAuthUrl" | "handleOidcCallback"> {
	const { db, oidcProviders, rateLimiter, emitAudit } = ctx;

	async function getOidcAuthUrl(
		connectionId: string,
		state?: string,
		nonce?: string,
	): Promise<string> {
		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);
		if (conn.type !== "oidc") {
			throw new SsoError(
				SSO_ERROR.CONNECTION_TYPE_MISMATCH,
				`Connection "${connectionId}" is not an OIDC connection`,
			);
		}

		const provider = oidcProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`OIDC provider "${conn.providerId}" not configured`,
			);

		const discovery = await fetchOidcDiscovery(provider.issuer);
		const scopes = (provider.scopes ?? ["openid", "profile", "email"]).join(" ");

		const url = new URL(discovery.authorization_endpoint);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("client_id", provider.clientId);
		url.searchParams.set("redirect_uri", provider.callbackUrl);
		url.searchParams.set("scope", scopes);
		if (state) url.searchParams.set("state", state);
		if (nonce) url.searchParams.set("nonce", nonce);

		return url.toString();
	}

	async function handleOidcCallback(
		connectionId: string,
		code: string,
		expectedNonce?: string,
	): Promise<{ user: { id: string; email: string; name?: string }; orgId: string }> {
		emitAudit({ type: "sso_login_attempt", connectionId, metadata: { protocol: "oidc" } });

		if (!rateLimiter.check(`oidc:${connectionId}`)) {
			emitAudit({ type: "sso_login_failure", connectionId, error: "Rate limited" });
			throw new SsoError(
				SSO_ERROR.RATE_LIMITED,
				"Too many SSO login attempts. Please try again later.",
			);
		}

		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);

		const provider = oidcProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`OIDC provider "${conn.providerId}" not configured`,
			);

		const discovery = await fetchOidcDiscovery(provider.issuer);
		const authMethod = provider.tokenEndpointAuthMethod ?? "client_secret_post";

		const params = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: provider.callbackUrl,
		});

		const headers: Record<string, string> = {
			"Content-Type": "application/x-www-form-urlencoded",
		};

		if (authMethod === "client_secret_basic") {
			const credentials = btoa(
				`${encodeURIComponent(provider.clientId)}:${encodeURIComponent(provider.clientSecret)}`,
			);
			headers.Authorization = `Basic ${credentials}`;
		} else {
			params.set("client_id", provider.clientId);
			params.set("client_secret", provider.clientSecret);
		}

		const tokenRes = await fetch(discovery.token_endpoint, {
			method: "POST",
			headers,
			body: params.toString(),
		});
		if (!tokenRes.ok) {
			emitAudit({
				type: "sso_login_failure",
				connectionId,
				providerId: conn.providerId,
				error: `Token exchange failed: HTTP ${tokenRes.status}`,
			});
			throw new SsoError(
				SSO_ERROR.OIDC_TOKEN_EXCHANGE_FAILED,
				`OIDC token exchange failed: HTTP ${tokenRes.status}`,
			);
		}

		const tokens = (await tokenRes.json()) as OidcTokenResponse;

		const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
		const { payload } = await jwtVerify(tokens.id_token, jwks, {
			issuer: provider.issuer,
			audience: provider.clientId,
		});

		if (expectedNonce) {
			const tokenNonce = payload.nonce as string | undefined;
			if (tokenNonce !== expectedNonce) {
				emitAudit({
					type: "sso_login_failure",
					connectionId,
					providerId: conn.providerId,
					error: "Nonce mismatch",
				});
				throw new SsoError(
					SSO_ERROR.OIDC_NONCE_MISMATCH,
					`OIDC nonce mismatch: expected "${expectedNonce}" but got "${tokenNonce ?? "(none)"}"`,
				);
			}
		}

		if (payload.at_hash && tokens.access_token) {
			const atHash = payload.at_hash as string;
			// at_hash is the base64url encoding of the left half of the hash of the access_token
			const accessTokenHashBytes = await sha256Raw(tokens.access_token);
			const leftHalf = accessTokenHashBytes.subarray(0, accessTokenHashBytes.length / 2);
			const expectedAtHash = uint8ArrayToBase64Url(leftHalf);
			if (atHash !== expectedAtHash) {
				emitAudit({
					type: "sso_login_failure",
					connectionId,
					error: "at_hash mismatch",
				});
				throw new SsoError(SSO_ERROR.OIDC_TOKEN_EXCHANGE_FAILED, "OIDC at_hash validation failed");
			}
		}

		const email = payload.email as string | undefined;
		if (!email) {
			throw new SsoError(
				SSO_ERROR.OIDC_MISSING_EMAIL,
				"OIDC id_token does not contain an email claim",
			);
		}
		const name = (payload.name as string | undefined) ?? undefined;

		const oidcUserIdHash = await sha256Raw(`${conn.providerId}:${payload.sub}`);
		const userId = `oidc_${toHex(oidcUserIdHash).slice(0, 32)}`;

		emitAudit({
			type: "sso_login_success",
			connectionId,
			providerId: conn.providerId,
			email,
		});

		return {
			user: { id: userId, email, name },
			orgId: conn.orgId,
		};
	}

	return { getOidcAuthUrl, handleOidcCallback };
}
