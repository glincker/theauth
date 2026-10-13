/**
 * RFC 6749 section 6 refresh for the built-in providers.
 *
 * Response bodies are parsed but never echoed in errors, since failures can
 * still carry token material.
 */

import { OAuthRefreshError } from "../errors.js";
import type { OAuthTokens } from "../types.js";

export interface RefresherConfig {
	/** Display name used in error messages. */
	providerName: string;
	tokenUrl: string;
	clientId: string;
	clientSecret: string;
	/** How client credentials are sent. Defaults to `body` (matching code exchange). */
	authStyle?: "body" | "basic";
}

export function createRefresher(
	config: RefresherConfig,
): (refreshToken: string) => Promise<OAuthTokens> {
	return async (refreshToken) => {
		const params = new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
		});
		const headers: Record<string, string> = {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
		};
		if (config.authStyle === "basic") {
			headers.Authorization = `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
		} else {
			params.set("client_id", config.clientId);
			params.set("client_secret", config.clientSecret);
		}

		let res: Response;
		try {
			res = await fetch(config.tokenUrl, {
				method: "POST",
				headers,
				body: params.toString(),
			});
		} catch {
			throw new OAuthRefreshError(`${config.providerName} token refresh request failed`, {
				reauth: false,
			});
		}

		let raw: Record<string, unknown> = {};
		try {
			raw = (await res.json()) as Record<string, unknown>;
		} catch {
			// Fall through: a non-JSON body is a failure below.
		}

		if (!res.ok || typeof raw.access_token !== "string") {
			throw new OAuthRefreshError(`${config.providerName} token refresh failed (${res.status})`, {
				reauth: raw.error === "invalid_grant",
				status: res.status,
			});
		}

		return {
			accessToken: raw.access_token,
			refreshToken: typeof raw.refresh_token === "string" ? raw.refresh_token : undefined,
			expiresIn: typeof raw.expires_in === "number" ? raw.expires_in : undefined,
			tokenType: typeof raw.token_type === "string" ? raw.token_type : "Bearer",
			raw,
		};
	};
}
