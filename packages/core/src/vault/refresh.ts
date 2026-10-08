import type { VaultProviderConfig } from "./types.js";

export type RefreshOutcome =
	| {
			ok: true;
			accessToken: string;
			refreshToken?: string;
			expiresIn?: number;
			scopes?: string[];
	  }
	| { ok: false; reauth: boolean };

/**
 * RFC 6749 section 6 refresh. Response bodies are parsed but never logged or
 * echoed in errors, since failures can still contain token material.
 */
export async function refreshTokens(
	cfg: VaultProviderConfig,
	refreshToken: string,
	doFetch: typeof fetch,
): Promise<RefreshOutcome> {
	let res: Response;
	try {
		res = await doFetch(cfg.provider.tokenUrl, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: cfg.clientId,
				client_secret: cfg.clientSecret,
			}).toString(),
		});
	} catch {
		return { ok: false, reauth: false };
	}
	let body: Record<string, unknown> = {};
	try {
		body = (await res.json()) as Record<string, unknown>;
	} catch {
		return { ok: false, reauth: false };
	}
	if (!res.ok || typeof body.access_token !== "string") {
		return { ok: false, reauth: body.error === "invalid_grant" };
	}
	return {
		ok: true,
		accessToken: body.access_token,
		refreshToken: typeof body.refresh_token === "string" ? body.refresh_token : undefined,
		expiresIn: typeof body.expires_in === "number" ? body.expires_in : undefined,
		scopes: typeof body.scope === "string" ? body.scope.split(/[\s,]+/).filter(Boolean) : undefined,
	};
}
