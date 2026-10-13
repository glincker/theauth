import { ExtensionAuthError } from "./errors.js";

export interface TokenResponse {
	accessToken: string;
	tokenType: "Bearer" | "DPoP";
	expiresIn: number;
	refreshToken?: string;
	scope?: string;
	idToken?: string;
}

export interface OAuthErrorBody {
	error: string;
	description?: string;
}

export type TokenResult =
	| { ok: true; tokens: TokenResponse }
	| { ok: false; status: number; error: OAuthErrorBody };

async function readJson(res: Response): Promise<Record<string, unknown>> {
	try {
		const body: unknown = await res.json();
		return typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

/** Parse a token endpoint response. Never includes token values in errors. */
export async function parseTokenResponse(res: Response): Promise<TokenResult> {
	const body = await readJson(res);
	if (!res.ok) {
		const error = typeof body.error === "string" ? body.error : "server_error";
		const description =
			typeof body.error_description === "string" ? body.error_description : undefined;
		return { ok: false, status: res.status, error: { error, description } };
	}
	const access = body.access_token;
	const type = typeof body.token_type === "string" ? body.token_type.toLowerCase() : "";
	if (typeof access !== "string" || (type !== "bearer" && type !== "dpop")) {
		return { ok: false, status: res.status, error: { error: "invalid_response" } };
	}
	return {
		ok: true,
		tokens: {
			accessToken: access,
			tokenType: type === "dpop" ? "DPoP" : "Bearer",
			expiresIn: typeof body.expires_in === "number" ? body.expires_in : 3600,
			refreshToken: typeof body.refresh_token === "string" ? body.refresh_token : undefined,
			scope: typeof body.scope === "string" ? body.scope : undefined,
			idToken: typeof body.id_token === "string" ? body.id_token : undefined,
		},
	};
}

export function formBody(params: Record<string, string | undefined>): string {
	const out = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) {
		if (v !== undefined) out.set(k, v);
	}
	return out.toString();
}

const CANCEL_PATTERN = /did not approve|cancel|closed|dismiss|denied/i;

export function classifyLaunchError(cause: unknown): ExtensionAuthError {
	const message = cause instanceof Error ? cause.message : String(cause);
	if (CANCEL_PATTERN.test(message)) {
		return new ExtensionAuthError("user_cancelled", "The user closed the sign in window");
	}
	return new ExtensionAuthError("authorization_failed", "The authorization page failed", {
		cause: message,
	});
}

export interface AuthorizationCallback {
	code: string;
}

export interface CallbackExpectations {
	state: string;
	issuer?: string;
	issuerRequired: boolean;
}

/** Validate the redirect URL returned by `launchWebAuthFlow`. */
export function parseAuthorizationCallback(
	responseUrl: string | undefined,
	expected: CallbackExpectations,
): AuthorizationCallback {
	if (!responseUrl) {
		throw new ExtensionAuthError("user_cancelled", "No redirect was returned");
	}
	const url = new URL(responseUrl);
	const params = url.search ? url.searchParams : new URLSearchParams(url.hash.replace(/^#/, ""));
	if (params.get("state") !== expected.state) {
		throw new ExtensionAuthError("state_mismatch", "The state parameter did not match");
	}
	const iss = params.get("iss");
	if (iss !== null && expected.issuer !== undefined && iss !== expected.issuer) {
		throw new ExtensionAuthError("authorization_failed", "The iss parameter did not match");
	}
	if (iss === null && expected.issuerRequired) {
		throw new ExtensionAuthError("authorization_failed", "The iss parameter is missing");
	}
	const error = params.get("error");
	if (error) {
		if (error === "access_denied") {
			throw new ExtensionAuthError("user_cancelled", "The user denied access");
		}
		throw new ExtensionAuthError("authorization_failed", `Authorization error: ${error}`, {
			error,
		});
	}
	const code = params.get("code");
	if (!code) throw new ExtensionAuthError("authorization_failed", "No authorization code returned");
	return { code };
}
