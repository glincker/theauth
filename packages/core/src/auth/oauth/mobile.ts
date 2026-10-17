/**
 * Native app sign-in for the OAuth plugin (RFC 8252 with PKCE).
 * The session token never appears in a URL: the app trades the code, plus the PKCE verifier that never left the device, for the session at the exchange route.
 */

import { verifyS256 } from "../../mcp/utils.js";
import type { OneTimeTokenModule } from "../one-time-token.js";

export interface MobileOAuthConfig {
	/** App redirect URIs the browser may be sent back to, matched exactly: a custom scheme (`myapp://auth/callback`) or an https app link. Without this the mobile flow is off. */
	redirectUris: string[];
	/** Seconds the exchange code stays valid. Default 60. */
	codeTtlSeconds?: number;
}

export const MOBILE_COOKIE = "theauth_mobile_oauth";

const PENDING = "mobile-oauth:pending";
const EXCHANGE = "mobile-oauth:exchange";
const PENDING_TTL_SECONDS = 600;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;

export interface MobileFlow {
	redirectUri: string;
	challenge: string;
}

export interface MobileOAuth {
	/** Validate the authorize parameters. Returns an error message when invalid. */
	parseStart(params: URLSearchParams): { flow: MobileFlow } | { error: string } | null;
	/** Remember the flow for the browser and return the cookie value to set. */
	begin(flow: MobileFlow): Promise<string>;
	/** Consume the cookie value at callback time. */
	resume(cookieValue: string | null): Promise<MobileFlow | null>;
	/** Mint the single-use code handed to the app. */
	issueCode(flow: MobileFlow, userId: string): Promise<string>;
	/** Redeem a code with the PKCE verifier. Returns the user id, or null. */
	redeem(code: string, verifier: string): Promise<string | null>;
	/** `redirectUri` with the given parameters appended to its query. */
	redirectWith(redirectUri: string, params: Record<string, string>): string;
}

export function createMobileOAuth(
	config: MobileOAuthConfig,
	tokens: OneTimeTokenModule,
): MobileOAuth {
	const allowed = new Set(config.redirectUris);
	const codeTtl = config.codeTtlSeconds ?? 60;

	return {
		parseStart(params) {
			const redirectUri = params.get("mobile_redirect");
			if (redirectUri === null) return null;
			if (!allowed.has(redirectUri)) return { error: "mobile_redirect is not allowed" };
			const challenge = params.get("code_challenge") ?? "";
			if (params.get("code_challenge_method") !== "S256" || !CHALLENGE_RE.test(challenge)) {
				return { error: "code_challenge with code_challenge_method=S256 is required" };
			}
			return { flow: { redirectUri, challenge } };
		},

		async begin(flow) {
			const made = await tokens.createToken({
				purpose: "custom",
				identifier: PENDING,
				metadata: { ...flow },
				ttlSeconds: PENDING_TTL_SECONDS,
			});
			if (!made.success) throw new Error("Could not start the mobile sign-in");
			return made.data.token;
		},

		async resume(cookieValue) {
			if (!cookieValue) return null;
			const used = await tokens.validateToken(cookieValue, "custom");
			if (!used.success || used.data.identifier !== PENDING) return null;
			const { redirectUri, challenge } = used.data.metadata ?? {};
			if (typeof redirectUri !== "string" || typeof challenge !== "string") return null;
			// Re-check in case the allowlist changed while the flow was in flight.
			return allowed.has(redirectUri) ? { redirectUri, challenge } : null;
		},

		async issueCode(flow, userId) {
			const made = await tokens.createToken({
				purpose: "custom",
				identifier: EXCHANGE,
				metadata: { userId, challenge: flow.challenge },
				ttlSeconds: codeTtl,
			});
			if (!made.success) throw new Error("Could not issue the mobile sign-in code");
			return made.data.token;
		},

		async redeem(code, verifier) {
			if (!VERIFIER_RE.test(verifier)) return null;
			// The code is consumed even when the verifier is wrong, so a stolen
			// code cannot be retried with guesses.
			const used = await tokens.validateToken(code, "custom");
			if (!used.success || used.data.identifier !== EXCHANGE) return null;
			const { userId, challenge } = used.data.metadata ?? {};
			if (typeof userId !== "string" || typeof challenge !== "string") return null;
			return (await verifyS256(verifier, challenge)) ? userId : null;
		},

		redirectWith(redirectUri, params) {
			const url = new URL(redirectUri);
			for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
			return url.toString();
		},
	};
}
