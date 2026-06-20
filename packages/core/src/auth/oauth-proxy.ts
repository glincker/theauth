/**
 * OAuth proxy module for mobile apps.
 *
 * Mobile apps cannot safely store OAuth client secrets. This module acts as a
 * server-side intermediary: the mobile app redirects to the provider via
 * TheAuth, which holds the secret and exchanges the authorization code for
 * tokens on the app's behalf.
 *
 * Flow:
 *   1. Mobile app calls GET /auth/oauth-proxy/start?provider=google&redirect_uri=myapp://callback
 *   2. TheAuth validates redirect_uri, stores proxy state, returns provider auth URL.
 *   3. User authenticates with the provider in a browser.
 *   4. Provider redirects to TheAuth callback with code + state.
 *   5. TheAuth exchanges the code (using the server-held client secret), then
 *      redirects the mobile app to its custom scheme URL with tokens as query params.
 *
 * Security:
 *   - redirect_uri is validated against an explicit allowlist — no open redirects.
 *   - Proxy state is a random UUID stored in memory with a 10-minute TTL.
 *   - PKCE passthrough: the mobile app may supply a code_challenge; TheAuth
 *     forwards it to the provider and passes the verifier back via the callback.
 */

import { generateId } from "../crypto/web-crypto.js";
import { generateCodeVerifier } from "./oauth/pkce.js";
import type { OAuthProvider } from "./oauth/types.js";
import type { RateLimiter } from "./rate-limiter.js";
import { createRateLimiter } from "./rate-limiter.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface OAuthProxyConfig {
	/**
	 * Allowed redirect URIs for mobile apps (e.g. `"myapp://callback"`).
	 * Only exact matches or scheme-prefix matches (when entry ends with `://`)
	 * are allowed. No wildcards. This is an allowlist — anything not listed
	 * will be rejected.
	 */
	allowedRedirectUris: string[];
	/** Rate limit per IP. Defaults to 20 requests per 60 seconds. */
	rateLimit?: { max: number; windowSeconds: number };
	/**
	 * How long a proxy state entry lives in seconds.
	 * Defaults to 600 (10 minutes).
	 */
	stateTtlSeconds?: number;
}

export interface ProxyTokens {
	accessToken: string;
	refreshToken?: string;
	idToken?: string;
	expiresIn?: number;
}

export interface OAuthProxyModule {
	/**
	 * Start the proxy flow.
	 *
	 * Validates `redirectUri` against the allowlist, generates a PKCE verifier,
	 * stores proxy state keyed by an opaque `proxyState` value, and returns the
	 * provider authorization URL for the caller to redirect to.
	 *
	 * @param provider     Provider ID (must be in `providers` map).
	 * @param redirectUri  Mobile app callback URI. Must be in `allowedRedirectUris`.
	 * @param state        Optional caller-supplied state passed back on completion.
	 * @param codeChallenge Optional PKCE code challenge from the mobile app (S256).
	 */
	startFlow(
		provider: string,
		redirectUri: string,
		state?: string,
		codeChallenge?: string,
	): Promise<{ authUrl: string; proxyState: string }>;

	/**
	 * Handle the provider callback.
	 *
	 * Looks up the stored proxy state, exchanges the code with the provider,
	 * and returns the final redirect URL for the mobile app plus the raw tokens.
	 *
	 * @param code        Authorization code from the provider.
	 * @param proxyState  The opaque state value returned by `startFlow`.
	 */
	handleCallback(
		code: string,
		proxyState: string,
	): Promise<{ redirectUrl: string; tokens: ProxyTokens }>;

	/** Route HTTP requests to the proxy endpoints. Returns null if no match. */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal state entry
// ---------------------------------------------------------------------------

interface ProxyStateEntry {
	provider: string;
	redirectUri: string;
	/** Caller's own state value (forwarded to the mobile app on completion). */
	callerState: string | undefined;
	/** PKCE verifier TheAuth generated for the provider exchange. */
	serverCodeVerifier: string;
	/** TheAuth's redirect URI pointing back to the callback endpoint. */
	serverRedirectUri: string;
	expiresAt: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_STATE_TTL_SECONDS = 600;
const DEFAULT_RATE_LIMIT = { max: 20, windowSeconds: 60 };

/** Returns true when `uri` is in the allowlist. */
function isAllowedRedirectUri(uri: string, allowedRedirectUris: string[]): boolean {
	for (const allowed of allowedRedirectUris) {
		// Exact match.
		if (uri === allowed) return true;
		// Scheme-only entry (e.g. "myapp://") — allow any URI under that scheme.
		if (allowed.endsWith("://") && uri.startsWith(allowed)) return true;
	}
	return false;
}

function jsonError(message: string, status: number): Response {
	return new Response(JSON.stringify({ error: message }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getClientIp(request: Request): string {
	return (
		request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		request.headers.get("x-real-ip") ??
		"unknown"
	);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createOAuthProxyModule(
	config: OAuthProxyConfig,
	providers: Record<string, OAuthProvider>,
	/** Base URL of the TheAuth server, e.g. "https://auth.example.com". */
	baseUrl: string,
): OAuthProxyModule {
	const ttlMs = (config.stateTtlSeconds ?? DEFAULT_STATE_TTL_SECONDS) * 1000;
	const rl = config.rateLimit ?? DEFAULT_RATE_LIMIT;
	const rateLimiter: RateLimiter = createRateLimiter({ max: rl.max, window: rl.windowSeconds });

	// In-memory state store — keyed by opaque proxyState UUID.
	const stateStore = new Map<string, ProxyStateEntry>();

	// The TheAuth-side callback URL registered with the provider.
	const serverCallbackUri = `${baseUrl.replace(/\/$/, "")}/auth/oauth-proxy/callback`;

	// ---------------------------------------------------------------------------
	// Periodic cleanup: prune expired entries whenever we write.
	// ---------------------------------------------------------------------------

	function pruneExpired(): void {
		const now = Date.now();
		for (const [key, entry] of stateStore) {
			if (entry.expiresAt <= now) {
				stateStore.delete(key);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// startFlow
	// ---------------------------------------------------------------------------

	async function startFlow(
		providerId: string,
		redirectUri: string,
		callerState?: string,
		_codeChallenge?: string,
	): Promise<{ authUrl: string; proxyState: string }> {
		if (!isAllowedRedirectUri(redirectUri, config.allowedRedirectUris)) {
			throw new OAuthProxyError(
				"redirect_uri_not_allowed",
				`Redirect URI is not in the allowlist: ${redirectUri}`,
			);
		}

		const provider = providers[providerId];
		if (!provider) {
			throw new OAuthProxyError("unknown_provider", `Unknown OAuth provider: ${providerId}`);
		}

		pruneExpired();

		const proxyState = generateId();
		const serverCodeVerifier = generateCodeVerifier();
		const expiresAt = Date.now() + ttlMs;

		stateStore.set(proxyState, {
			provider: providerId,
			redirectUri,
			callerState,
			serverCodeVerifier,
			serverRedirectUri: serverCallbackUri,
			expiresAt,
		});

		// The state we pass to the provider encodes our proxyState so the callback
		// can look it up. We keep it as-is; the provider will round-trip it.
		const authUrl = await provider.getAuthorizationUrl(
			proxyState,
			serverCodeVerifier,
			serverCallbackUri,
		);

		return { authUrl, proxyState };
	}

	// ---------------------------------------------------------------------------
	// handleCallback
	// ---------------------------------------------------------------------------

	async function handleCallback(
		code: string,
		proxyState: string,
	): Promise<{ redirectUrl: string; tokens: ProxyTokens }> {
		const entry = stateStore.get(proxyState);

		if (!entry) {
			throw new OAuthProxyError("invalid_state", "Unknown or already-used proxy state.");
		}

		if (entry.expiresAt <= Date.now()) {
			stateStore.delete(proxyState);
			throw new OAuthProxyError("state_expired", "Proxy state has expired. Start the flow again.");
		}

		// Consume — delete before the network call to prevent replay.
		stateStore.delete(proxyState);

		const provider = providers[entry.provider];
		if (!provider) {
			throw new OAuthProxyError(
				"unknown_provider",
				`Provider "${entry.provider}" is no longer configured.`,
			);
		}

		// Exchange the code using the server-held client secret.
		const providerTokens = await provider.exchangeCode(
			code,
			entry.serverCodeVerifier,
			entry.serverRedirectUri,
		);

		// Build the mobile app redirect URL. Tokens are passed as query params
		// so custom-scheme handlers can read them from the URL on all platforms.
		const params = new URLSearchParams();
		params.set("access_token", providerTokens.accessToken);
		if (providerTokens.refreshToken) {
			params.set("refresh_token", providerTokens.refreshToken);
		}
		if (providerTokens.expiresIn !== undefined) {
			params.set("expires_in", String(providerTokens.expiresIn));
		}
		// Forward id_token if the provider included one in the raw response.
		const rawIdToken = providerTokens.raw.id_token;
		if (typeof rawIdToken === "string") {
			params.set("id_token", rawIdToken);
		}
		if (entry.callerState) {
			params.set("state", entry.callerState);
		}

		const separator = entry.redirectUri.includes("?") ? "&" : "?";
		const redirectUrl = `${entry.redirectUri}${separator}${params.toString()}`;

		const tokens: ProxyTokens = {
			accessToken: providerTokens.accessToken,
			refreshToken: providerTokens.refreshToken,
			idToken: typeof rawIdToken === "string" ? rawIdToken : undefined,
			expiresIn: providerTokens.expiresIn,
		};

		return { redirectUrl, tokens };
	}

	// ---------------------------------------------------------------------------
	// handleRequest
	// ---------------------------------------------------------------------------

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname.replace(/\/$/, "");

		// ── GET /auth/oauth-proxy/start ──────────────────────────────────────────

		if (request.method === "GET" && pathname.endsWith("/auth/oauth-proxy/start")) {
			const ip = getClientIp(request);
			const rlResult = rateLimiter.check(ip);
			if (!rlResult.allowed) {
				return jsonError("Too many requests", 429);
			}

			const provider = url.searchParams.get("provider");
			const redirectUri = url.searchParams.get("redirect_uri");
			const callerState = url.searchParams.get("state") ?? undefined;
			const codeChallenge = url.searchParams.get("code_challenge") ?? undefined;

			if (!provider) {
				return jsonError("Missing required query parameter: provider", 400);
			}
			if (!redirectUri) {
				return jsonError("Missing required query parameter: redirect_uri", 400);
			}

			try {
				const result = await startFlow(provider, redirectUri, callerState, codeChallenge);
				return new Response(JSON.stringify(result), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				});
			} catch (err) {
				if (err instanceof OAuthProxyError) {
					const status = err.code === "redirect_uri_not_allowed" ? 400 : 400;
					return jsonError(err.message, status);
				}
				return jsonError("Failed to start OAuth proxy flow", 500);
			}
		}

		// ── GET /auth/oauth-proxy/callback ───────────────────────────────────────

		if (request.method === "GET" && pathname.endsWith("/auth/oauth-proxy/callback")) {
			const code = url.searchParams.get("code");
			const proxyState = url.searchParams.get("state");
			const errorParam = url.searchParams.get("error");

			if (errorParam) {
				// Provider returned an error — we need to redirect the mobile app to
				// an error state. Try to look up the state to find the redirect_uri.
				const entry = proxyState ? stateStore.get(proxyState) : undefined;
				if (entry) {
					stateStore.delete(proxyState as string);
					const params = new URLSearchParams({ error: errorParam });
					if (entry.callerState) params.set("state", entry.callerState);
					const sep = entry.redirectUri.includes("?") ? "&" : "?";
					return Response.redirect(`${entry.redirectUri}${sep}${params.toString()}`, 302);
				}
				return jsonError(`Provider returned error: ${errorParam}`, 400);
			}

			if (!code) {
				return jsonError("Missing required query parameter: code", 400);
			}
			if (!proxyState) {
				return jsonError("Missing required query parameter: state", 400);
			}

			try {
				const { redirectUrl } = await handleCallback(code, proxyState);
				return Response.redirect(redirectUrl, 302);
			} catch (err) {
				if (err instanceof OAuthProxyError) {
					return jsonError(err.message, 400);
				}
				return jsonError("OAuth callback failed", 500);
			}
		}

		return null;
	}

	return { startFlow, handleCallback, handleRequest };
}

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

export class OAuthProxyError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "OAuthProxyError";
		this.code = code;
	}
}
