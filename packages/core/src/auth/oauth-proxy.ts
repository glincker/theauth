/** OAuth proxy for mobile apps, which cannot safely hold OAuth client secrets. */

import { generateId } from "../crypto/web-crypto.js";
import type { TrustedProxyConfig } from "./client-ip.js";
import { resolveClientIp } from "./client-ip.js";
import { generateCodeVerifier } from "./oauth/pkce.js";
import type { OAuthProvider } from "./oauth/types.js";
import type { RateLimiter } from "./rate-limiter.js";
import { createRateLimiter } from "./rate-limiter.js";

export interface OAuthProxyConfig {
	/** Allowed redirect URIs for mobile apps (e.g. `myapp://callback`). Exact matches or scheme-only entries. */
	allowedRedirectUris: string[];
	/** Rate limit per IP. Defaults to 20 requests per 60 seconds. */
	rateLimit?: { max: number; windowSeconds: number };
	/** How long a proxy state entry lives, in seconds. Default: 600. */
	stateTtlSeconds?: number;
	/** Trusted proxy setup for client IP resolution. Forwarded headers are ignored by default. */
	trustedProxy?: TrustedProxyConfig;
}

export interface ProxyTokens {
	accessToken: string;
	refreshToken?: string;
	idToken?: string;
	expiresIn?: number;
}

export interface OAuthProxyModule {
	/** Starts the proxy flow: validates `redirectUri` against the allowlist and generates PKCE. */
	startFlow(
		provider: string,
		redirectUri: string,
		state?: string,
		codeChallenge?: string,
	): Promise<{ authUrl: string; proxyState: string }>;

	/** Handles the provider callback: looks up the stored state and exchanges the code. */
	handleCallback(
		code: string,
		proxyState: string,
	): Promise<{ redirectUrl: string; tokens: ProxyTokens }>;

	/** Route HTTP requests to the proxy endpoints. Returns null if no match. */
	handleRequest(request: Request): Promise<Response | null>;
}

interface ProxyStateEntry {
	provider: string;
	redirectUri: string;
	/** Caller's own state value (forwarded to the mobile app on completion). */
	callerState: string | undefined;
	serverCodeVerifier: string;
	serverRedirectUri: string;
	expiresAt: number;
}

const DEFAULT_STATE_TTL_SECONDS = 600;
const DEFAULT_RATE_LIMIT = { max: 20, windowSeconds: 60 };

/** Returns true when `uri` is in the allowlist. */
function isAllowedRedirectUri(uri: string, allowedRedirectUris: string[]): boolean {
	for (const allowed of allowedRedirectUris) {
		if (uri === allowed) return true;
		// Scheme-only entry (e.g. `myapp://`) allows any URI under that scheme.
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

export function createOAuthProxyModule(
	config: OAuthProxyConfig,
	providers: Record<string, OAuthProvider>,
	/** Base URL of the TheAuth server, e.g. "https://auth.example.com". */
	baseUrl: string,
): OAuthProxyModule {
	const ttlMs = (config.stateTtlSeconds ?? DEFAULT_STATE_TTL_SECONDS) * 1000;
	const rl = config.rateLimit ?? DEFAULT_RATE_LIMIT;
	const rateLimiter: RateLimiter = createRateLimiter({ max: rl.max, window: rl.windowSeconds });

	const stateStore = new Map<string, ProxyStateEntry>();

	const serverCallbackUri = `${baseUrl.replace(/\/$/, "")}/auth/oauth-proxy/callback`;

	function pruneExpired(): void {
		const now = Date.now();
		for (const [key, entry] of stateStore) {
			if (entry.expiresAt <= now) {
				stateStore.delete(key);
			}
		}
	}

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

		// Consume, delete before the network call to prevent replay.
		stateStore.delete(proxyState);

		const provider = providers[entry.provider];
		if (!provider) {
			throw new OAuthProxyError(
				"unknown_provider",
				`Provider "${entry.provider}" is no longer configured.`,
			);
		}

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

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const pathname = url.pathname.replace(/\/$/, "");

		if (request.method === "GET" && pathname.endsWith("/auth/oauth-proxy/start")) {
			const ip = resolveClientIp(request, config.trustedProxy) ?? "unknown";
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
					return jsonError(err.message, 400);
				}
				return jsonError("Failed to start OAuth proxy flow", 500);
			}
		}

		if (request.method === "GET" && pathname.endsWith("/auth/oauth-proxy/callback")) {
			const code = url.searchParams.get("code");
			const proxyState = url.searchParams.get("state");
			const errorParam = url.searchParams.get("error");

			if (errorParam) {
				// Provider returned an error, we need to redirect the mobile app to
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

export class OAuthProxyError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "OAuthProxyError";
		this.code = code;
	}
}
