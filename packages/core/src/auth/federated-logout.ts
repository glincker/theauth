/**
 * Federated logout for OpenID Connect.
 *
 * Three pieces, each usable alone:
 *
 * - RP-initiated logout (OIDC RP-Initiated Logout 1.0). `buildEndSessionUrl`
 *   sends your user to the IdP's `end_session_endpoint`. `createEndSessionHandler`
 *   is the other side: an OP endpoint that validates `id_token_hint` and
 *   `post_logout_redirect_uri` and ends the session.
 * - Back-channel logout, receiving (OIDC Back-Channel Logout 1.0).
 *   `createBackChannelLogoutReceiver` verifies a `logout_token` POSTed by the
 *   IdP and tells you which `sub` or `sid` to sign out.
 * - Back-channel logout, sending. `sendBackChannelLogout` signs a logout token
 *   and POSTs it to a client's `backchannel_logout_uri`.
 *
 * Nothing here is wired in by default.
 */

import type { JWTVerifyGetKey, JWTVerifyOptions, JWTVerifyResult } from "jose";
import { decodeJwt, jwtVerify, SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { DnsResolver } from "../mcp/safe-fetch.js";
import { checkFetchableUrl, defaultDnsResolver, isBlockedIp } from "../mcp/safe-fetch.js";
import type { Result } from "../mcp/types.js";

export const BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

type VerifyKey = CryptoKey | Uint8Array | JWTVerifyGetKey;

function fail<T>(code: string, message: string): Result<T> {
	return { success: false, error: { code, message } };
}

function noStore(init: ResponseInit & { body?: string }): Response {
	const headers = new Headers(init.headers);
	headers.set("Cache-Control", "no-store");
	return new Response(init.body ?? null, { status: init.status, headers });
}

async function verifyWith(
	token: string,
	key: VerifyKey,
	options: JWTVerifyOptions,
): Promise<JWTVerifyResult> {
	// jose types the static-key and key-resolver forms as separate overloads, so a
	// static key is wrapped in a resolver to reach a single call. Verification is identical.
	const getKey: JWTVerifyGetKey = typeof key === "function" ? key : async () => key;
	return jwtVerify(token, getKey, options);
}

// ---------------------------------------------------------------------------
// RP-initiated logout: building the request
// ---------------------------------------------------------------------------

export interface EndSessionUrlParams {
	idTokenHint?: string;
	postLogoutRedirectUri?: string;
	state?: string;
	clientId?: string;
	logoutHint?: string;
	uiLocales?: string;
}

/**
 * Build the URL that sends the user agent to the IdP's end session endpoint.
 * `clientId` is required by some IdPs when `idTokenHint` is absent. The
 * endpoint must be https (or http on localhost for development).
 */
export function buildEndSessionUrl(
	endSessionEndpoint: string,
	params: EndSessionUrlParams,
): Result<string> {
	let url: URL;
	try {
		url = new URL(endSessionEndpoint);
	} catch {
		return fail("INVALID_ENDPOINT", "end_session_endpoint is not a valid URL.");
	}
	const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
	if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
		return fail("INVALID_ENDPOINT", "end_session_endpoint must use https.");
	}
	if (params.postLogoutRedirectUri && !params.idTokenHint && !params.clientId) {
		return fail(
			"MISSING_HINT",
			"postLogoutRedirectUri needs idTokenHint or clientId so the IdP can check it.",
		);
	}
	const set = (k: string, v: string | undefined): void => {
		if (v) url.searchParams.set(k, v);
	};
	set("id_token_hint", params.idTokenHint);
	set("post_logout_redirect_uri", params.postLogoutRedirectUri);
	set("state", params.state);
	set("client_id", params.clientId);
	set("logout_hint", params.logoutHint);
	set("ui_locales", params.uiLocales);
	return { success: true, data: url.toString() };
}

// ---------------------------------------------------------------------------
// RP-initiated logout: the OP endpoint
// ---------------------------------------------------------------------------

export interface LogoutClient {
	/** Exact-match allowlist for `post_logout_redirect_uri`. */
	postLogoutRedirectUris: string[];
}

export interface EndSessionContext {
	request: Request;
	/** Verified `sub` from `id_token_hint`, when one was supplied. */
	sub?: string;
	/** Verified `sid` from `id_token_hint`. */
	sid?: string;
	/** Client the request is for (from the hint audience or `client_id`). */
	clientId?: string;
}

export interface EndSessionHandlerConfig {
	/** This provider's issuer. `id_token_hint` must carry it. */
	issuer: string;
	/** Key material that verifies tokens this provider issued. */
	verificationKey: VerifyKey;
	/** Look up a registered client. Return `null` when unknown. */
	getClient: (clientId: string) => Promise<LogoutClient | null>;
	/** End the provider session. Called once, after validation. */
	endSession: (ctx: EndSessionContext) => Promise<void>;
	/** Where to send the user when no valid `post_logout_redirect_uri` applies. */
	defaultRedirectUri?: string;
	/** Accepted signing algorithms for `id_token_hint`. Default `["RS256","ES256","EdDSA"]`. */
	algorithms?: string[];
}

export interface EndSessionHandler {
	handleRequest(request: Request): Promise<Response>;
}

/**
 * OP-side end session endpoint. Accepts GET (query) and POST (form).
 *
 * An expired `id_token_hint` is fine (the spec says so), a forged one is not.
 * `post_logout_redirect_uri` is only honored on exact match against the
 * client's registered list, and only when the client is known from a verified
 * hint or a `client_id` that resolves. Anything else ends the session and
 * shows `defaultRedirectUri` or a plain 200.
 */
export function createEndSessionHandler(config: EndSessionHandlerConfig): EndSessionHandler {
	const algorithms = config.algorithms ?? ["RS256", "ES256", "EdDSA"];

	async function readParams(request: Request): Promise<URLSearchParams | null> {
		if (request.method === "GET") return new URL(request.url).searchParams;
		if (request.method === "POST") {
			try {
				return new URLSearchParams(await request.text());
			} catch {
				return null;
			}
		}
		return null;
	}

	async function handleRequest(request: Request): Promise<Response> {
		const params = await readParams(request);
		if (!params) {
			return noStore({ status: 405, headers: { Allow: "GET, POST" } });
		}
		const hint = params.get("id_token_hint");
		const postLogout = params.get("post_logout_redirect_uri");
		const state = params.get("state");
		let clientId = params.get("client_id") ?? undefined;
		let sub: string | undefined;
		let sid: string | undefined;

		if (hint) {
			try {
				const { payload } = await verifyWith(hint, config.verificationKey, {
					issuer: config.issuer,
					algorithms,
					// Expired hints are valid for logout. Ten years of tolerance
					// covers every realistic token lifetime.
					clockTolerance: 60 * 60 * 24 * 3650,
				});
				sub = typeof payload.sub === "string" ? payload.sub : undefined;
				sid = typeof payload.sid === "string" ? payload.sid : undefined;
				const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
				if (clientId && aud.length > 0 && !aud.includes(clientId)) {
					return noStore({
						status: 400,
						body: JSON.stringify({
							error: "invalid_request",
							error_description: "client_id does not match id_token_hint",
						}),
						headers: { "Content-Type": "application/json" },
					});
				}
				clientId = clientId ?? aud[0];
			} catch {
				return noStore({
					status: 400,
					body: JSON.stringify({
						error: "invalid_request",
						error_description: "id_token_hint is invalid",
					}),
					headers: { "Content-Type": "application/json" },
				});
			}
		}

		let redirect: string | null = null;
		if (postLogout) {
			if (!clientId) {
				return noStore({
					status: 400,
					body: JSON.stringify({
						error: "invalid_request",
						error_description: "post_logout_redirect_uri requires id_token_hint or client_id",
					}),
					headers: { "Content-Type": "application/json" },
				});
			}
			const client = await config.getClient(clientId);
			if (!client?.postLogoutRedirectUris.includes(postLogout)) {
				return noStore({
					status: 400,
					body: JSON.stringify({
						error: "invalid_request",
						error_description: "post_logout_redirect_uri is not registered",
					}),
					headers: { "Content-Type": "application/json" },
				});
			}
			redirect = postLogout;
		}

		await config.endSession({ request, sub, sid, clientId });

		const target = redirect ?? config.defaultRedirectUri ?? null;
		if (!target) {
			return noStore({
				status: 200,
				body: JSON.stringify({ status: "logged_out" }),
				headers: { "Content-Type": "application/json" },
			});
		}
		const location = new URL(target);
		if (redirect && state) location.searchParams.set("state", state);
		return noStore({ status: 302, headers: { Location: location.toString() } });
	}

	return { handleRequest };
}

// ---------------------------------------------------------------------------
// Back-channel logout: receiving
// ---------------------------------------------------------------------------

export interface LogoutTokenClaims {
	iss: string;
	sub?: string;
	sid?: string;
	jti: string;
	iat: number;
}

export interface LogoutReplayStore {
	/**
	 * Record a `jti`. Resolve `true` if it is new, `false` if it was seen
	 * before. Use a shared store (Redis, KV) when you run several instances.
	 */
	markSeen(jti: string, ttlSeconds: number): Promise<boolean>;
}

export interface BackChannelLogoutReceiverConfig {
	/** Issuer you trust logout tokens from. */
	issuer: string;
	/** Your client id at that IdP (the expected `aud`). */
	clientId: string;
	/** Verification key or JWKS resolver (`createRemoteJWKSet`). */
	verificationKey: VerifyKey;
	/** Sign the user out. Throw to make the endpoint answer 400. */
	onLogout: (claims: LogoutTokenClaims) => Promise<void>;
	/** Accepted algorithms. Default `["RS256","ES256","EdDSA"]`. */
	algorithms?: string[];
	/** How old `iat` may be, in seconds. Default 120. */
	maxAgeSeconds?: number;
	/** Replay protection. Defaults to a per-process in-memory store. */
	replayStore?: LogoutReplayStore;
}

export interface BackChannelLogoutReceiver {
	verifyLogoutToken(token: string): Promise<Result<LogoutTokenClaims>>;
	/** POST handler for your `backchannel_logout_uri`. */
	handleRequest(request: Request): Promise<Response>;
}

function createMemoryReplayStore(): LogoutReplayStore {
	const seen = new Map<string, number>();
	return {
		async markSeen(jti, ttlSeconds) {
			const now = Date.now();
			for (const [key, expiry] of seen) if (expiry <= now) seen.delete(key);
			if (seen.has(jti)) return false;
			seen.set(jti, now + ttlSeconds * 1000);
			return true;
		},
	};
}

export function createBackChannelLogoutReceiver(
	config: BackChannelLogoutReceiverConfig,
): BackChannelLogoutReceiver {
	const algorithms = config.algorithms ?? ["RS256", "ES256", "EdDSA"];
	const maxAge = config.maxAgeSeconds ?? 120;
	const replay = config.replayStore ?? createMemoryReplayStore();

	async function verifyLogoutToken(token: string): Promise<Result<LogoutTokenClaims>> {
		let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
		try {
			const verified = await verifyWith(token, config.verificationKey, {
				issuer: config.issuer,
				audience: config.clientId,
				algorithms,
				maxTokenAge: `${maxAge}s`,
			});
			if (verified.protectedHeader.typ && verified.protectedHeader.typ.toLowerCase() === "jwt") {
				return fail("INVALID_LOGOUT_TOKEN", "typ must not be JWT for a logout token.");
			}
			payload = verified.payload;
		} catch (err) {
			return fail(
				"INVALID_LOGOUT_TOKEN",
				err instanceof Error ? err.message : "Logout token verification failed.",
			);
		}
		const events = payload.events;
		if (!events || typeof events !== "object" || !(BACKCHANNEL_LOGOUT_EVENT in events)) {
			return fail("INVALID_LOGOUT_TOKEN", "Missing backchannel-logout event.");
		}
		if ("nonce" in payload) return fail("INVALID_LOGOUT_TOKEN", "nonce must not be present.");
		const sub = typeof payload.sub === "string" ? payload.sub : undefined;
		const sid = typeof payload.sid === "string" ? payload.sid : undefined;
		if (!sub && !sid) return fail("INVALID_LOGOUT_TOKEN", "sub or sid is required.");
		if (typeof payload.jti !== "string" || !payload.jti) {
			return fail("INVALID_LOGOUT_TOKEN", "jti is required.");
		}
		if (typeof payload.iat !== "number") return fail("INVALID_LOGOUT_TOKEN", "iat is required.");
		if (!(await replay.markSeen(payload.jti, maxAge * 2))) {
			return fail("INVALID_LOGOUT_TOKEN", "Logout token already used.");
		}
		return {
			success: true,
			data: { iss: config.issuer, sub, sid, jti: payload.jti, iat: payload.iat },
		};
	}

	async function handleRequest(request: Request): Promise<Response> {
		const bad = (description: string): Response =>
			noStore({
				status: 400,
				body: JSON.stringify({ error: "invalid_request", error_description: description }),
				headers: { "Content-Type": "application/json" },
			});
		if (request.method !== "POST") {
			return noStore({ status: 405, headers: { Allow: "POST" } });
		}
		if (
			!(request.headers.get("content-type") ?? "").includes("application/x-www-form-urlencoded")
		) {
			return bad("Content-Type must be application/x-www-form-urlencoded");
		}
		const token = new URLSearchParams(await request.text()).get("logout_token");
		if (!token) return bad("logout_token is required");
		const result = await verifyLogoutToken(token);
		if (!result.success) return bad(result.error.message);
		try {
			await config.onLogout(result.data);
		} catch {
			return bad("logout could not be processed");
		}
		return noStore({ status: 200 });
	}

	return { verifyLogoutToken, handleRequest };
}

// ---------------------------------------------------------------------------
// Back-channel logout: sending
// ---------------------------------------------------------------------------

export interface SendBackChannelLogoutParams {
	issuer: string;
	/** Client id of the receiving RP (becomes `aud`). */
	clientId: string;
	/** The RP's registered `backchannel_logout_uri`. */
	backchannelLogoutUri: string;
	sub?: string;
	sid?: string;
	signingKey: CryptoKey | Uint8Array;
	alg: string;
	kid?: string;
	/** Token lifetime in seconds. Default 120. */
	ttlSeconds?: number;
	/** Request timeout in ms. Default 5000. */
	timeoutMs?: number;
	/** Fetch override, e.g. one pinned to a validated address. */
	fetchImpl?: typeof fetch;
	/** DNS resolver for the private-address check. */
	resolver?: DnsResolver;
	/** Skip the https and private network checks. Development only. */
	allowInsecure?: boolean;
}

/**
 * Sign a logout token and deliver it. Never throws. Fails closed on non-https
 * URLs and hosts that resolve to private addresses. Does not follow redirects.
 */
export async function sendBackChannelLogout(
	params: SendBackChannelLogoutParams,
): Promise<Result<{ status: number }>> {
	if (!params.sub && !params.sid) return fail("INVALID_REQUEST", "sub or sid is required.");

	if (!params.allowInsecure) {
		const checked = checkFetchableUrl(params.backchannelLogoutUri);
		if (!checked.ok) return fail("UNSAFE_URL", checked.message);
		try {
			const addresses = await (params.resolver ?? defaultDnsResolver)(checked.url.hostname);
			if (addresses.length === 0 || addresses.some(isBlockedIp)) {
				return fail("UNSAFE_URL", "host resolves to a non-public address");
			}
		} catch {
			return fail("UNSAFE_URL", "host could not be resolved");
		}
	}

	const now = Math.floor(Date.now() / 1000);
	const token = await new SignJWT({
		events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
		...(params.sub ? { sub: params.sub } : {}),
		...(params.sid ? { sid: params.sid } : {}),
	})
		.setProtectedHeader({
			alg: params.alg,
			typ: "logout+jwt",
			...(params.kid ? { kid: params.kid } : {}),
		})
		.setIssuer(params.issuer)
		.setAudience(params.clientId)
		.setIssuedAt(now)
		.setExpirationTime(now + (params.ttlSeconds ?? 120))
		.setJti(generateId())
		.sign(params.signingKey);

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), params.timeoutMs ?? 5000);
	try {
		const res = await (params.fetchImpl ?? fetch)(params.backchannelLogoutUri, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ logout_token: token }).toString(),
			redirect: "manual",
			signal: controller.signal,
		});
		if (res.status >= 200 && res.status < 300) {
			return { success: true, data: { status: res.status } };
		}
		return fail("DELIVERY_FAILED", `RP answered ${res.status}`);
	} catch {
		return fail("DELIVERY_FAILED", "RP unreachable or timed out");
	} finally {
		clearTimeout(timer);
	}
}

/** Decode a logout token without verifying it. For logs and tests only. */
export function peekLogoutToken(token: string): Record<string, unknown> | null {
	try {
		return decodeJwt(token) as Record<string, unknown>;
	} catch {
		return null;
	}
}
