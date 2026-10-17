import type { JWK } from "jose";
import type { SafeFetchOptions } from "./safe-fetch.js";
import { checkFetchableUrl, safeFetchJson } from "./safe-fetch.js";
import type { McpAuthContext, McpClient } from "./types.js";

/**
 * Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
 * The authorization server fetches that URL and the document must repeat the same `client_id`, so an attacker cannot make the server trust a document by pointing a client_id at someone else's URL.
 */

/** Re-read interval when the document carries no usable Cache-Control. */
const CIMD_CACHE_MS = 60 * 60 * 1000;
const CIMD_MIN_CACHE_SECONDS = 60;
const CIMD_MAX_CACHE_SECONDS = 24 * 60 * 60;
const DEFAULT_NEGATIVE_CACHE_SECONDS = 30;
const MAX_TRACKED_CLIENTS = 1000;
/** Members that only exist on private or symmetric JWKs. */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

interface CimdState {
	/** Wall-clock time after which the stored document must be re-read. */
	refreshAt: Map<string, number>;
	/** Wall-clock time until which a failed fetch is not retried. */
	failedUntil: Map<string, number>;
}

const states = new WeakMap<object, CimdState>();

function stateFor(ctx: McpAuthContext): CimdState {
	let state = states.get(ctx);
	if (!state) {
		state = { refreshAt: new Map(), failedUntil: new Map() };
		states.set(ctx, state);
	}
	return state;
}

function prune(map: Map<string, number>): void {
	if (map.size < MAX_TRACKED_CLIENTS) return;
	const now = Date.now();
	for (const [id, at] of map) {
		if (at <= now) map.delete(id);
	}
	if (map.size >= MAX_TRACKED_CLIENTS) map.clear();
}

/**
 * Seconds a fetched document may be reused, from `Cache-Control: max-age`, clamped to [60s, 24h]. `no-store`, `no-cache` and `max-age=0` get the minimum. Absent or unparsable gives the one hour default.
 */
export function cimdCacheSeconds(cacheControl: string | undefined): number {
	const defaultSeconds = CIMD_CACHE_MS / 1000;
	if (!cacheControl) return defaultSeconds;
	const directives = cacheControl
		.toLowerCase()
		.split(",")
		.map((d) => d.trim());
	if (directives.includes("no-store") || directives.includes("no-cache")) {
		return CIMD_MIN_CACHE_SECONDS;
	}
	for (const d of directives) {
		const match = /^max-age=(\d{1,10})$/.exec(d);
		if (match?.[1] !== undefined) {
			const seconds = Number(match[1]);
			return Math.min(CIMD_MAX_CACHE_SECONDS, Math.max(CIMD_MIN_CACHE_SECONDS, seconds));
		}
	}
	return defaultSeconds;
}

export type ClientMetadataResult =
	| { ok: true; client: McpClient; cacheSeconds: number }
	| { ok: false; message: string };

function isStringArray(v: unknown): v is string[] {
	return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function validRedirectUri(uri: string): boolean {
	try {
		const u = new URL(uri);
		if (u.hash) return false;
		if (u.protocol === "https:") return true;
		return (
			u.protocol === "http:" &&
			(u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]")
		);
	} catch {
		return false;
	}
}

/** Fetch and validate the metadata document for `clientId`. Fails closed. */
export async function fetchClientMetadataDocument(
	ctx: McpAuthContext,
	clientId: string,
): Promise<ClientMetadataResult> {
	const opts = ctx.config.clientIdMetadataDocuments;
	if (!opts?.enabled) return { ok: false, message: "Client ID Metadata Documents are disabled" };

	const checked = checkFetchableUrl(clientId);
	if (!checked.ok)
		return { ok: false, message: `client_id is not a fetchable https URL: ${checked.message}` };
	if (opts.allowedHosts && !opts.allowedHosts.includes(checked.url.hostname.toLowerCase())) {
		return { ok: false, message: "client_id host is not allowed" };
	}

	const fetchOptions: SafeFetchOptions = {
		...(opts.resolver ? { resolver: opts.resolver } : {}),
		...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
	};
	const fetched = await safeFetchJson(clientId, fetchOptions);
	if (!fetched.ok) {
		return { ok: false, message: `client metadata document rejected: ${fetched.message}` };
	}

	const doc = fetched.json;
	if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
		return { ok: false, message: "client metadata document must be a JSON object" };
	}
	const d = doc as Record<string, unknown>;

	// The document must name itself. This is the core CIMD binding.
	if (d.client_id !== clientId) {
		return { ok: false, message: "client metadata document client_id does not match its URL" };
	}
	if (!isStringArray(d.redirect_uris) || d.redirect_uris.length === 0) {
		return { ok: false, message: "client metadata document needs redirect_uris" };
	}
	if (!d.redirect_uris.every(validRedirectUri)) {
		return { ok: false, message: "client metadata document has an invalid redirect_uri" };
	}
	// Shared secrets make no sense for URL-identified clients.
	if (d.client_secret !== undefined || d.client_secret_expires_at !== undefined) {
		return { ok: false, message: "client metadata document must not contain client_secret" };
	}
	const authMethod = d.token_endpoint_auth_method;
	if (authMethod !== undefined && authMethod !== "none" && authMethod !== "private_key_jwt") {
		return {
			ok: false,
			message: "only token_endpoint_auth_method none and private_key_jwt are supported",
		};
	}
	let jwks: { keys: JWK[] } | undefined;
	let jwksUri: string | undefined;
	if (authMethod === "private_key_jwt") {
		const inline = d.jwks;
		const uri = d.jwks_uri;
		if ((inline === undefined) === (uri === undefined)) {
			return { ok: false, message: "private_key_jwt needs exactly one of jwks or jwks_uri" };
		}
		if (inline !== undefined) {
			const keys =
				typeof inline === "object" && inline !== null
					? (inline as { keys?: unknown }).keys
					: undefined;
			if (
				!Array.isArray(keys) ||
				keys.length === 0 ||
				!keys.every((k) => typeof k === "object" && k !== null && !Array.isArray(k)) ||
				keys.some((k) => PRIVATE_JWK_MEMBERS.some((m) => m in (k as object)))
			) {
				return { ok: false, message: "jwks must hold public keys" };
			}
			jwks = { keys: keys as JWK[] };
		} else {
			if (typeof uri !== "string" || !checkFetchableUrl(uri).ok) {
				return { ok: false, message: "jwks_uri must be a public https URL" };
			}
			jwksUri = uri;
		}
	}
	const privateKey = authMethod === "private_key_jwt";

	const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
	const now = new Date();
	return {
		ok: true,
		client: {
			clientId,
			clientSecret: null,
			clientName: str(d.client_name),
			clientUri: str(d.client_uri),
			logoUri: str(d.logo_uri),
			redirectUris: d.redirect_uris,
			grantTypes: ["authorization_code", "refresh_token"],
			responseTypes: ["code"],
			tokenEndpointAuthMethod: privateKey ? "private_key_jwt" : "none",
			scope: str(d.scope),
			contacts: isStringArray(d.contacts) ? d.contacts : null,
			tosUri: str(d.tos_uri),
			policyUri: str(d.policy_uri),
			softwareId: str(d.software_id),
			softwareVersion: str(d.software_version),
			clientType: privateKey ? "confidential" : "public",
			disabled: false,
			userId: null,
			source: "cimd",
			...(jwks ? { jwks } : {}),
			...(jwksUri ? { jwksUri } : {}),
			createdAt: now,
			updatedAt: now,
		},
		cacheSeconds: cimdCacheSeconds(fetched.cacheControl),
	};
}

/**
 * Look a client up in storage and, when enabled, fall back to a Client ID Metadata Document for https client_ids. Resolved documents are stored so the token endpoint sees the same client.
 * URL-identified clients are re-read once their document's Cache-Control max-age (clamped to 60s..24h, default 1h) has passed, so redirect_uri changes and removals take effect. A failed refresh fails closed, and a failed fetch is remembered briefly (`negativeCacheSeconds`, default 30) so a bad or slow document is not hammered.
 */
export async function resolveClient(
	ctx: McpAuthContext,
	clientId: string,
): Promise<McpClient | null> {
	const stored = await ctx.findClient(clientId);
	const cimd = ctx.config.clientIdMetadataDocuments?.enabled === true;
	const isUrlClient = clientId.startsWith("https://");
	const state = stateFor(ctx);
	if (stored) {
		const refreshAt = state.refreshAt.get(clientId);
		const stale =
			refreshAt !== undefined
				? Date.now() >= refreshAt
				: Date.now() - stored.updatedAt.getTime() > CIMD_CACHE_MS;
		if (!(cimd && isUrlClient && stored.source === "cimd" && stale)) return stored;
	}
	if (!cimd || !isUrlClient) return null;

	const failedUntil = state.failedUntil.get(clientId);
	if (failedUntil !== undefined && Date.now() < failedUntil) return null;

	const result = await fetchClientMetadataDocument(ctx, clientId);
	if (!result.ok) {
		const negative =
			ctx.config.clientIdMetadataDocuments?.negativeCacheSeconds ?? DEFAULT_NEGATIVE_CACHE_SECONDS;
		if (negative > 0) {
			prune(state.failedUntil);
			state.failedUntil.set(clientId, Date.now() + negative * 1000);
		}
		return null;
	}
	state.failedUntil.delete(clientId);
	prune(state.refreshAt);
	state.refreshAt.set(clientId, Date.now() + result.cacheSeconds * 1000);
	await ctx.storeClient(result.client);
	return result.client;
}
