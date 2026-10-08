import type { SafeFetchOptions } from "./safe-fetch.js";
import { checkFetchableUrl, safeFetchJson } from "./safe-fetch.js";
import type { McpAuthContext, McpClient } from "./types.js";

/**
 * Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
 *
 * The client_id is an https URL. The authorization server fetches that URL and
 * the document must repeat the same `client_id`, so an attacker cannot make the
 * server trust a document by pointing a client_id at someone else's URL.
 */

const CIMD_CACHE_MS = 60 * 60 * 1000;

export type ClientMetadataResult = { ok: true; client: McpClient } | { ok: false; message: string };

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
	if (authMethod !== undefined && authMethod !== "none") {
		return { ok: false, message: "only token_endpoint_auth_method none is supported" };
	}

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
			tokenEndpointAuthMethod: "none",
			scope: str(d.scope),
			contacts: isStringArray(d.contacts) ? d.contacts : null,
			tosUri: str(d.tos_uri),
			policyUri: str(d.policy_uri),
			softwareId: str(d.software_id),
			softwareVersion: str(d.software_version),
			clientType: "public",
			disabled: false,
			userId: null,
			source: "cimd",
			createdAt: now,
			updatedAt: now,
		},
	};
}

/**
 * Look a client up in storage and, when enabled, fall back to a Client ID
 * Metadata Document for https client_ids. Resolved documents are stored so the
 * token endpoint sees the same client.
 */
export async function resolveClient(
	ctx: McpAuthContext,
	clientId: string,
): Promise<McpClient | null> {
	const stored = await ctx.findClient(clientId);
	const cimd = ctx.config.clientIdMetadataDocuments?.enabled === true;
	const isUrlClient = clientId.startsWith("https://");
	if (stored) {
		// URL-identified clients are cached, but the document is re-read after an
		// hour so redirect_uri changes (and removals) take effect. A failed
		// refresh fails closed.
		const stale = Date.now() - stored.updatedAt.getTime() > CIMD_CACHE_MS;
		if (!(cimd && isUrlClient && stored.source === "cimd" && stale)) return stored;
	}
	if (!cimd || !isUrlClient) return null;
	const result = await fetchClientMetadataDocument(ctx, clientId);
	if (!result.ok) return null;
	await ctx.storeClient(result.client);
	return result.client;
}
