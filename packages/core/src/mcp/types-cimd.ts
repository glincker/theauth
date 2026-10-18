import type { DnsResolver, SafeFetchFailure } from "./safe-fetch.js";
import type { McpClient, Result } from "./types.js";

/** How a Client ID Metadata Document host is checked before fetching. */
export type CimdResolverMode = DnsResolver | "auto" | "none";

/** Client ID Metadata Documents configuration (`McpConfig.clientIdMetadataDocuments`). Off by default. */
export interface McpCimdConfig {
	enabled: boolean;
	/** "auto" (default): node:dns when importable (Node, Bun, Deno). Without it every fetch fails closed, unless `allowedHosts` is set (then hostname rules apply and a warning is logged once). "none": hostname rules only, no resolution. Or a resolver, for example createDohResolver(). */
	resolver?: CimdResolverMode;
	/** Fetch override, for example one that pins the connection to the resolved IP. */
	fetchImpl?: typeof fetch;
	/** Exact hosts or "*.example.com" (subdomains only). When set, nothing else is fetched. */
	allowedHosts?: string[];
	/** Same pattern syntax. Checked before allowedHosts. */
	deniedHosts?: string[];
	/** Default 5120, clamped to [1024, 16384]. */
	maxBytes?: number;
	/** Default 5000, clamped to [500, 10000]. Covers headers and body. */
	timeoutMs?: number;
	/** Default 60, floor 30. */
	minCacheSeconds?: number;
	/** Default 86400, ceiling 604800. */
	maxCacheSeconds?: number;
	/** Default 3600, used when the response has no max-age. */
	defaultCacheSeconds?: number;
	/** Seconds a failed fetch is remembered before the next attempt. Default 30, clamped to [0, 300]; 0 disables the negative cache. */
	negativeCacheSeconds?: number;
	/** What happens when a document bound to an agent changes redirect_uris or token_endpoint_auth_method. Default "disable". */
	onBoundClientChange?: "disable" | "allow";
	/** Maximum fetches per registrable domain per minute (admin refresh excluded). Default 30, clamped to [1, 100000]. */
	maxFetchesPerHostPerMinute?: number;
	/** Cap on stored CIMD clients that were never consented to. Needs a store that implements `countUnconsentedCimdClients`. Default 1000. */
	maxUnconsentedClients?: number;
	/** Seconds an unconsented CIMD row is kept before a sweep may delete it. Default 86400. */
	unconsentedRetentionSeconds?: number;
	/** Fire and forget: runs in a microtask, never awaited, errors and rejected promises are swallowed. */
	onEvent?: (event: McpCimdEvent) => void | Promise<void>;
}

export type CimdRejectReason =
	| SafeFetchFailure
	| "invalid_client_id_url"
	| "host_not_allowed"
	| "blocked"
	| "rate_limited"
	| "capacity"
	| "invalid_document";

export type McpCimdEvent =
	| { type: "cimd.fetched"; clientId: string; digest: string; cacheSeconds: number }
	| { type: "cimd.rejected"; clientId: string; reason: CimdRejectReason }
	| { type: "cimd.changed"; clientId: string; fields: string[]; action: "disabled" | "allowed" }
	| { type: "cimd.blocked"; clientId: string; rule: string };

/** `disabledReason` values written by theAuth. */
export const CIMD_DISABLED_REASON_BLOCKED = "blocked";
export const CIMD_DISABLED_REASON_CHANGED_WHILE_BOUND = "cimd_changed_while_bound";

/** Facts about a client the app's consent page must show. Returned by `mcp.describeClient`. */
export type ConsentWarning =
	/** Redirect URI host is not the client_id host or a subdomain of it. */
	| "redirect_host_differs"
	/** Redirect URI is loopback: any local app can claim this client id. */
	| "localhost_redirect"
	/** client_id host contains an xn-- label. */
	| "idn_host"
	/** client_name contains a domain-like token that is not the client host. */
	| "name_mentions_other_host"
	| "client_uri_host_differs"
	/** No prior approval by this user (app supplied flag). */
	| "first_use"
	/** Redirect URI uses plain http. */
	| "http_redirect"
	/** An admin bound this client to an agent: approving gives that agent's identity to the client. */
	| "bound_to_agent"
	/** The stored document was re-read and updated in the last 24 hours. */
	| "recently_changed";

export interface ClientDescription {
	clientId: string;
	source: "cimd" | "dcr" | "preregistered";
	/** What the UI must show as the primary identity. ASCII hostname for CIMD, null otherwise. */
	verifiedHost: string | null;
	/** Self-asserted. Show it as secondary text, never alone. */
	clientName: string | null;
	logoUri: string | null;
	redirectUri: string;
	redirectHost: string;
	/** Set only by an admin binding, never by the document. */
	agentId: string | null;
	warnings: ConsentWarning[];
}

/** Design name for the consent view model. */
export type ConsentClientView = ClientDescription;

export interface McpClientBlock {
	id: string;
	kind: "url" | "host";
	value: string;
	reason: string | null;
	createdBy: string | null;
	createdAt: Date;
}

export interface McpClientBlockStore {
	/** `hosts` is the host and each parent domain, so a "host" rule covers subdomains. */
	findBlock: (url: string, hosts: string[]) => Promise<McpClientBlock | null>;
	addBlock: (block: Omit<McpClientBlock, "id" | "createdAt">) => Promise<McpClientBlock>;
	removeBlock: (id: string) => Promise<void>;
	listBlocks: () => Promise<McpClientBlock[]>;
}

/** Admin API exposed as `mcp.cimd`. */
export interface McpCimdAdmin {
	block(input: {
		kind: "url" | "host";
		value: string;
		reason?: string;
		createdBy?: string;
	}): Promise<McpClientBlock>;
	unblock(id: string): Promise<void>;
	listBlocks(): Promise<McpClientBlock[]>;
	/** Forces a fetch, ignoring the stored expiry and the negative cache. */
	refresh(clientId: string): Promise<Result<McpClient>>;
	/** Clears `disabled` and `disabledReason`. */
	enable(clientId: string): Promise<void>;
	/** The stored client including its snapshot, or null. */
	inspect(clientId: string): Promise<McpClient | null>;
}

/** Stored Client ID Metadata Document snapshot on `McpClient.cimd`. */
export interface McpClientCimdSnapshot {
	digest: string;
	fetchedAt: Date;
	expiresAt: Date;
	document: Record<string, unknown>;
}
