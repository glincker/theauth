import { validateCimdDocument } from "./cimd-document.js";
import { emitCimdHook, safeEventId } from "./cimd-events.js";
import { checkClientIdUrl, looksLikeCimdClientId, screenHostname } from "./cimd-url.js";
import type { SafeFetchEvent, SafeFetchFailure, SafeFetchOptions } from "./safe-fetch.js";
import { safeFetchJson } from "./safe-fetch.js";
import type { McpAuthContext, McpClient, Result } from "./types.js";
import type {
	CimdRejectReason,
	McpCimdConfig,
	McpCimdEvent,
	McpClientBlockStore,
} from "./types-cimd.js";
import { CIMD_DISABLED_REASON_CHANGED_WHILE_BOUND } from "./types-cimd.js";

/**
 * Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).
 * The authorization server fetches the client_id URL; the document must repeat that exact URL,
 * so an attacker cannot make the server trust a document by pointing a client_id at someone
 * else's URL.
 *
 * Cache semantics: freshness lives in the stored row (`client.cimd.expiresAt`), so every
 * isolate agrees and nothing depends on per isolate memory. The only per isolate state is the
 * negative cache (a retry backoff that never serves a document) and in-flight coalescing.
 */

const DEFAULT_MIN_CACHE_SECONDS = 60;
const MIN_CACHE_FLOOR_SECONDS = 30;
const DEFAULT_MAX_CACHE_SECONDS = 24 * 60 * 60;
const MAX_CACHE_CEILING_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_DEFAULT_CACHE_SECONDS = 60 * 60;
const DEFAULT_NEGATIVE_CACHE_SECONDS = 30;
const MAX_NEGATIVE_CACHE_SECONDS = 300;
const MAX_TRACKED_CLIENTS = 2048;
const MAX_TRACKED_HOSTS = 2048;
const DEFAULT_MAX_FETCHES_PER_HOST_PER_MINUTE = 30;
const DEFAULT_MAX_UNCONSENTED = 1000;
const DEFAULT_UNCONSENTED_RETENTION_SECONDS = 24 * 60 * 60;
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const GENERIC_FAILURE = "client metadata document could not be used";

export interface CimdCacheBounds {
	min: number;
	max: number;
	default: number;
}

const clamp = (n: number, lo: number, hi: number): number => Math.min(hi, Math.max(lo, n));

/** Effective cache bounds for a config: defaults applied, floors and ceilings enforced, min <= default <= max. */
export function cimdCacheBounds(cfg: McpCimdConfig | undefined): CimdCacheBounds {
	const min = clamp(
		Math.floor(cfg?.minCacheSeconds ?? DEFAULT_MIN_CACHE_SECONDS),
		MIN_CACHE_FLOOR_SECONDS,
		MAX_CACHE_CEILING_SECONDS,
	);
	const max = clamp(
		Math.floor(cfg?.maxCacheSeconds ?? DEFAULT_MAX_CACHE_SECONDS),
		min,
		MAX_CACHE_CEILING_SECONDS,
	);
	const def = clamp(
		Math.floor(cfg?.defaultCacheSeconds ?? DEFAULT_DEFAULT_CACHE_SECONDS),
		min,
		max,
	);
	return { min, max, default: def };
}

const DEFAULT_BOUNDS: CimdCacheBounds = {
	min: DEFAULT_MIN_CACHE_SECONDS,
	max: DEFAULT_MAX_CACHE_SECONDS,
	default: DEFAULT_DEFAULT_CACHE_SECONDS,
};

/**
 * Seconds a fetched document may be reused, from `Cache-Control: max-age`, clamped to the bounds (default 60s..24h). `no-store`, `no-cache` and `max-age=0` get the minimum. Absent or unparsable gives the default (1h). `s-maxage`, `Expires` and `ETag` are ignored.
 */
export function cimdCacheSeconds(
	cacheControl: string | undefined,
	bounds: CimdCacheBounds = DEFAULT_BOUNDS,
): number {
	if (!cacheControl) return bounds.default;
	const directives = cacheControl
		.toLowerCase()
		.split(",")
		.map((d) => d.trim());
	if (directives.includes("no-store") || directives.includes("no-cache")) return bounds.min;
	for (const d of directives) {
		const match = /^max-age=(\d{1,10})$/.exec(d);
		if (match?.[1] !== undefined) return clamp(Number(match[1]), bounds.min, bounds.max);
	}
	return bounds.default;
}

/** Optional context members the surface layer wires in. */
export interface CimdContextExtras {
	clientBlocks?: McpClientBlockStore;
}

type StoreWithOptions = (
	client: McpClient,
	options?: { preserveAdminState?: boolean },
) => Promise<void>;

interface NegativeEntry {
	until: number;
	/** True when the failure says nothing about the document itself (network, DNS, timeout). */
	transient: boolean;
}

interface HostWindow {
	start: number;
	count: number;
}

interface CimdState {
	/** Bounded, oldest evicted first; never cleared wholesale, so junk ids cannot flush real entries. */
	failed: Map<string, NegativeEntry>;
	inflight: Map<string, Promise<ResolveOutcome>>;
	hosts: Map<string, HostWindow>;
	lastSweep: number;
	/** One safe-fetch observer per context, so the "no resolver" notice is reported once. */
	fetchObserver: (event: SafeFetchEvent) => void;
}

const states = new WeakMap<object, CimdState>();

function stateFor(ctx: McpAuthContext): CimdState {
	let state = states.get(ctx);
	if (!state) {
		state = {
			failed: new Map(),
			inflight: new Map(),
			hosts: new Map(),
			lastSweep: Date.now(),
			fetchObserver: (event) => {
				if (event.type === "safe_fetch.resolver_unavailable") {
					try {
						ctx.logger?.warn(`[mcp-cimd] ${event.detail}`);
					} catch {
						// A broken logger must not break a fetch.
					}
				}
			},
		};
		states.set(ctx, state);
	}
	return state;
}

/** Inserts as the newest entry and evicts the oldest ones past `limit`. */
function remember<V>(map: Map<string, V>, key: string, value: V, limit: number): void {
	map.delete(key);
	map.set(key, value);
	while (map.size > limit) {
		const oldest = map.keys().next();
		if (oldest.done) break;
		map.delete(oldest.value);
	}
}

function emit(cfg: McpCimdConfig | undefined, event: McpCimdEvent): void {
	emitCimdHook(
		cfg,
		event.type === "cimd.rejected" ? { ...event, clientId: safeEventId(event.clientId) } : event,
	);
}

/** Options for every outbound fetch the CIMD feature makes (documents and JWKS). */
export function cimdFetchOptions(ctx: McpAuthContext): SafeFetchOptions {
	const cfg = ctx.config.clientIdMetadataDocuments;
	if (!cfg) return {};
	return {
		...(cfg.resolver ? { resolver: cfg.resolver } : {}),
		...(cfg.fetchImpl ? { fetchImpl: cfg.fetchImpl } : {}),
		...(cfg.maxBytes !== undefined ? { maxBytes: clamp(cfg.maxBytes, 1024, 16384) } : {}),
		...(cfg.timeoutMs !== undefined ? { timeoutMs: clamp(cfg.timeoutMs, 500, 10000) } : {}),
		// Without a resolver only an allow list still gives a full guarantee, so only then do name rules suffice.
		...(cfg.allowedHosts !== undefined ? { onResolverUnavailable: "names_only" as const } : {}),
		onEvent: stateFor(ctx).fetchObserver,
	};
}

export type ClientMetadataResult =
	| { ok: true; client: McpClient; cacheSeconds: number }
	| { ok: false; message: string; reason: CimdRejectReason };

/** Checks that need no network: URL form, host policy. */
function precheck(
	cfg: McpCimdConfig,
	clientId: string,
): { ok: true; host: string } | { ok: false; reason: CimdRejectReason } {
	const url = checkClientIdUrl(clientId);
	if (!url.ok) return { ok: false, reason: "invalid_client_id_url" };
	const screened = screenHostname(url.host, {
		...(cfg.allowedHosts ? { allowedHosts: cfg.allowedHosts } : {}),
		...(cfg.deniedHosts ? { deniedHosts: cfg.deniedHosts } : {}),
	});
	if (!screened.ok) return { ok: false, reason: screened.code };
	return { ok: true, host: url.host };
}

/** The host and each parent domain that still has two labels, so a "host" block covers subdomains. */
function hostChain(host: string): string[] {
	const labels = host.split(".");
	const out: string[] = [];
	for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."));
	return out;
}

/** Fetch and validate the metadata document for `clientId`. Fails closed, never throws. */
export async function fetchClientMetadataDocument(
	ctx: McpAuthContext,
	clientId: string,
): Promise<ClientMetadataResult> {
	const cfg = ctx.config.clientIdMetadataDocuments;
	if (!cfg?.enabled)
		return {
			ok: false,
			message: "Client ID Metadata Documents are disabled",
			reason: "invalid_client_id_url",
		};
	const bad = (reason: CimdRejectReason): ClientMetadataResult => {
		emit(cfg, { type: "cimd.rejected", clientId, reason });
		return { ok: false, message: GENERIC_FAILURE, reason };
	};
	const pre = precheck(cfg, clientId);
	if (!pre.ok) return bad(pre.reason);

	const fetched = await safeFetchJson(clientId, cimdFetchOptions(ctx));
	if (!fetched.ok) return bad(fetched.reason);

	const bounds = cimdCacheBounds(cfg);
	const cacheSeconds = cimdCacheSeconds(fetched.cacheControl, bounds);
	const validated = await validateCimdDocument(clientId, fetched.json, {
		cacheSeconds,
		hostPolicy: {
			...(cfg.deniedHosts ? { deniedHosts: cfg.deniedHosts } : {}),
			...(cfg.allowedHosts ? { allowedHosts: cfg.allowedHosts } : {}),
		},
	});
	if (!validated.ok) return bad("invalid_document");
	emit(cfg, { type: "cimd.fetched", clientId, digest: validated.digest, cacheSeconds });
	return { ok: true, client: validated.client, cacheSeconds };
}

function sameSet(a: string[], b: string[]): boolean {
	return a.length === b.length && new Set([...a, ...b]).size === a.length;
}

/**
 * Merge a fresh fetch into the stored row. Admin state (`disabled`, `disabledReason`, `agentId`, `createdAt`) always comes from the stored row. A bound client whose redirect URIs or auth method change is disabled (unless `onBoundClientChange` is "allow").
 */
function mergeRefresh(cfg: McpCimdConfig, stored: McpClient, fresh: McpClient): McpClient {
	const merged: McpClient = {
		...fresh,
		disabled: stored.disabled,
		disabledReason: stored.disabledReason ?? null,
		agentId: stored.agentId ?? null,
		userId: stored.userId,
		createdAt: stored.createdAt,
	};
	if (stored.agentId) {
		const fields: string[] = [];
		if (!sameSet(stored.redirectUris, fresh.redirectUris)) fields.push("redirect_uris");
		if (stored.tokenEndpointAuthMethod !== fresh.tokenEndpointAuthMethod) {
			fields.push("token_endpoint_auth_method");
		}
		if (fields.length > 0) {
			const disable = (cfg.onBoundClientChange ?? "disable") === "disable";
			if (disable && !stored.disabled) {
				merged.disabled = true;
				merged.disabledReason = CIMD_DISABLED_REASON_CHANGED_WHILE_BOUND;
			}
			emit(cfg, {
				type: "cimd.changed",
				clientId: stored.clientId,
				fields,
				action: disable ? "disabled" : "allowed",
			});
		}
	}
	return merged;
}

type ResolveOutcome = { client: McpClient | null; reason?: CimdRejectReason };

const TRANSIENT_FAILURES: ReadonlySet<CimdRejectReason> = new Set<SafeFetchFailure>([
	"timeout",
	"network_error",
	"dns_failure",
]);

/** Fixed window per registrable domain (last two labels), so random subdomains share one budget. Returns false when the host is over budget. */
function takeHostToken(state: CimdState, cfg: McpCimdConfig, host: string): boolean {
	const limit = clamp(
		Math.floor(cfg.maxFetchesPerHostPerMinute ?? DEFAULT_MAX_FETCHES_PER_HOST_PER_MINUTE),
		1,
		100_000,
	);
	const key = host.split(".").slice(-2).join(".");
	const now = Date.now();
	const current = state.hosts.get(key);
	if (current && now - current.start < 60_000) {
		if (current.count >= limit) return false;
		current.count++;
		return true;
	}
	remember(state.hosts, key, { start: now, count: 1 }, MAX_TRACKED_HOSTS);
	return true;
}

/** True when a brand new CIMD row may be stored. Sweeps stale unconsented rows when at the cap, and at most hourly otherwise. */
async function hasCapacity(
	ctx: McpAuthContext,
	cfg: McpCimdConfig,
	state: CimdState,
): Promise<boolean> {
	const count = ctx.countUnconsentedCimdClients;
	if (!count) return true;
	const max = clamp(Math.floor(cfg.maxUnconsentedClients ?? DEFAULT_MAX_UNCONSENTED), 1, 1_000_000);
	const retention =
		(cfg.unconsentedRetentionSeconds ?? DEFAULT_UNCONSENTED_RETENTION_SECONDS) * 1000;
	const sweep = async (): Promise<void> => {
		state.lastSweep = Date.now();
		try {
			await ctx.deleteStaleUnconsentedCimdClients?.(new Date(Date.now() - retention));
		} catch {
			// A failed sweep only means the cap is enforced against more rows.
		}
	};
	try {
		if (Date.now() - state.lastSweep > SWEEP_INTERVAL_MS) await sweep();
		if ((await count()) < max) return true;
		await sweep();
		return (await count()) < max;
	} catch {
		return true;
	}
}

async function fetchAndStore(
	ctx: McpAuthContext,
	cfg: McpCimdConfig,
	clientId: string,
	stored: McpClient | null,
	options: { admin?: boolean } = {},
): Promise<ResolveOutcome> {
	const state = stateFor(ctx);
	if (!options.admin) {
		const host = checkClientIdUrl(clientId);
		if (host.ok && !takeHostToken(state, cfg, host.host)) {
			emit(cfg, { type: "cimd.rejected", clientId, reason: "rate_limited" });
			return { client: staleFallback(cfg, stored, true), reason: "rate_limited" };
		}
		if (!stored && !(await hasCapacity(ctx, cfg, state))) {
			emit(cfg, { type: "cimd.rejected", clientId, reason: "capacity" });
			return { client: null, reason: "capacity" };
		}
	}
	const result = await fetchClientMetadataDocument(ctx, clientId);
	if (!result.ok) {
		const seconds = clamp(
			cfg.negativeCacheSeconds ?? DEFAULT_NEGATIVE_CACHE_SECONDS,
			0,
			MAX_NEGATIVE_CACHE_SECONDS,
		);
		if (seconds > 0) {
			remember(
				state.failed,
				clientId,
				{
					until: Date.now() + seconds * 1000,
					transient: TRANSIENT_FAILURES.has(result.reason),
				},
				MAX_TRACKED_CLIENTS,
			);
		}
		return {
			client: staleFallback(cfg, stored, TRANSIENT_FAILURES.has(result.reason)),
			reason: result.reason,
		};
	}
	state.failed.delete(clientId);
	const merged = stored ? mergeRefresh(cfg, stored, result.client) : result.client;
	await (ctx.storeClient as StoreWithOptions)(merged, { preserveAdminState: true });
	return { client: merged };
}

/** After a transient refresh failure the old snapshot keeps serving until `fetchedAt + maxCacheSeconds`. Anything else fails closed. */
function staleFallback(
	cfg: McpCimdConfig,
	stored: McpClient | null,
	transient: boolean,
): McpClient | null {
	if (!stored || !transient || !stored.cimd) return null;
	const hardExpiry = stored.cimd.fetchedAt.getTime() + cimdCacheBounds(cfg).max * 1000;
	return Date.now() < hardExpiry ? stored : null;
}

function coalesced(
	ctx: McpAuthContext,
	cfg: McpCimdConfig,
	clientId: string,
	stored: McpClient | null,
): Promise<ResolveOutcome> {
	const state = stateFor(ctx);
	const running = state.inflight.get(clientId);
	if (running) return running;
	const promise = fetchAndStore(ctx, cfg, clientId, stored).finally(() => {
		state.inflight.delete(clientId);
	});
	state.inflight.set(clientId, promise);
	return promise;
}

/** True when the stored snapshot is still fresh. Rows without a snapshot (written by older versions) age from `updatedAt`. */
function isFresh(cfg: McpCimdConfig, stored: McpClient): boolean {
	const expires =
		stored.cimd?.expiresAt.getTime() ??
		stored.updatedAt.getTime() + cimdCacheBounds(cfg).default * 1000;
	return Date.now() < expires;
}

/** Returns a rejection when the URL, host policy or block store forbids this client id. */
async function gate(
	ctx: McpAuthContext,
	cfg: McpCimdConfig,
	clientId: string,
): Promise<CimdRejectReason | null> {
	const pre = precheck(cfg, clientId);
	if (!pre.ok) {
		emit(cfg, { type: "cimd.rejected", clientId, reason: pre.reason });
		return pre.reason;
	}
	const blocks = (ctx as McpAuthContext & CimdContextExtras).clientBlocks;
	if (blocks) {
		const block = await blocks.findBlock(clientId, hostChain(pre.host));
		if (block) {
			emit(cfg, { type: "cimd.blocked", clientId, rule: `${block.kind}:${block.value}` });
			return "blocked";
		}
	}
	return null;
}

/**
 * Look a client up in storage and, when enabled, fall back to a Client ID Metadata Document for https client_ids. Resolved documents are stored so the token endpoint sees the same client.
 * Order: stored non-CIMD row wins; then URL form, host policy and block store; a disabled stored row is returned without a fetch; a fresh stored snapshot is returned; a recent failure is not retried; otherwise one coalesced fetch.
 */
export async function resolveClient(
	ctx: McpAuthContext,
	clientId: string,
): Promise<McpClient | null> {
	const found = await ctx.findClient(clientId);
	// A store with a case insensitive collation can hand back another client's row for a case
	// variant of the id. Never serve it, and never fetch and store over it.
	if (found && found.clientId !== clientId) return null;
	const stored = found;
	if (stored && stored.source !== "cimd") return stored;
	const cfg = ctx.config.clientIdMetadataDocuments;
	// Turning the feature off is a kill switch: stored CIMD rows stop serving too.
	if (stored?.source === "cimd" && !cfg?.enabled) return null;
	if (!cfg?.enabled || !looksLikeCimdClientId(clientId)) return stored;

	if ((await gate(ctx, cfg, clientId)) !== null) return null;
	if (stored?.disabled) return stored;
	if (stored && isFresh(cfg, stored)) return stored;

	const failed = stateFor(ctx).failed.get(clientId);
	if (failed && Date.now() < failed.until) {
		return staleFallback(cfg, stored, failed.transient);
	}
	return (await coalesced(ctx, cfg, clientId, stored)).client;
}

/** Admin refresh: ignores the stored expiry and the negative cache, still honors blocks and host policy. Never undoes `disabled`. */
export async function refreshCimdClient(
	ctx: McpAuthContext,
	clientId: string,
): Promise<Result<McpClient>> {
	const cfg = ctx.config.clientIdMetadataDocuments;
	const error = (message: string): Result<McpClient> => ({
		success: false,
		error: { code: "INVALID_CLIENT", message },
	});
	if (!cfg?.enabled || !looksLikeCimdClientId(clientId)) {
		return error("Client ID Metadata Documents are not enabled for this client");
	}
	const stored = await ctx.findClient(clientId);
	if (stored && stored.clientId !== clientId) return error(GENERIC_FAILURE);
	if (stored && stored.source !== "cimd") return error("client is not a metadata document client");
	if ((await gate(ctx, cfg, clientId)) !== null) return error(GENERIC_FAILURE);
	stateFor(ctx).failed.delete(clientId);
	const fetched = await fetchAndStore(ctx, cfg, clientId, stored, { admin: true });
	// A refresh that fell back to the old snapshot is still a failed refresh for the admin.
	if (!fetched.client || fetched.reason) return error(GENERIC_FAILURE);
	return { success: true, data: fetched.client };
}
