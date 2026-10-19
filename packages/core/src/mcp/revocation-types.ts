// Contract for MCP tokens bound to their delegation (design F1).
// Types plus the few constants the design names. No runtime logic lives here.

import type { McpActorClaim, McpJtiDenylist, Result } from "./types.js";

// Binding claim

/** Name of the private JWT claim that carries the delegation binding. */
export const MCP_DELEGATION_CLAIM = "theauth_dlg";

/** Current version of the `theauth_dlg` claim. Validators refuse any other value. */
export const MCP_DELEGATION_BINDING_VERSION = 1;

/**
 * Private claim on exchanged tokens: the jtis of the subject token lineage, root first (the direct
 * parent last). A revoked ancestor denies the child. A sibling of `theauth_dlg` so unbound exchanged
 * tokens carry it too; validators that predate it ignore it.
 */
export const MCP_PARENT_JTI_CLAIM = "theauth_pjti";

/** Most ancestor jtis a token may carry. Longer or malformed lists make the token invalid. */
export const MCP_PARENT_JTI_MAX = 32;

/** Private claim `theauth_dlg`: what this token's authority rests on. Signed, so never trusted from anywhere else. */
export interface McpDelegationBinding {
	/** Claim version. Always 1; a token with another version is invalid. */
	v: typeof MCP_DELEGATION_BINDING_VERSION;
	/** Agent ids on the authority path, root first. Every one must stay `active` and unexpired. */
	agt: string[];
	/** `theauth_delegation_chains.id` for each consecutive agent pair in `agt` (length agt.length - 1, may be 0). */
	lnk: string[];
}

// Freshness contract

/** How a resource server validation learns about revocation. Introspection and the token endpoint are always live. */
export type McpFreshnessMode = "live" | "cached" | "offline";

/** Mode names, for config parsing (env `THEAUTH_MCP_REVOCATION_MODE`). */
export const MCP_FRESHNESS_MODES: readonly McpFreshnessMode[] = ["live", "cached", "offline"];

/** Default mode when `createMcpModule` gets `auth` (a shared database). */
export const MCP_DEFAULT_FRESHNESS_MODE_WITH_DB: McpFreshnessMode = "live";

/** Default mode without a database (custom stores): nothing shared to read. */
export const MCP_DEFAULT_FRESHNESS_MODE_WITHOUT_DB: McpFreshnessMode = "offline";

/** Defaults the design fixes. Each can be overridden by config or by the env var named on the config field. */
export const MCP_REVOCATION_DEFAULTS = {
	maxStalenessMs: 5000,
	pollIntervalMs: 1000,
	cacheMax: 10000,
	introspectionMaxRequestsPerMinute: 600,
	/** Introspected `token` values longer than this are inactive without any crypto. */
	introspectionMaxTokenLength: 8192,
	/** Prune at most this many revocation rows per run. */
	pruneLimit: 500,
} as const;

export interface McpRevocationConfig {
	/** Default "live" when createMcpModule gets `auth` (a database), else "offline". Env THEAUTH_MCP_REVOCATION_MODE. */
	mode?: McpFreshnessMode;
	/** cached: hard upper bound on staleness. Default 5000. Env THEAUTH_MCP_REVOCATION_MAX_STALENESS_MS. */
	maxStalenessMs?: number;
	/** cached: how often an instance checks the revocation table fingerprint. Default 1000. Env THEAUTH_MCP_REVOCATION_POLL_MS. */
	pollIntervalMs?: number;
	/** cached: max entries. Default 10000. Env THEAUTH_MCP_REVOCATION_CACHE_MAX. */
	cacheMax?: number;
	/** Refuse token exchange when actors resolve to no agent row (no unbound delegated tokens). Default false. */
	requireBoundChain?: boolean;
	/** `session.revokeAll(userId)` also revokes that user's MCP tokens. Default true. */
	revokeOnSignOutEverywhere?: boolean;
	/** Clock skew allowance (ms) for `sub` and `client` watermarks written by other instances. Default 0. Env THEAUTH_MCP_REVOCATION_SKEW_MS. */
	clockSkewMs?: number;
	/** Minimum gap (ms) between opportunistic prunes of expired denylist rows, per instance. Default 60000. Env THEAUTH_MCP_REVOCATION_PRUNE_INTERVAL_MS. */
	pruneIntervalMs?: number;
	/** Called after every revocation is recorded (wire `sharedSignals().bridge.onMcpRevocation`). Errors swallowed. */
	onRevoked?: (event: McpRevocationEvent) => void | Promise<void>;
}

/** Why a token is inactive. Reported to entitled introspection callers and in `details.revocation`. */
export type McpInactiveReason =
	| "expired"
	| "revoked"
	| "subject_revoked"
	| "client_revoked"
	| "delegation_revoked"
	| "delegation_expired"
	| "agent_revoked"
	| "agent_expired"
	| "invalid";

/** Outcome of checking a binding against the delegation and agent rows. */
export type McpBindingVerdict =
	| {
			live: true;
			/** Earliest expiry on the path (links, agents). A cached live verdict never outlives it. */
			validUntil: Date;
	  }
	| {
			live: false;
			/** Why the authority is gone. */
			reason: McpInactiveReason;
			/** The link or agent id that failed. Server side only, never in a 401 body. */
			id: string;
	  };

/** A live delegation link found at mint time. */
export interface McpLiveLink {
	/** `theauth_delegation_chains.id`, written into `lnk`. */
	id: string;
	/** Caps the minted token's `exp`. */
	expiresAt: Date;
}

/** An agent row as seen at mint time. */
export interface McpBindingAgent {
	/** Only "active" agents may appear in a binding. */
	status: string;
	/** Caps the minted token's `exp`; null means no expiry. */
	expiresAt: Date | null;
	/** Owning user. A token `sub` equal to the root agent's owner needs no link for the first hop. */
	ownerId: string;
}

/** A live inbound delegation link, for walking an agent's authority path up to its root. */
export interface McpInboundLink {
	/** `theauth_delegation_chains.id`. */
	id: string;
	/** The delegating agent. */
	from: string;
	expiresAt: Date;
}

/** A token exchange refused because the subject is not entitled to an agent. Ids only, never a token. */
export interface McpBindingDenial {
	/** The agent the subject is not entitled to (the acting agent of the refused child). */
	agentId: string;
	/** The token `sub` that asked for it. */
	subject: string;
	/** The client that presented the exchange. */
	clientId: string;
	/** The refused authority path, root first. */
	agt: string[];
	reason: string;
}

/** Reads the delegation and agent rows a binding names. Source of truth for live checks. */
export interface McpBindingStore {
	/** At most 3 indexed queries: chains by id IN, agents by id IN, liveness of agt[0] upstream. */
	check(binding: McpDelegationBinding, now: Date): Promise<McpBindingVerdict>;
	/** Earliest created live link from -> to (status active, unexpired, linkState live), or null. */
	findLiveLink(from: string, to: string, now: Date): Promise<McpLiveLink | null>;
	/** Agent rows that exist among `ids`, with status and expiry (for mint time resolution and caps). */
	agents(ids: string[]): Promise<Map<string, McpBindingAgent>>;
	/**
	 * Live inbound links to `to` (active, unexpired, delegator live), earliest created first. Used to
	 * name an agent's authority path up to its root at mint time. Optional: without it a token names
	 * only the agents it resolved, and the root's upstream is checked by `check` alone.
	 */
	liveInbound?(to: string, now: Date): Promise<McpInboundLink[]>;
	/** Record a refused exchange in the audit log. Optional, best effort: errors are swallowed. */
	auditDenial?(denial: McpBindingDenial): Promise<void>;
}

/** Result of resolving a binding at mint time (token exchange and agent bound grants). */
export interface McpMintBinding {
	/** The claim to sign, or undefined for an unbound token (no actor resolved to an agent row). */
	binding?: McpDelegationBinding;
	/** Earliest expiry among the links and agents in `binding`, or null when none expire. Caps `exp`. */
	capAt: Date | null;
}

/** Input to mint time binding resolution for token exchange. */
export interface McpMintBindingInput {
	/** The subject token's verified `theauth_dlg`, when present. Never taken from request input. */
	parent?: McpDelegationBinding;
	/** The subject token `sub`. */
	subject: string;
	/** The subject token's `act` chain, used to resolve a parent binding from scratch when `parent` is absent. */
	act?: McpActorClaim;
	/** The new actor: actor token subject, else the calling client. */
	actor: { sub: string; clientId?: string };
	/** When true, an unbound result is an `invalid_grant` instead. */
	requireBoundChain: boolean;
	now: Date;
}

/** One entry of the cached mode LRU, keyed by the signed `jti`. Values come from the DB, never request input. */
export interface McpFreshnessCacheEntry {
	/** "live" or why the token is dead. Negative verdicts are terminal. */
	verdict: "live" | McpInactiveReason;
	/** Epoch ms after which the entry must be recomputed: min(now + maxStalenessMs, binding validUntil, token exp). */
	validUntil: number;
}

/** Freshness facts attached to a validated session. */
export interface McpSessionFreshness {
	/** The mode that produced this verdict. "offline" means revocation was not consulted beyond the denylist. */
	mode: McpFreshnessMode;
	/** When the revocation and binding checks ran (or the cached verdict was computed). */
	checkedAt: Date;
}

/** Re-runs revocation and binding checks live, for long running handlers and SSE streams. */
export type McpRevalidate = () => Promise<Result<void>>;

/** Shape of `error.details.revocation` on an `INVALID_TOKEN` result. Server side only. */
export interface McpRevocationDetails {
	reason: McpInactiveReason;
	/** The jti, subject, client, link or agent id that matched. */
	id: string;
}

/** Options for `validateAccessToken`. */
export interface McpValidateOptions {
	/** Scopes the token must carry. Checked after revocation, so a revoked token gets 401, never 403. */
	requiredScopes?: string[];
	/** The canonical URI of this resource server. Required: a token minted for another resource must never be accepted here. */
	expectedAudience?: string;
	/** Thumbprint of the DPoP key whose proof the caller already verified for this request, or null/undefined for a bearer presentation. */
	presentedDpopJkt?: string | null;
	/** Override the configured mode for this call. Introspection and `revalidate()` pass "live". */
	freshness?: McpFreshnessMode;
}

/** Extra `requireMcpAuth` options for long running handlers. */
export interface McpRevalidateOptions {
	/** Re-run live checks before a tool invocation when the last check is older than this. Default off. */
	revalidateEveryMs?: number;
}

// Shared denylist

/** What a revocation row denies. `jti`, `dlg`, `agent` deny outright; `sub` and `client` are `iat` watermarks. */
export type McpRevocationKind = "jti" | "dlg" | "agent" | "sub" | "client";

export interface McpRevocationEntry {
	kind: McpRevocationKind;
	/** The jti, link id, agent id, user id or client id. Never a token value. */
	id: string;
	/** After this the row may be pruned (the thing it denies cannot be valid any more). */
	expiresAt: Date;
	/** Audit reason, for example "delegation.revoke". */
	reason: string;
	/** Root delegation id of a cascade, or the revoking actor. Never a token value. */
	sourceId?: string;
}

/** Everything one validation needs to check against the denylist in one query. All from the verified token. */
export interface McpRevocationQuery {
	jti: string;
	sub: string;
	clientId: string;
	/** Token `iat` in epoch seconds. Dead when `iat * 1000 <= revoked_at_ms` of a `sub` or `client` row (fail closed). */
	iat: number;
	/** `theauth_dlg.lnk`, empty for unbound tokens. */
	dlg: string[];
	/** `theauth_dlg.agt` (or `[agent_id]` for legacy agent tokens), empty otherwise. */
	agents: string[];
}

/** First denylist hit, by precedence jti, sub, client, dlg, agent. */
export interface McpRevocationHit {
	kind: McpRevocationKind;
	id: string;
}

/** Shared, DB backed revocation list. Also satisfies `McpJtiDenylist` so it can be `config.jtiDenylist`. */
export interface McpRevocationStore extends McpJtiDenylist {
	/** Upsert rows (re-revoking a `sub` raises its watermark). Never runs inside a transaction. */
	revokeMany(entries: McpRevocationEntry[], revokedAt?: Date): Promise<void>;
	/** One query. Returns the first hit by precedence jti, sub, client, dlg, agent; or null. */
	check(q: McpRevocationQuery): Promise<McpRevocationHit | null>;
	/** Newest `revoked_at_ms` plus a count of the rows near it (no COUNT(*) over the table), for cached mode. Compared to the last seen value, never to a clock. */
	fingerprint(): Promise<string>;
	/** Delete rows past `expiresAt`, at most `limit` (default 500). Returns rows deleted. */
	prune(now: Date, limit?: number): Promise<number>;
}

// Push path

export interface McpRevocationEvent {
	kind: McpRevocationKind;
	/** Ids revoked by this event (a cascade lists every link). */
	ids: string[];
	revokedAt: Date;
	reason: string;
	/** Root owner user id when known, for the SSF subject. */
	userId?: string;
	/** Root delegation id of a cascade, or the revoking actor. */
	sourceId?: string;
}

/** Records revocations and fans them out to local caches and `onRevoked`. Implemented in `revocation-bus.ts`. */
export interface McpRevocationBus {
	/** Records rows (when a store is set), notifies local listeners, then calls onRevoked. */
	publish(event: McpRevocationEvent, entries: McpRevocationEntry[]): Promise<void>;
	/** Notified once per publish, after the push. Returns an unsubscribe function. */
	subscribe(listener: (event: McpRevocationEvent) => void): () => void;
	/** Local cache invalidation: notified BEFORE the push (so a failed push still clears this instance) and again after it (for reads that raced the write). Idempotent listeners only. */
	subscribeClear?(listener: (event: McpRevocationEvent) => void): () => void;
}

export interface McpRevocationBusOptions {
	/** Where rows are written. Absent: events are local only. */
	store?: McpRevocationStore;
	onRevoked?: McpRevocationConfig["onRevoked"];
}

// Introspection (RFC 7662)

/** A resource server allowed to introspect tokens minted for its audiences. */
export interface McpIntrospectionResourceServer {
	/** Confidential client id that authenticates to `/mcp/introspect`. */
	clientId: string;
	/** Token `aud` values this client is entitled to. */
	audiences: string[];
}

export interface McpIntrospectionConfig {
	enabled: boolean;
	/** Confidential clients that may introspect tokens whose `aud` is in `audiences` (resource servers). The token's own client may always introspect it. */
	resourceServers?: McpIntrospectionResourceServer[];
	/** Per client, per instance. Default 600. Env THEAUTH_MCP_INTROSPECT_RPM. */
	maxRequestsPerMinute?: number;
}

/** Form fields of `POST /mcp/introspect` (client auth fields are read separately). */
export interface McpIntrospectionRequest {
	token: string;
	/** Advisory. Refresh tokens are never introspectable and always report `active: false`. */
	token_type_hint?: "access_token" | "refresh_token";
}

/**
 * RFC 7662 response. A caller that is not entitled (neither the token's `client_id` nor a
 * `resourceServers` entry covering its `aud`) always gets exactly `{ "active": false }`.
 */
export interface McpIntrospectionResponse {
	active: boolean;
	scope?: string;
	client_id?: string;
	sub?: string;
	exp?: number;
	iat?: number;
	aud?: string | string[];
	iss?: string;
	jti?: string;
	token_type?: "Bearer" | "DPoP";
	/** The resource server verifies the DPoP proof itself against this thumbprint. */
	cnf?: { jkt: string };
	/** RFC 9470 section 6.2: authentication context class reference of the user's login. */
	acr?: string;
	/** RFC 8176 authentication methods of the user's login. */
	amr?: string[];
	/** RFC 9470 section 6.2: epoch seconds of the user's authentication event. */
	auth_time?: number;
	act?: McpActorClaim;
	agent_id?: string;
	theauth_dlg?: McpDelegationBinding;
	/** theAuth extension. Only for callers entitled to the token, only when active is false. */
	theauth_inactive_reason?: McpInactiveReason;
}
