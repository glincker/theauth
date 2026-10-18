// Freshness of MCP access tokens at the resource server (design F1, section 2).
//
// Runs only AFTER the JWT signature, audience, issuer, exp and DPoP binding verified, so nothing
// here ever sees input from an unauthenticated caller. Modes:
//   live    revocation store + binding check on every validation, no cache, no coalescing
//   cached  per process LRU keyed by the signed jti, fingerprint polling, hard maxStalenessMs bound
//   offline claims until exp, plus the in memory jtiDenylist when one is configured
// Any store error rejects the token (fail closed). Tokens and their claims are never logged.

import type {
	McpBindingStore,
	McpDelegationBinding,
	McpFreshnessCacheEntry,
	McpFreshnessMode,
	McpInactiveReason,
	McpRevocationConfig,
	McpRevocationEvent,
	McpRevocationHit,
	McpRevocationStore,
} from "./revocation-types.js";
import {
	MCP_DEFAULT_FRESHNESS_MODE_WITH_DB,
	MCP_DEFAULT_FRESHNESS_MODE_WITHOUT_DB,
	MCP_DELEGATION_BINDING_VERSION,
	MCP_FRESHNESS_MODES,
	MCP_REVOCATION_DEFAULTS,
} from "./revocation-types.js";
import type { McpAuthContext, TheAuthError } from "./types.js";

/** Runtime collaborators the freshness checks read. `createMcpModule` attaches them (see {@link attachFreshnessDeps}). */
export interface McpFreshnessDeps {
	/** Shared denylist. When absent, `config.jtiDenylist` is used if it implements the full store. */
	revocations?: McpRevocationStore;
	/** Delegation and agent rows behind `theauth_dlg`. Needed to verify bound tokens in live and cached mode. */
	bindings?: McpBindingStore;
	/** Local revocation bus. Any event drops cached positive verdicts. Returns an unsubscribe function. */
	subscribe?: (listener: (event: McpRevocationEvent) => void) => () => void;
}

/** What a validation hands to the freshness check. Every field comes from the verified token. */
export interface McpFreshnessSubject {
	jti: string;
	sub: string;
	clientId: string;
	/** `iat` in epoch seconds, 0 when the claim is missing (fail closed against watermarks). */
	iat: number;
	/** `exp` in epoch seconds. */
	exp: number;
	binding?: McpDelegationBinding;
	/** Legacy tokens: `agent_id` without a binding. */
	agentId?: string;
}

export type McpFreshnessOutcome =
	| { ok: true; mode: McpFreshnessMode; checkedAt: Date }
	| { ok: false; kind: "inactive"; reason: McpInactiveReason; id: string }
	| { ok: false; kind: "unavailable" };

export interface McpFreshnessSettings {
	mode: McpFreshnessMode;
	maxStalenessMs: number;
	pollIntervalMs: number;
	cacheMax: number;
}

const MAX_BINDING_ENTRIES = 32;
const MAX_ID_LENGTH = 256;

const DEPS = new WeakMap<McpAuthContext, McpFreshnessDeps>();

/** Attach stores and the bus subscription to a context. Call once at module creation. Resets any cache. */
export function attachFreshnessDeps(ctx: McpAuthContext, deps: McpFreshnessDeps): void {
	const old = STATES.get(ctx);
	old?.unsubscribe?.();
	STATES.delete(ctx);
	DEPS.set(ctx, deps);
}

function isRevocationStore(value: unknown): value is McpRevocationStore {
	if (typeof value !== "object" || value === null) return false;
	const v = value as Record<string, unknown>;
	return (
		typeof v.check === "function" &&
		typeof v.fingerprint === "function" &&
		typeof v.isRevoked === "function"
	);
}

function revocationsOf(ctx: McpAuthContext): McpRevocationStore | undefined {
	const attached = DEPS.get(ctx)?.revocations;
	if (attached) return attached;
	const denylist: unknown = ctx.config.jtiDenylist;
	return isRevocationStore(denylist) ? denylist : undefined;
}

function envOf(name: string): string | undefined {
	const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
	const value = proc?.env?.[name];
	return value === undefined || value === "" ? undefined : value;
}

function positiveInt(configured: number | undefined, envName: string, fallback: number): number {
	const fromEnv = envOf(envName);
	const raw = configured ?? (fromEnv === undefined ? undefined : Number(fromEnv));
	return typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? Math.floor(raw) : fallback;
}

/** Resolve mode and bounds: config wins, then env, then the design defaults. */
export function resolveFreshnessSettings(ctx: McpAuthContext): McpFreshnessSettings {
	const cfg: McpRevocationConfig = ctx.config.revocation ?? {};
	const deps = DEPS.get(ctx);
	const hasStores = Boolean(deps?.revocations ?? deps?.bindings ?? revocationsOf(ctx));
	const fromEnv = envOf("THEAUTH_MCP_REVOCATION_MODE");
	const envMode = MCP_FRESHNESS_MODES.find((m) => m === fromEnv);
	const mode =
		cfg.mode ??
		envMode ??
		(hasStores ? MCP_DEFAULT_FRESHNESS_MODE_WITH_DB : MCP_DEFAULT_FRESHNESS_MODE_WITHOUT_DB);
	return {
		mode,
		maxStalenessMs: positiveInt(
			cfg.maxStalenessMs,
			"THEAUTH_MCP_REVOCATION_MAX_STALENESS_MS",
			MCP_REVOCATION_DEFAULTS.maxStalenessMs,
		),
		pollIntervalMs: positiveInt(
			cfg.pollIntervalMs,
			"THEAUTH_MCP_REVOCATION_POLL_MS",
			MCP_REVOCATION_DEFAULTS.pollIntervalMs,
		),
		cacheMax: positiveInt(
			cfg.cacheMax,
			"THEAUTH_MCP_REVOCATION_CACHE_MAX",
			MCP_REVOCATION_DEFAULTS.cacheMax,
		),
	};
}

/**
 * Shape check for the signed `theauth_dlg` claim. Returns undefined when absent, null when present
 * but malformed (the token is then invalid, never trusted partially).
 */
export function parseBinding(raw: unknown): McpDelegationBinding | null | undefined {
	if (raw === undefined) return undefined;
	if (typeof raw !== "object" || raw === null) return null;
	const { v, agt, lnk } = raw as Record<string, unknown>;
	if (v !== MCP_DELEGATION_BINDING_VERSION) return null;
	if (!Array.isArray(agt) || !Array.isArray(lnk)) return null;
	if (agt.length < 1 || agt.length > MAX_BINDING_ENTRIES) return null;
	if (lnk.length !== agt.length - 1) return null;
	const ok = (x: unknown): x is string =>
		typeof x === "string" && x.length > 0 && x.length <= MAX_ID_LENGTH;
	if (!agt.every(ok) || !lnk.every(ok)) return null;
	return { v: MCP_DELEGATION_BINDING_VERSION, agt: [...agt], lnk: [...lnk] };
}

const HIT_REASON: Record<McpRevocationHit["kind"], McpInactiveReason> = {
	jti: "revoked",
	sub: "subject_revoked",
	client: "client_revoked",
	dlg: "delegation_revoked",
	agent: "agent_revoked",
};

const INACTIVE_MESSAGE: Record<McpInactiveReason, string> = {
	expired: "Token has expired",
	revoked: "Token has been revoked",
	subject_revoked: "Token has been revoked",
	client_revoked: "Token has been revoked",
	delegation_revoked: "Delegation has been revoked",
	delegation_expired: "Delegation has expired",
	agent_revoked: "Agent has been revoked",
	agent_expired: "Agent has expired",
	invalid: "Token is not valid",
};

/** Build the error for a failed outcome. Reason and id go to `details.revocation` (server side), the message names no ids. */
export function freshnessError(
	outcome: Exclude<McpFreshnessOutcome, { ok: true }>,
	extra: Record<string, unknown> = {},
): TheAuthError {
	if (outcome.kind === "unavailable") {
		return {
			code: "SERVER_ERROR",
			message: "Revocation status is temporarily unavailable",
			details: { unavailable: true, ...extra },
		};
	}
	return {
		code: "INVALID_TOKEN",
		message: INACTIVE_MESSAGE[outcome.reason],
		details: {
			...(outcome.reason === "revoked" ? { revoked: true } : {}),
			revocation: { reason: outcome.reason, id: outcome.id },
			...extra,
		},
	};
}

// Cache state (cached mode only)

type Entry = McpFreshnessCacheEntry & { computedAt: number; tag: string; id: string };

interface State {
	entries: Map<string, Entry>;
	inflight: Map<string, Promise<Verdict>>;
	generation: number;
	lastFingerprint?: string;
	lastPollAt?: number;
	poll?: Promise<void>;
	unsubscribe?: () => void;
}

const STATES = new WeakMap<McpAuthContext, State>();

function stateOf(ctx: McpAuthContext): State {
	let state = STATES.get(ctx);
	if (!state) {
		const created: State = { entries: new Map(), inflight: new Map(), generation: 0 };
		created.unsubscribe = DEPS.get(ctx)?.subscribe?.(() => clearPositive(created));
		STATES.set(ctx, created);
		state = created;
	}
	return state;
}

/** Drop positive verdicts (negative ones are terminal: a revoked token never comes back). */
function clearPositive(state: State): void {
	state.generation++;
	for (const [key, entry] of state.entries) {
		if (entry.verdict === "live") state.entries.delete(key);
	}
}

/** Drop every cached positive verdict for a context (for the revocation bus wiring and tests). */
export function invalidateFreshnessCache(ctx: McpAuthContext): void {
	const state = STATES.get(ctx);
	if (state) clearPositive(state);
}

/** Entries currently held, for tests and metrics. */
export function freshnessCacheSize(ctx: McpAuthContext): number {
	return STATES.get(ctx)?.entries.size ?? 0;
}

function tagOf(s: McpFreshnessSubject): string {
	const b = s.binding;
	return [s.jti, s.sub, s.clientId, s.iat, b?.agt.join(","), b?.lnk.join(","), s.agentId].join(
		"\u0000",
	);
}

// Verdict computation

interface Verdict {
	verdict: "live" | McpInactiveReason;
	id: string;
	/** Earliest binding expiry in epoch ms, when live. */
	boundUntil?: number;
}

/** Reads the stores once. Throws on any store error: callers fail closed. */
async function computeVerdict(
	ctx: McpAuthContext,
	subject: McpFreshnessSubject,
	now: number,
): Promise<Verdict> {
	const revocations = revocationsOf(ctx);
	const bindings = DEPS.get(ctx)?.bindings;
	const denylist = ctx.config.jtiDenylist;
	const agents = subject.binding?.agt ?? (subject.agentId ? [subject.agentId] : []);
	const links = subject.binding?.lnk ?? [];
	const toCheck: McpDelegationBinding | undefined =
		subject.binding ??
		(subject.agentId
			? { v: MCP_DELEGATION_BINDING_VERSION, agt: [subject.agentId], lnk: [] }
			: undefined);
	if (subject.binding && !bindings) {
		throw new Error("binding store is not configured");
	}

	const [hit, extraDeny, bound] = await Promise.all([
		revocations
			? revocations.check({
					jti: subject.jti,
					sub: subject.sub,
					clientId: subject.clientId,
					iat: subject.iat,
					dlg: links,
					agents,
				})
			: Promise.resolve(null),
		denylist && denylist !== revocations ? denylist.isRevoked(subject.jti) : Promise.resolve(false),
		toCheck && bindings ? bindings.check(toCheck, new Date(now)) : Promise.resolve(undefined),
	]);

	if (hit) return { verdict: HIT_REASON[hit.kind], id: hit.id };
	if (extraDeny) return { verdict: "revoked", id: subject.jti };
	if (bound && !bound.live) return { verdict: bound.reason, id: bound.id };
	return {
		verdict: "live",
		id: subject.jti,
		...(bound?.live ? { boundUntil: bound.validUntil.getTime() } : {}),
	};
}

function outcomeOf(
	verdict: Verdict["verdict"],
	id: string,
	mode: McpFreshnessMode,
	checkedAt: number,
): McpFreshnessOutcome {
	if (verdict === "live") return { ok: true, mode, checkedAt: new Date(checkedAt) };
	return { ok: false, kind: "inactive", reason: verdict, id };
}

async function maybePoll(
	ctx: McpAuthContext,
	state: State,
	settings: McpFreshnessSettings,
	now: number,
): Promise<void> {
	const store = revocationsOf(ctx);
	if (!store) return;
	const last = state.lastPollAt;
	// A clock that moved backwards makes the poll due (never trust a future timestamp).
	if (last !== undefined && now >= last && now - last < settings.pollIntervalMs) return;
	if (!state.poll) {
		state.poll = (async () => {
			try {
				const fp = await store.fingerprint();
				if (state.lastFingerprint !== undefined && fp !== state.lastFingerprint)
					clearPositive(state);
				state.lastFingerprint = fp;
			} catch {
				// Polling failure keeps entries, which still die at maxStalenessMs.
			} finally {
				state.lastPollAt = Date.now();
				state.poll = undefined;
			}
		})();
	}
	await state.poll;
}

function usable(entry: Entry, tag: string, now: number, maxStalenessMs: number): boolean {
	if (entry.tag !== tag) return false;
	if (entry.verdict !== "live") return now < entry.validUntil;
	// A clock that moved backwards invalidates positives instead of extending them.
	return (
		now >= entry.computedAt && now - entry.computedAt < maxStalenessMs && now < entry.validUntil
	);
}

function remember(state: State, key: string, entry: Entry, cacheMax: number): void {
	state.entries.delete(key);
	state.entries.set(key, entry);
	while (state.entries.size > cacheMax) {
		const oldest = state.entries.keys().next();
		if (oldest.done) break;
		state.entries.delete(oldest.value);
	}
}

async function checkCached(
	ctx: McpAuthContext,
	subject: McpFreshnessSubject,
	settings: McpFreshnessSettings,
): Promise<McpFreshnessOutcome> {
	const state = stateOf(ctx);
	await maybePoll(ctx, state, settings, Date.now());
	const tag = tagOf(subject);
	const now = Date.now();
	const hit = state.entries.get(subject.jti);
	if (hit && usable(hit, tag, now, settings.maxStalenessMs)) {
		// LRU touch
		state.entries.delete(subject.jti);
		state.entries.set(subject.jti, hit);
		return outcomeOf(hit.verdict, hit.id, "cached", hit.computedAt);
	}
	let flight = state.inflight.get(tag);
	if (!flight) {
		const generation = state.generation;
		const started = Date.now();
		const created = computeVerdict(ctx, subject, started).then((v) => {
			const negative = v.verdict !== "live";
			// A clear during the read means the verdict may predate a revocation: do not keep it.
			if (negative || generation === state.generation) {
				const expMs = subject.exp * 1000;
				const validUntil = negative
					? expMs
					: Math.min(
							started + settings.maxStalenessMs,
							v.boundUntil ?? Number.POSITIVE_INFINITY,
							expMs,
						);
				remember(
					state,
					subject.jti,
					{ verdict: v.verdict, validUntil, computedAt: started, tag, id: v.id },
					settings.cacheMax,
				);
			}
			return v;
		});
		flight = created;
		state.inflight.set(tag, created);
		const cleanup = () => {
			if (state.inflight.get(tag) === created) state.inflight.delete(tag);
		};
		created.then(cleanup, cleanup);
	}
	const v = await flight;
	return outcomeOf(v.verdict, v.id, "cached", Date.now());
}

/**
 * Check one verified token. `mode` is the effective mode (configured, or "live" for `revalidate()`).
 * Never throws: store errors become `{ kind: "unavailable" }`.
 */
export async function checkFreshness(
	ctx: McpAuthContext,
	subject: McpFreshnessSubject,
	mode: McpFreshnessMode,
): Promise<McpFreshnessOutcome> {
	try {
		const settings = resolveFreshnessSettings(ctx);
		if (mode === "cached") return await checkCached(ctx, subject, settings);
		if (mode === "offline") {
			const denylist = ctx.config.jtiDenylist;
			if (denylist && (await denylist.isRevoked(subject.jti))) {
				return { ok: false, kind: "inactive", reason: "revoked", id: subject.jti };
			}
			return { ok: true, mode, checkedAt: new Date() };
		}
		const now = Date.now();
		const v = await computeVerdict(ctx, subject, now);
		return outcomeOf(v.verdict, v.id, "live", now);
	} catch {
		return { ok: false, kind: "unavailable" };
	}
}
