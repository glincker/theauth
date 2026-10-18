/**
 * Idle timeout and remember me settings for the session manager, plus the reserved metadata keys that carry them.
 *
 * The sessions table has no activity column, so `lastActiveAt` and `rememberMe` live in the session `metadata` JSON under reserved keys. They are stripped from `Session.metadata` and surfaced as `Session.lastActiveAt` and `Session.rememberMe`.
 */

export const LAST_ACTIVE_KEY = "theauthLastActiveAt";
export const REMEMBER_ME_KEY = "theauthRememberMe";
/** Authentication events (`AuthEvent[]`) behind `Session.auth`. */
export const AUTH_EVENTS_KEY = "theauthAuthEvents";

const DAY_SECONDS = 60 * 60 * 24;
const DEFAULT_ACTIVITY_GRANULARITY_MS = 60_000;
const DEFAULT_REMEMBER_ME_MAX_AGE_SECONDS = 30 * DAY_SECONDS;
const DEFAULT_REMEMBER_ME_CAP_SECONDS = 90 * DAY_SECONDS;

/** Why a token did not validate. `idle_timeout` and `expired` delete the row. */
export type SessionInvalidReason = "invalid_token" | "not_found" | "expired" | "idle_timeout";

export interface SessionActivityConfig {
	/** Deny a session with no activity for this long, in ms. Default: off. Env THEAUTH_SESSION_IDLE_TIMEOUT_MS. The absolute `maxAge` still applies. */
	idleTimeoutMs?: number;
	/** `lastActiveAt` is rewritten only when it is at least this old, in ms, so a busy session costs one write per window. Default: 60000, or a quarter of the idle timeout when that is shorter. Env THEAUTH_SESSION_ACTIVITY_GRANULARITY_MS. Must be below `idleTimeoutMs`. */
	activityGranularityMs?: number;
	/** Absolute lifetime in seconds of a session created with `rememberMe: true`. Default: 2592000 (30 days). Env THEAUTH_SESSION_REMEMBER_ME_MAX_AGE. */
	rememberMeMaxAge?: number;
	/** Hard ceiling in seconds on the remember me lifetime, whatever `rememberMeMaxAge` says. Default: 7776000 (90 days). */
	rememberMeMaxAgeCap?: number;
	/** Clock in epoch ms. Default: `Date.now`. Tests inject a fake one. */
	now?: () => number;
}

export interface ResolvedSessionActivity {
	idleTimeoutMs: number | undefined;
	granularityMs: number;
	rememberMeSeconds: number;
	now: () => number;
}

function envNumber(name: string): number | undefined {
	const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
	const raw = proc?.env?.[name];
	if (raw === undefined || raw === "") return undefined;
	const n = Number(raw);
	if (!Number.isFinite(n)) throw new Error(`SessionManager: ${name} must be a number.`);
	return n;
}

function positive(value: number | undefined, label: string): number | undefined {
	if (value === undefined) return undefined;
	if (!Number.isFinite(value) || value < 1) {
		throw new Error(`SessionManager: ${label} must be a positive number.`);
	}
	return Math.floor(value);
}

/** Resolve config over env over defaults. Throws on a nonsense combination. */
export function resolveSessionActivity(config: SessionActivityConfig): ResolvedSessionActivity {
	const idleTimeoutMs = positive(
		config.idleTimeoutMs ?? envNumber("THEAUTH_SESSION_IDLE_TIMEOUT_MS"),
		"idleTimeoutMs",
	);
	const granularityMs =
		positive(
			config.activityGranularityMs ?? envNumber("THEAUTH_SESSION_ACTIVITY_GRANULARITY_MS"),
			"activityGranularityMs",
		) ??
		(idleTimeoutMs === undefined
			? DEFAULT_ACTIVITY_GRANULARITY_MS
			: Math.min(DEFAULT_ACTIVITY_GRANULARITY_MS, Math.max(1, Math.floor(idleTimeoutMs / 4))));
	if (idleTimeoutMs !== undefined && granularityMs >= idleTimeoutMs) {
		throw new Error("SessionManager: activityGranularityMs must be shorter than idleTimeoutMs.");
	}
	const rememberMe =
		positive(
			config.rememberMeMaxAge ?? envNumber("THEAUTH_SESSION_REMEMBER_ME_MAX_AGE"),
			"rememberMeMaxAge",
		) ?? DEFAULT_REMEMBER_ME_MAX_AGE_SECONDS;
	const cap =
		positive(config.rememberMeMaxAgeCap, "rememberMeMaxAgeCap") ?? DEFAULT_REMEMBER_ME_CAP_SECONDS;
	return {
		idleTimeoutMs,
		granularityMs,
		rememberMeSeconds: Math.min(rememberMe, cap),
		now: config.now ?? (() => Date.now()),
	};
}

export interface SplitMetadata {
	/** Caller metadata with the reserved keys removed, or undefined when nothing is left. */
	metadata: Record<string, unknown> | undefined;
	lastActiveAt: number | undefined;
	rememberMe: boolean | undefined;
	/** The stored authentication events, unvalidated. Run them through `normalizeEvents`. */
	authEvents: unknown;
}

/** Separate the reserved keys from the metadata a caller stored. */
export function splitMetadata(raw: Record<string, unknown> | null | undefined): SplitMetadata {
	if (!raw) {
		return {
			metadata: undefined,
			lastActiveAt: undefined,
			rememberMe: undefined,
			authEvents: undefined,
		};
	}
	const {
		[LAST_ACTIVE_KEY]: last,
		[REMEMBER_ME_KEY]: remember,
		[AUTH_EVENTS_KEY]: authEvents,
		...rest
	} = raw;
	return {
		metadata: Object.keys(rest).length > 0 ? rest : undefined,
		lastActiveAt: typeof last === "number" && Number.isFinite(last) ? last : undefined,
		rememberMe: typeof remember === "boolean" ? remember : undefined,
		authEvents,
	};
}
