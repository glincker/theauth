/**
 * beforeAuthorize hook runner: timeout via AbortSignal, fail-closed by default.
 */
import type { DecisionCode } from "../permission/codes.js";
import type {
	BeforeAuthorizeContext,
	HookDelegationChain,
	HookVerdict,
	TheAuthHooks,
} from "./lifecycle.js";
import type { HookErrorInfo, ResolvedHookSafety } from "./safety.js";
import { HookTimeoutError } from "./safety.js";

type VerdictMeta = Pick<HookVerdict, "guard" | "ruleId" | "metadata">;

export type HookOutcome =
	| { kind: "allow"; elapsedMs: number }
	| ({
			kind: "deny" | "escalate";
			code: DecisionCode;
			reason: string;
			elapsedMs: number;
	  } & VerdictMeta)
	| { kind: "fail_open"; code: "hook_timeout" | "hook_error"; elapsedMs: number };

export type BeforeAuthorizeRunner = (
	ctx: Omit<BeforeAuthorizeContext, "signal" | "delegation"> & {
		delegation: () => Promise<HookDelegationChain>;
	},
) => Promise<HookOutcome | null>;

export type TimeoutResult<T> =
	| { ok: true; value: T }
	| { ok: false; timedOut: boolean; error: unknown };

/**
 * Run fn with an AbortController and race it against the timeout. The timer is
 * always cleared. A late result or rejection of an abandoned fn is ignored.
 * timeoutMs <= 0 disables the timeout.
 */
export async function runWithTimeout<T>(
	fn: (signal: AbortSignal) => Promise<T>,
	timeoutMs: number,
): Promise<TimeoutResult<T>> {
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<TimeoutResult<T>>((resolve) => {
		if (timeoutMs > 0) {
			timer = setTimeout(() => {
				controller.abort();
				resolve({ ok: false, timedOut: true, error: undefined });
			}, timeoutMs);
		}
	});
	let work: Promise<T>;
	try {
		work = Promise.resolve(fn(controller.signal));
	} catch (error) {
		return { ok: false, timedOut: false, error };
	}
	// Swallow a late rejection after the timeout won the race.
	work.catch(() => undefined);
	const settled = work.then(
		(value): TimeoutResult<T> => ({ ok: true, value }),
		(error): TimeoutResult<T> => ({ ok: false, timedOut: false, error }),
	);
	try {
		return await (timeoutMs > 0 ? Promise.race([settled, timeout]) : settled);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

type Normalized = { decision: "allow" | "deny" | "escalate"; reason?: string } & VerdictMeta;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

const MAX_METADATA_KEYS = 16;
const MAX_VALUE_CHARS = 256;

function clip(value: string): string {
	return value.length > MAX_VALUE_CHARS ? value.slice(0, MAX_VALUE_CHARS) : value;
}

/** Keep scalar values only: max 16 keys, strings clipped to 256 chars. */
function sanitizeMetadata(raw: Record<string, unknown>): Record<string, string | number | boolean> {
	const out: Record<string, string | number | boolean> = {};
	for (const [key, value] of Object.entries(raw)) {
		if (Object.keys(out).length >= MAX_METADATA_KEYS) break;
		if (typeof value === "string") out[clip(key)] = clip(value);
		else if (typeof value === "number" && Number.isFinite(value)) out[clip(key)] = value;
		else if (typeof value === "boolean") out[clip(key)] = value;
	}
	return out;
}

/** Returns undefined for a malformed verdict. */
export function normalizeVerdict(result: unknown): Normalized | undefined {
	if (result === undefined || result === null) return { decision: "allow" };
	if (!isRecord(result)) return undefined;
	const reason = typeof result.reason === "string" ? result.reason : undefined;
	const d = result.decision;
	if (d === "allow" || d === "deny" || d === "escalate") {
		const verdict: Normalized = { decision: d, reason };
		if (typeof result.guard === "string") verdict.guard = clip(result.guard);
		if (typeof result.ruleId === "string") verdict.ruleId = clip(result.ruleId);
		if (isRecord(result.metadata)) verdict.metadata = sanitizeMetadata(result.metadata);
		return verdict;
	}
	if (typeof result.allow === "boolean") {
		return { decision: result.allow ? "allow" : "deny", reason };
	}
	return undefined;
}

export function notify(safety: ResolvedHookSafety, info: HookErrorInfo): void {
	try {
		safety.onHookError?.(info);
	} catch {
		// onHookError must not change the outcome.
	}
}

export function createBeforeAuthorizeRunner(
	hooks: Pick<TheAuthHooks, "beforeAuthorize">,
	safety: ResolvedHookSafety,
): BeforeAuthorizeRunner {
	const guard = safety.beforeAuthorize;
	return async (ctx) => {
		const hook = hooks.beforeAuthorize;
		if (!hook) return null;

		// Lineage loads before the clock starts; a DB error propagates, it is not a hook error.
		const { delegation: loadDelegation, ...rest } = ctx;
		const delegation = await loadDelegation();

		const startedAt = Date.now();
		const res = await runWithTimeout(
			(signal) => hook({ ...rest, delegation, signal }),
			guard.timeoutMs,
		);
		const elapsedMs = Date.now() - startedAt;

		if (!res.ok) {
			const timedOut = res.timedOut;
			notify(safety, {
				hook: "beforeAuthorize",
				kind: timedOut ? "timeout" : "error",
				error: res.error,
				elapsedMs,
				agentId: ctx.agentId,
			});
			return failure(timedOut ? "timeout" : "error", res.error, guard, elapsedMs);
		}

		const verdict = normalizeVerdict(res.value);
		if (!verdict) {
			notify(safety, {
				hook: "beforeAuthorize",
				kind: "malformed",
				elapsedMs,
				agentId: ctx.agentId,
			});
			return failure("malformed", undefined, guard, elapsedMs);
		}
		if (verdict.decision === "allow") return { kind: "allow", elapsedMs };
		const { decision, reason, ...meta } = verdict;
		if (decision === "escalate") {
			return {
				kind: "escalate",
				code: "approval_required",
				reason: reason ?? "beforeAuthorize hook requires approval",
				elapsedMs,
				...meta,
			};
		}
		return {
			kind: "deny",
			code: "hook_denied",
			reason: reason ?? "Blocked by beforeAuthorize hook",
			elapsedMs,
			...meta,
		};
	};
}

function failure(
	kind: "timeout" | "error" | "malformed",
	error: unknown,
	guard: ResolvedHookSafety["beforeAuthorize"],
	elapsedMs: number,
): HookOutcome {
	const mode = kind === "timeout" ? guard.onTimeout : guard.onError;
	const code = kind === "timeout" ? "hook_timeout" : "hook_error";
	if (mode === "throw") {
		if (kind === "timeout") throw new HookTimeoutError("beforeAuthorize", guard.timeoutMs);
		throw error ?? new Error("beforeAuthorize hook returned a malformed verdict");
	}
	if (mode === "allow") return { kind: "fail_open", code, elapsedMs };
	return {
		kind: "deny",
		code,
		reason:
			kind === "timeout"
				? `beforeAuthorize hook timed out after ${guard.timeoutMs}ms`
				: "beforeAuthorize hook failed",
		elapsedMs,
	};
}
