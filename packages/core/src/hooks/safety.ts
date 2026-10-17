/**
 * Hook safety: timeout and fail-closed configuration.
 *
 * Resolution order, per field: per-hook option, then top-level `hookSafety`
 * option, then THEAUTH_HOOK_* env var, then the built-in default.
 */

export type HookFailMode = "deny" | "allow" | "throw";

export interface HookGuardOptions {
	/** Milliseconds before the hook is abandoned. 0 disables the timeout. Clamped to 0..60000. */
	timeoutMs?: number;
	/** What a timeout means. "throw" rejects the call with HookTimeoutError. */
	onTimeout?: HookFailMode;
	/** What a thrown error or malformed verdict means. "throw" re-throws the original error. */
	onError?: HookFailMode;
}

export type HookName = "beforeAuthorize" | "beforeAgentCreate";

export interface HookErrorInfo {
	hook: HookName;
	kind: "timeout" | "error" | "malformed";
	error?: unknown;
	elapsedMs: number;
	agentId?: string;
}

export interface HookSafetyConfig extends HookGuardOptions {
	beforeAuthorize?: HookGuardOptions;
	beforeAgentCreate?: HookGuardOptions;
	/** Called on every timeout and error, whatever the fail mode. A throw is swallowed. */
	onHookError?: (info: HookErrorInfo) => void;
}

export interface ResolvedHookGuard {
	timeoutMs: number;
	onTimeout: HookFailMode;
	onError: HookFailMode;
}

export interface ResolvedHookSafety {
	beforeAuthorize: ResolvedHookGuard;
	beforeAgentCreate: ResolvedHookGuard;
	onHookError?: HookSafetyConfig["onHookError"];
}

/** Runtime-neutral env reader (no Node APIs in core). */
export type EnvReader = (name: string) => string | undefined;

export const defaultEnvReader: EnvReader = (name) => {
	const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
	return proc?.env?.[name];
};

export const DEFAULT_HOOK_TIMEOUT_MS = 2000;
export const MAX_HOOK_TIMEOUT_MS = 60000;

export class HookTimeoutError extends Error {
	readonly code = "HOOK_TIMEOUT" as const;
	readonly timeoutMs: number;

	constructor(hook: HookName, timeoutMs: number) {
		super(`${hook} hook timed out after ${timeoutMs}ms`);
		this.name = "HookTimeoutError";
		this.timeoutMs = timeoutMs;
	}
}

export class HookBlockedError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "HookBlockedError";
		this.code = code;
	}
}

function isFailMode(value: unknown): value is HookFailMode {
	return value === "deny" || value === "allow" || value === "throw";
}

function parseTimeout(value: unknown): number | undefined {
	let n: number | undefined;
	if (typeof value === "number") n = value;
	else if (typeof value === "string" && value.trim() !== "") n = Number(value);
	if (n === undefined || !Number.isFinite(n)) return undefined;
	return Math.min(MAX_HOOK_TIMEOUT_MS, Math.max(0, Math.floor(n)));
}

function parseMode(value: unknown): HookFailMode | undefined {
	return isFailMode(value) ? value : undefined;
}

function resolveGuard(
	hook: HookName,
	config: HookSafetyConfig | undefined,
	env: EnvReader,
): ResolvedHookGuard {
	const own = config?.[hook];
	const defaultMode: HookFailMode = hook === "beforeAuthorize" ? "deny" : "throw";
	return {
		timeoutMs:
			parseTimeout(own?.timeoutMs) ??
			parseTimeout(config?.timeoutMs) ??
			parseTimeout(env("THEAUTH_HOOK_TIMEOUT_MS")) ??
			DEFAULT_HOOK_TIMEOUT_MS,
		onTimeout:
			parseMode(own?.onTimeout) ??
			parseMode(config?.onTimeout) ??
			parseMode(env("THEAUTH_HOOK_ON_TIMEOUT")) ??
			defaultMode,
		onError:
			parseMode(own?.onError) ??
			parseMode(config?.onError) ??
			parseMode(env("THEAUTH_HOOK_ON_ERROR")) ??
			defaultMode,
	};
}

/** Resolve hook safety settings. Never throws; invalid values fall through to the next level. */
export function resolveHookSafety(
	config?: HookSafetyConfig,
	env: EnvReader = defaultEnvReader,
): ResolvedHookSafety {
	return {
		beforeAuthorize: resolveGuard("beforeAuthorize", config, env),
		beforeAgentCreate: resolveGuard("beforeAgentCreate", config, env),
		onHookError: config?.onHookError,
	};
}
