/**
 * Wires hook safety into the hooks a TheAuth instance was configured with: the beforeAuthorize runner and the beforeAgentCreate guard.
 */
import type { CreateAgentInput } from "../types.js";
import type { TheAuthHooks } from "./lifecycle.js";
import type { BeforeAuthorizeRunner } from "./run.js";
import { createBeforeAuthorizeRunner, normalizeVerdict, notify, runWithTimeout } from "./run.js";
import type { HookSafetyConfig } from "./safety.js";
import { HookBlockedError, HookTimeoutError, resolveHookSafety } from "./safety.js";

export interface HookRuntime {
	/** Resolves null when no beforeAuthorize hook is configured. */
	runBeforeAuthorize: BeforeAuthorizeRunner;
	/** Run beforeAgentCreate with timeout and failure policy. Throws to block creation. */
	guardAgentCreate(input: CreateAgentInput): Promise<void>;
}

export function createHookRuntime(
	hooks: TheAuthHooks,
	hookSafety: HookSafetyConfig | undefined,
): HookRuntime {
	const safety = resolveHookSafety(hookSafety);
	const runBeforeAuthorize = createBeforeAuthorizeRunner(hooks, safety);

	async function guardAgentCreate(input: CreateAgentInput): Promise<void> {
		const hook = hooks.beforeAgentCreate;
		if (!hook) return;
		const guard = safety.beforeAgentCreate;
		const startedAt = Date.now();
		const res = await runWithTimeout(() => hook(input), guard.timeoutMs);
		const elapsedMs = Date.now() - startedAt;

		if (!res.ok) {
			const kind = res.timedOut ? "timeout" : "error";
			notify(safety, { hook: "beforeAgentCreate", kind, error: res.error, elapsedMs });
			const mode = res.timedOut ? guard.onTimeout : guard.onError;
			if (mode === "allow") return;
			if (res.timedOut) {
				if (mode === "throw") throw new HookTimeoutError("beforeAgentCreate", guard.timeoutMs);
				throw new HookBlockedError(
					"hook_timeout",
					`beforeAgentCreate hook timed out after ${guard.timeoutMs}ms`,
				);
			}
			if (mode === "throw") throw res.error;
			throw new HookBlockedError("hook_error", "beforeAgentCreate hook failed");
		}

		const verdict = normalizeVerdict(res.value);
		if (!verdict) {
			notify(safety, { hook: "beforeAgentCreate", kind: "malformed", elapsedMs });
			if (guard.onError === "allow") return;
			if (guard.onError === "throw") {
				throw new Error("beforeAgentCreate hook returned a malformed verdict");
			}
			throw new HookBlockedError("hook_error", "beforeAgentCreate hook failed");
		}
		if (verdict.decision !== "allow") {
			throw new HookBlockedError(
				"hook_denied",
				verdict.reason ?? "Agent creation blocked by beforeAgentCreate hook",
			);
		}
	}

	return { runBeforeAuthorize, guardAgentCreate };
}
