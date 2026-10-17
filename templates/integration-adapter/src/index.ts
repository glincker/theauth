/**
 * Community integration template for theAuth.
 *
 * Shape of the hook input and output mirrors docs/hooks.mdx (beforeAuthorize).
 * Replace `evaluate` with your own policy check. Keep it generic: no vendor SDK here.
 */

export interface AuthorizeContext {
	agentId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
}

export interface HookDecision {
	allow: boolean;
	reason?: string;
}

export type BeforeAuthorizeResult = HookDecision | void;

/**
 * Placeholder evaluation. Return a decision, or throw / reject on failure.
 * Replace the body with a call to your own policy engine or service.
 */
export async function evaluate(context: AuthorizeContext): Promise<HookDecision> {
	if (context.action.length === 0) {
		return { allow: false, reason: "empty action" };
	}
	return { allow: true };
}

export interface AdapterOptions {
	/** Max time to wait for evaluate() before denying. */
	timeoutMs?: number;
	/** Injected evaluator, defaults to evaluate(). Lets tests swap in fakes. */
	evaluator?: (context: AuthorizeContext) => Promise<HookDecision>;
}

const DEFAULT_TIMEOUT_MS = 2000;

/**
 * Build a beforeAuthorize hook. Denies by default when evaluate() throws,
 * rejects, or does not settle within timeoutMs.
 */
export function createBeforeAuthorizeHook(options: AdapterOptions = {}) {
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const evaluator = options.evaluator ?? evaluate;

	return async (context: AuthorizeContext): Promise<HookDecision> => {
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			const timeout = new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error("evaluation timed out")), timeoutMs);
			});
			const decision = await Promise.race([evaluator(context), timeout]);
			if (decision && decision.allow === true) {
				return { allow: true };
			}
			return { allow: false, reason: decision?.reason ?? "denied by integration" };
		} catch (error) {
			const message = error instanceof Error ? error.message : "unknown error";
			return { allow: false, reason: `integration error: ${message}` };
		} finally {
			if (timer !== undefined) clearTimeout(timer);
		}
	};
}
