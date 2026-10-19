// Vercel AI SDK: wrap a tool map so each call is authorized before `execute` runs.
// Structural types only. `ai` is not imported.

import type { GateOptions, ToolDenial } from "./gate.js";
import { createGate } from "./gate.js";

/** A Vercel AI SDK tool as far as this helper cares. Extra properties are kept. */
export interface AiSdkToolLike {
	execute?: (args: never, options: never) => unknown;
}

export type GuardAiSdkToolsOptions<C = unknown> = GateOptions<C> & {
	/** Read the per-call context (for example the agent id) from the AI SDK call options. Default: the options object itself. */
	contextOf?: (callOptions: unknown) => C | undefined;
};

type Guarded<T extends AiSdkToolLike> = T extends { execute: (...a: infer A) => infer R }
	? Omit<T, "execute"> & { execute: (...a: A) => Promise<Awaited<R> | ToolDenial> }
	: T;

/**
 * Return a copy of the tool map where every tool with an `execute` runs `authorize` first. A refused call resolves to a `ToolDenial` (with the decision code) instead of throwing, so the model can read it and stop. Tools without `execute` (client side tools) pass through unchanged.
 */
export function guardAiSdkTools<T extends Record<string, AiSdkToolLike>, C = unknown>(
	tools: T,
	options: GuardAiSdkToolsOptions<C>,
): { [K in keyof T]: Guarded<T[K]> } {
	const gate = createGate<C>(options);
	const out: Record<string, unknown> = {};
	for (const [name, tool] of Object.entries(tools)) {
		const original = tool.execute;
		if (typeof original !== "function") {
			out[name] = tool;
			continue;
		}
		out[name] = {
			...tool,
			execute: async (args: unknown, callOptions: unknown) => {
				const ctx = options.contextOf
					? options.contextOf(callOptions)
					: (callOptions as C | undefined);
				const refused = await gate.check(name, args, ctx);
				if (refused) return refused;
				return (original as (a: unknown, o: unknown) => unknown).call(tool, args, callOptions);
			},
		};
	}
	return out as { [K in keyof T]: Guarded<T[K]> };
}
