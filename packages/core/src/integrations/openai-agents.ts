// OpenAI Agents SDK style function tool guard. Structural types only. `@openai/agents` is not imported.
// Guard the plain definition first, then pass the result to the SDK's `tool()`.

import type { GateOptions, ToolDenial } from "./gate.js";
import { createGate } from "./gate.js";

/** A function tool definition: a name plus `execute(input, context)`. Extra properties are kept. */
export interface FunctionToolLike<I = never, X = never, R = unknown> {
	name: string;
	execute: (input: I, context?: X) => R | Promise<R>;
}

export type GuardFunctionToolOptions<C = unknown> = GateOptions<C> & {
	/** Turn a denial into the tool result. Default: return the `ToolDenial` object, which the SDK serializes for the model. */
	formatDenial?: (denial: ToolDenial) => unknown;
};

/** Wrap one function tool definition so `authorize` runs before `execute`. The run context is passed to `agentId` as `ctx`. */
export function guardFunctionTool<T extends FunctionToolLike, C = unknown>(
	definition: T,
	options: GuardFunctionToolOptions<C>,
): T {
	const gate = createGate<C>(options);
	const original = definition.execute as (input: unknown, context?: unknown) => unknown;
	const execute = async (input: unknown, context?: unknown): Promise<unknown> => {
		const refused = await gate.check(definition.name, input, context as C | undefined);
		if (refused) return options.formatDenial ? options.formatDenial(refused) : refused;
		return original.call(definition, input, context);
	};
	return { ...definition, execute } as T;
}

/** Guard a list of function tool definitions with the same options. */
export function guardFunctionTools<T extends FunctionToolLike, C = unknown>(
	definitions: readonly T[],
	options: GuardFunctionToolOptions<C>,
): T[] {
	return definitions.map((definition) => guardFunctionTool(definition, options));
}
