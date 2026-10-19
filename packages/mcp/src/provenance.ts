import { z } from "zod";

/**
 * Input provenance for admin MCP calls. A client that knows where the inputs of a tool call came from (the user message, a retrieved document, another tool's output) passes them in the request `_meta`, and the server writes them into the audit row next to the call. The deployment hashes the content with its audit key, it is never stored.
 * The claim comes from the caller and is not verified here. Same shape as `TheAuth-Inputs` in the core package (`parseInputsMeta`).
 */
export const INPUTS_META_KEY = "io.theauth/inputs";

const SourceSchema = z
	.object({
		kind: z.enum(["user_message", "tool_output", "retrieved_document", "agent"]),
		id: z.string().max(256).optional(),
		content: z.string().max(65536).optional(),
		hash: z
			.string()
			.regex(/^[0-9a-f]{64}$/)
			.optional(),
		hashVersion: z.literal(2).optional(),
	})
	.strict()
	.refine((s) => s.content !== undefined || s.hash !== undefined);

export type InputSource = z.infer<typeof SourceSchema>;

const SourcesSchema = z.array(SourceSchema).min(1).max(32);

/** Inputs from the `_meta` of a tool call, or undefined when absent or malformed (a bad claim never fails the call). */
export function readInputsMeta(extra: unknown): InputSource[] | undefined {
	if (typeof extra !== "object" || extra === null) return undefined;
	const meta = (extra as { _meta?: unknown })._meta;
	if (typeof meta !== "object" || meta === null) return undefined;
	const parsed = SourcesSchema.safeParse((meta as Record<string, unknown>)[INPUTS_META_KEY]);
	return parsed.success ? parsed.data : undefined;
}
