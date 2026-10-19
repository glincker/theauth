/**
 * How a client hands input provenance to a server: a JSON body field (`inputs`), an HTTP header, or the MCP `_meta` object of a tool call.
 * Everything here is a claim by the caller. The server hashes what it is given and records it, it does not verify that a source is real. Treat the record as traceability evidence (which inputs the caller says were in context), not as proof.
 * Header form: `TheAuth-Inputs: <base64url of a JSON array>`. Prefer entries with a `hash` over `content`, because content in a header is size capped and may be logged by proxies.
 * MCP form: `_meta["io.theauth/inputs"]` holds the same array (MCP reserves unprefixed `_meta` names for the spec, so a reverse DNS prefix is used).
 */

import { z } from "zod";
import { fromBase64Url, toBase64Url } from "../crypto/web-crypto.js";
import type { InputSource } from "./provenance.js";
import { INPUT_SOURCE_KINDS } from "./provenance.js";

export const INPUTS_HEADER = "theauth-inputs";
export const INPUTS_META_KEY = "io.theauth/inputs";

const MAX_HEADER_CHARS = 8192;
const MAX_CONTENT_CHARS = 65536;

export const InputSourceSchema = z
	.object({
		kind: z.enum(INPUT_SOURCE_KINDS),
		id: z.string().max(256).optional(),
		content: z.string().max(MAX_CONTENT_CHARS).optional(),
		hash: z
			.string()
			.regex(/^[0-9a-f]{64}$/)
			.optional(),
		hashVersion: z.literal(2).optional(),
	})
	.strict()
	.refine((s) => s.content !== undefined || s.hash !== undefined, {
		message: "an input needs content or hash",
	});

export const InputSourcesSchema = z.array(InputSourceSchema).max(32);

/** Validate a decoded value. Undefined for anything malformed, so a bad claim never blocks the call. */
export function parseInputSources(value: unknown): InputSource[] | undefined {
	const parsed = InputSourcesSchema.safeParse(value);
	return parsed.success && parsed.data.length > 0 ? parsed.data : undefined;
}

/** Read the `TheAuth-Inputs` header. Undefined when absent, too long or malformed. */
export function parseInputsHeader(value: string | null | undefined): InputSource[] | undefined {
	if (!value || value.length > MAX_HEADER_CHARS) return undefined;
	try {
		const json = new TextDecoder().decode(fromBase64Url(value.trim()));
		return parseInputSources(JSON.parse(json));
	} catch {
		return undefined;
	}
}

/** Build the header value for a client. */
export function encodeInputsHeader(inputs: readonly InputSource[]): string {
	return toBase64Url(new TextEncoder().encode(JSON.stringify(inputs)));
}

/** Read the inputs from the `_meta` object of an MCP request. */
export function parseInputsMeta(meta: unknown): InputSource[] | undefined {
	if (typeof meta !== "object" || meta === null) return undefined;
	return parseInputSources((meta as Record<string, unknown>)[INPUTS_META_KEY]);
}
