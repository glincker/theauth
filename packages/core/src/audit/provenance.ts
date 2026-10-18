/**
 * Input provenance for audit rows: where the inputs of a call came from, as kind, optional id and a content hash. The content itself is never stored, only its SHA-256, so a row can prove that a given message or document was an input without keeping it.
 * The record is written to `input_provenance` (covered by the chain hash on version 2 rows). `keys` repeats each source as `<kind>:<hash>` so the audit query can filter on it with a plain substring match on every database.
 */

import { sha256 } from "../crypto/web-crypto.js";

export const INPUT_SOURCE_KINDS = [
	"user_message",
	"tool_output",
	"retrieved_document",
	"agent",
] as const;
export type InputSourceKind = (typeof INPUT_SOURCE_KINDS)[number];

/** One input to a call. Give `content` (hashed here, then dropped) or a `hash` computed elsewhere. */
export interface InputSource {
	kind: InputSourceKind;
	/** Identifier of the source, for example a message id or a tool call id. Stored as given. */
	id?: string;
	/** The raw content. Hashed and discarded, never stored. */
	content?: string;
	/** Lowercase hex SHA-256 of the content, when the caller already has it. */
	hash?: string;
}

export interface InputSourceRecord {
	kind: InputSourceKind;
	id?: string;
	hash: string;
}

export type InputProvenanceRecord = {
	sources: InputSourceRecord[];
	keys: string[];
};

/** Filter on `AuditFilter.provenance`. Both fields narrow the match. */
export interface ProvenanceFilter {
	kind?: InputSourceKind;
	/** Lowercase hex SHA-256 of the content. Use `hashInputContent` to compute it. */
	hash?: string;
}

const MAX_SOURCES = 32;
const MAX_ID_LENGTH = 256;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const KIND_SET: ReadonlySet<string> = new Set(INPUT_SOURCE_KINDS);

export function isInputSourceKind(value: unknown): value is InputSourceKind {
	return typeof value === "string" && KIND_SET.has(value);
}

/** SHA-256 of the content with a domain prefix, as stored in `hash`. */
export async function hashInputContent(content: string): Promise<string> {
	return sha256(`theauth.audit.input.v1:${content}`);
}

async function toRecord(source: InputSource): Promise<InputSourceRecord | undefined> {
	if (!source || !isInputSourceKind(source.kind)) return undefined;
	let hash: string | undefined;
	if (typeof source.content === "string") hash = await hashInputContent(source.content);
	else if (typeof source.hash === "string" && HASH_PATTERN.test(source.hash)) hash = source.hash;
	if (!hash) return undefined;
	const id =
		typeof source.id === "string" && source.id !== ""
			? source.id.slice(0, MAX_ID_LENGTH)
			: undefined;
	return { kind: source.kind, ...(id ? { id } : {}), hash };
}

/** Normalize caller supplied inputs into the stored record. Entries with a bad kind or without content or hash are dropped. Undefined when nothing is left. */
export async function buildInputProvenance(
	inputs: readonly InputSource[] | undefined,
): Promise<InputProvenanceRecord | undefined> {
	if (!Array.isArray(inputs) || inputs.length === 0) return undefined;
	const sources: InputSourceRecord[] = [];
	const keys: string[] = [];
	for (const input of inputs.slice(0, MAX_SOURCES)) {
		const rec = await toRecord(input);
		if (!rec) continue;
		const key = `${rec.kind}:${rec.hash}`;
		if (keys.includes(key)) continue;
		keys.push(key);
		sources.push(rec);
	}
	return sources.length > 0 ? { sources, keys } : undefined;
}

/** Add captured sources to an existing provenance record (the taint labels), keeping its other fields. */
export function withInputSources(
	base: Record<string, unknown> | undefined,
	captured: InputProvenanceRecord | undefined,
): Record<string, unknown> | undefined {
	if (!captured) return base;
	return { ...(base ?? {}), sources: captured.sources, keys: captured.keys };
}

/** Substring that a stored record contains when it matches the filter, or undefined when the filter is empty or invalid. Hex and kind names carry no LIKE wildcards. */
export function provenanceNeedle(filter: ProvenanceFilter): string | undefined {
	const kind = filter.kind;
	const hash = filter.hash;
	if (kind !== undefined && !isInputSourceKind(kind))
		throw new TypeError("invalid provenance kind");
	if (hash !== undefined && !HASH_PATTERN.test(hash)) {
		throw new TypeError("provenance hash must be 64 lowercase hex characters");
	}
	if (kind && hash) return `"${kind}:${hash}"`;
	if (hash) return `:${hash}"`;
	if (kind) return `"${kind}:`;
	return undefined;
}
