/**
 * Input provenance for audit rows: where the inputs of a call came from, as kind, optional id and a content hash. The content itself is never stored, only a hash. Version 2 hashes are HMAC-SHA-256 under a subkey derived (HKDF, RFC 5869) from the audit key, so someone who reads the table cannot confirm a guess at short content without the key. Version 1 hashes (plain domain prefixed SHA-256, no `hv` field) from wave 8 rows still verify and still match queries.
 * The record is written to `input_provenance` (covered by the chain hash on version 2 rows). `keys` repeats each source as `<kind>:<hash>` so the audit query can filter on it with a plain substring match on every database.
 */

import { hmacSha256, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { getAuditChainConfig } from "./chain.js";
import { resolvePseudonymKey } from "./pseudonym.js";

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
	/** Set to 2 when `hash` is already a keyed version 2 hash (from `hashInputContent`). */
	hashVersion?: 2;
}

export interface InputSourceRecord {
	kind: InputSourceKind;
	id?: string;
	hash: string;
	/** Hash version. 2 is the keyed HMAC. Absent means the plain SHA-256 of version 1 rows. */
	hv?: 2;
}

export type InputProvenanceRecord = {
	sources: InputSourceRecord[];
	keys: string[];
};

/** Filter on `AuditFilter.provenance`. Both fields narrow the match. */
export interface ProvenanceFilter {
	kind?: InputSourceKind;
	/** Lowercase hex hash of the content, exactly as stored. */
	hash?: string;
	/** Raw content to look for. The query hashes it with the audit key (keyed and plain forms) and matches either, so the caller needs no key. */
	content?: string;
}

const MAX_SOURCES = 32;
const MAX_ID_LENGTH = 256;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const KIND_SET: ReadonlySet<string> = new Set(INPUT_SOURCE_KINDS);

export function isInputSourceKind(value: unknown): value is InputSourceKind {
	return typeof value === "string" && KIND_SET.has(value);
}

const SUBKEY_INFO = "theauth.audit.input.v2";
const PLAIN_PREFIX = "theauth.audit.input.v1:";

/** Version 1 hash: SHA-256 of the content with a domain prefix. Unkeyed, kept to verify and query old rows. */
export async function hashInputContentPlain(content: string): Promise<string> {
	return sha256(`${PLAIN_PREFIX}${content}`);
}

/** Derive the provenance subkey from the audit key with HKDF-SHA-256 (RFC 5869). The chain key itself is never used to hash content. Returns lowercase hex. */
export async function deriveProvenanceKey(auditKey: string): Promise<string> {
	const enc = new TextEncoder();
	const base = await globalThis.crypto.subtle.importKey(
		"raw",
		enc.encode(auditKey),
		"HKDF",
		false,
		["deriveBits"],
	);
	const bits = await globalThis.crypto.subtle.deriveBits(
		{ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(SUBKEY_INFO) },
		base,
		256,
	);
	return Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Version 2 hash: HMAC-SHA-256 of the content under the provenance subkey. */
export async function hashInputContent(content: string, auditKey: string): Promise<string> {
	return hmacSha256(await deriveProvenanceKey(auditKey), content);
}

/** The key provenance hashes are derived from: `audit.hmacKey` when set, else the installation secret. */
export async function resolveProvenanceAuditKey(db: Database): Promise<string | undefined> {
	return resolvePseudonymKey(db, getAuditChainConfig(db)?.hmacKey, true);
}

/** Check content against a stored source record, honoring its hash version. */
export async function verifyInputHash(
	content: string,
	record: Pick<InputSourceRecord, "hash" | "hv">,
	auditKey: string,
): Promise<boolean> {
	const expected =
		record.hv === 2
			? await hashInputContent(content, auditKey)
			: await hashInputContentPlain(content);
	return expected === record.hash;
}

async function toRecord(
	source: InputSource,
	auditKey: string | undefined,
): Promise<InputSourceRecord | undefined> {
	if (!source || !isInputSourceKind(source.kind)) return undefined;
	let hash: string | undefined;
	let hv: 2 | undefined;
	if (typeof source.content === "string") {
		if (auditKey) {
			hash = await hashInputContent(source.content, auditKey);
			hv = 2;
		} else hash = await hashInputContentPlain(source.content);
	} else if (typeof source.hash === "string" && HASH_PATTERN.test(source.hash)) {
		hash = source.hash;
		// A caller supplied hash is stored as given. Version 2 only when the caller says so.
		if (source.hashVersion === 2) hv = 2;
	}
	if (!hash) return undefined;
	const id =
		typeof source.id === "string" && source.id !== ""
			? source.id.slice(0, MAX_ID_LENGTH)
			: undefined;
	return { kind: source.kind, ...(id ? { id } : {}), hash, ...(hv ? { hv } : {}) };
}

/** Normalize caller supplied inputs into the stored record. With `auditKey`, content is hashed with the keyed version 2 hash, otherwise with the plain version 1 hash. Entries with a bad kind or without content or hash are dropped. Undefined when nothing is left. */
export async function buildInputProvenance(
	inputs: readonly InputSource[] | undefined,
	auditKey?: string,
): Promise<InputProvenanceRecord | undefined> {
	if (!Array.isArray(inputs) || inputs.length === 0) return undefined;
	const sources: InputSourceRecord[] = [];
	const keys: string[] = [];
	for (const input of inputs.slice(0, MAX_SOURCES)) {
		const rec = await toRecord(input, auditKey);
		if (!rec) continue;
		const key = `${rec.kind}:${rec.hash}`;
		if (keys.includes(key)) continue;
		keys.push(key);
		sources.push(rec);
	}
	return sources.length > 0 ? { sources, keys } : undefined;
}

/** `buildInputProvenance` with the keyed hash for this database. Falls back to the plain hash when no key can be resolved, so a key lookup failure never loses the row. */
export async function captureInputProvenance(
	db: Database,
	inputs: readonly InputSource[] | undefined,
): Promise<InputProvenanceRecord | undefined> {
	if (!Array.isArray(inputs) || inputs.length === 0) return undefined;
	let key: string | undefined;
	try {
		key = await resolveProvenanceAuditKey(db);
	} catch {
		key = undefined;
	}
	return buildInputProvenance(inputs, key);
}

/** Add captured sources to an existing provenance record (the taint labels), keeping its other fields. */
export function withInputSources(
	base: Record<string, unknown> | undefined,
	captured: InputProvenanceRecord | undefined,
): Record<string, unknown> | undefined {
	if (!captured) return base;
	return { ...(base ?? {}), sources: captured.sources, keys: captured.keys };
}

/** Substrings of which a stored record contains one when it matches the filter. Empty when the filter is empty. `extraHashes` are the hashes of `filter.content` (keyed and plain). Hex and kind names carry no LIKE wildcards. */
export function provenanceNeedles(
	filter: ProvenanceFilter,
	extraHashes: readonly string[] = [],
): string[] {
	const kind = filter.kind;
	if (kind !== undefined && !isInputSourceKind(kind))
		throw new TypeError("invalid provenance kind");
	if (filter.hash !== undefined && !HASH_PATTERN.test(filter.hash)) {
		throw new TypeError("provenance hash must be 64 lowercase hex characters");
	}
	const hashes = [...(filter.hash ? [filter.hash] : []), ...extraHashes];
	if (hashes.length > 0) {
		return hashes.map((h) => (kind ? `"${kind}:${h}"` : `:${h}"`));
	}
	return kind ? [`"${kind}:`] : [];
}

/** Hashes to search for when the filter carries raw `content`. */
export async function provenanceContentHashes(
	db: Database,
	filter: ProvenanceFilter,
): Promise<string[]> {
	if (typeof filter.content !== "string") return [];
	const out = [await hashInputContentPlain(filter.content)];
	const key = await resolveProvenanceAuditKey(db);
	if (key) out.push(await hashInputContent(filter.content, key));
	return out;
}
