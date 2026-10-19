/**
 * Canonical JSON for the approval hash, byte for byte what theauth-go writes with
 * `json.Marshal` over a map decoded from JSON (`policy/toolguard/approval_hash.go`):
 *
 * - object keys sorted by UTF-8 bytes at every depth (not UTF-16 code units),
 * - strings escaped like Go: `<`, `>`, `&`, U+2028 and U+2029 as `\u00XX` escapes, `\b` and `\f`
 *   as short escapes, a lone surrogate replaced by U+FFFD (what UTF-8 transport does to it),
 * - numbers as float64 text (`-0` stays `-0`), a bigint as its decimal digits,
 * - NaN and Infinity throw, Go's encoder rejects them too (the old behavior of writing `null`
 *   made `{amount: NaN}` hash like `{amount: null}`),
 * - an object property that is `undefined` is left out, an array element that is `undefined`
 *   becomes `null`, as `JSON.stringify` does.
 *
 * A `Date` becomes its ISO 8601 string (Go would write RFC 3339 with trimmed zeros, so keep dates
 * out of cross language arguments). Shared vectors: tests/fixtures/approval-hash-vectors.json.
 */

import { compareBytes, goJsonString } from "../audit/go-chain-verify.js";

const HAS_SURROGATE = /[\ud800-\udfff]/;

/** What a UTF-8 transport does to a lone surrogate: it becomes U+FFFD, which Go then reads as such. */
function wellFormed(s: string): string {
	if (!HAS_SURROGATE.test(s)) return s;
	return s.replace(/[\ud800-\udbff][\udc00-\udfff]|[\ud800-\udfff]/g, (m) =>
		m.length === 2 ? m : "\ufffd",
	);
}

const str = (s: string): string => goJsonString(wellFormed(s));

export function canonicalApprovalJson(value: unknown): string {
	return encode(value, new WeakSet<object>());
}

function encode(value: unknown, path: WeakSet<object>): string {
	if (value === null || value === undefined) return "null";
	switch (typeof value) {
		case "string":
			return str(value);
		case "boolean":
			return value ? "true" : "false";
		case "bigint":
			return value.toString();
		case "number":
			if (!Number.isFinite(value)) throw new TypeError("canonicalApprovalJson: non-finite number");
			return Object.is(value, -0) ? "-0" : String(value);
		case "object":
			break;
		default:
			throw new TypeError(`canonicalApprovalJson: unsupported ${typeof value}`);
	}
	const obj = value as object;
	if (obj instanceof Date) return str(obj.toISOString());
	if (path.has(obj)) throw new TypeError("canonicalApprovalJson: circular reference");
	path.add(obj);
	try {
		if (Array.isArray(obj)) return `[${obj.map((v) => encode(v, path)).join(",")}]`;
		const rec = obj as Record<string, unknown>;
		const parts: string[] = [];
		for (const key of Object.keys(rec).sort(compareBytes)) {
			const v = rec[key];
			if (v === undefined) continue;
			parts.push(`${str(key)}:${encode(v, path)}`);
		}
		return `{${parts.join(",")}}`;
	} finally {
		path.delete(obj);
	}
}
