/**
 * Read-only verifier for audit chains exported by theauth-go (internal/audit ChainHashVersion 1).
 *
 * The Go chain is a different format from the TypeScript chain in `chain.ts`: one chain per
 * organization, plain SHA-256 over the `json.Marshal` bytes of a fixed-order struct, `seq` inside
 * the payload, `createdAt` in microseconds. This module recomputes those bytes exactly, so it
 * replicates Go's encoder rules: struct key order, HTML-escaped strings, byte-sorted map keys,
 * float64 number formatting. Runs on Web Crypto only.
 */

/** Hash version this verifier understands (Go `ChainHashVersion`). */
export const GO_CHAIN_HASH_VERSION = 1;

/** One audit row in the Go export shape (`models.AuditEvent` JSON plus the hashed pseudonyms). */
export interface GoAuditRow {
	id: string;
	organizationId?: string | null;
	actorUserId?: string | null;
	actorSessionId?: string | null;
	action: string;
	targetType?: string | null;
	targetId?: string | null;
	metadata?: Record<string, unknown> | null;
	ip?: string | null;
	userAgent?: string | null;
	/** RFC 3339 with up to nanosecond digits, as Go writes it. Only microseconds are hashed. */
	createdAt: string;
	subjectId?: string | null;
	actorId?: string | null;
	policyVersion?: string | null;
	approverId?: string | null;
	delegationChain?: string[] | null;
	inputProvenance?: Record<string, unknown> | null;
	chainSeq?: number | null;
	prevHash?: string | null;
	hash?: string | null;
	/** Absent means 1. Anything else is reported as unsupported_hash_version. */
	hashVersion?: number | null;
	/** Stored pseudonyms. Needed for erased rows, optional when `pseudonymSecret` is given. */
	actorUserPseudonym?: string | null;
	subjectPseudonym?: string | null;
	actorPseudonym?: string | null;
	approverPseudonym?: string | null;
}

export type GoChainFailureReason =
	| "malformed_row"
	| "unsupported_hash_version"
	| "seq_duplicate"
	| "seq_gap"
	| "prev_hash_mismatch"
	| "hash_mismatch"
	| "missing_pseudonym_input"
	| "pseudonym_mismatch";

export interface GoChainFailure {
	reason: GoChainFailureReason;
	chainKey: string;
	rowId: string;
	seq: number;
	/** Index of the row in the input array. */
	index: number;
	detail?: string;
}

export interface GoChainVerifyOptions {
	/** The installation pseudonym secret (raw bytes, or hex). Enables raw id vs pseudonym checks. */
	pseudonymSecret?: Uint8Array | string;
	/**
	 * Treat the first row seen for each chain as trusted for `seq` and `prev` (verifying an export
	 * window instead of a whole chain). Default false.
	 */
	allowPartialStart?: boolean;
}

export interface GoChainVerifyResult {
	ok: boolean;
	/** Rows with a hash that were examined (up to and including the first failure). */
	checked: number;
	/** Rows without a hash (written before the chain existed), skipped. */
	unchained: number;
	/** Checked rows whose raw ids are blank while a pseudonym is hashed (GDPR erasure). */
	erased: number;
	/** Distinct chain keys seen. */
	chains: number;
	/** Checked rows whose pseudonyms were trusted as given, with no secret to recompute them. */
	pseudonymsUnchecked: number;
	firstFailure?: GoChainFailure;
}

const encoder = new TextEncoder();

function hex(bytes: ArrayBuffer): string {
	let out = "";
	for (const b of new Uint8Array(bytes)) out += b.toString(16).padStart(2, "0");
	return out;
}

/** Go `encoding/json` string encoding with HTML escaping on (the `json.Marshal` default). */
export function goJsonString(s: string): string {
	let out = '"';
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
			const d = s.charCodeAt(i + 1);
			if (d >= 0xdc00 && d <= 0xdfff) {
				out += s.slice(i, i + 2);
				i++;
				continue;
			}
		}
		if (c >= 0xd800 && c <= 0xdfff) {
			out += "\\ufffd";
			continue;
		}
		switch (c) {
			case 0x22:
				out += '\\"';
				break;
			case 0x5c:
				out += "\\\\";
				break;
			case 0x0a:
				out += "\\n";
				break;
			case 0x0d:
				out += "\\r";
				break;
			case 0x09:
				out += "\\t";
				break;
			case 0x08:
				out += "\\b";
				break;
			case 0x0c:
				out += "\\f";
				break;
			case 0x3c:
			case 0x3e:
			case 0x26:
			case 0x2028:
			case 0x2029:
				out += `\\u${c.toString(16).padStart(4, "0")}`;
				break;
			default:
				out += c < 0x20 ? `\\u${c.toString(16).padStart(4, "0")}` : s[i];
		}
	}
	return `${out}"`;
}

function compareBytes(a: string, b: string): number {
	const x = encoder.encode(a);
	const y = encoder.encode(b);
	const n = Math.min(x.length, y.length);
	for (let i = 0; i < n; i++) {
		const d = (x[i] ?? 0) - (y[i] ?? 0);
		if (d !== 0) return d;
	}
	return x.length - y.length;
}

/** Go `json.Marshal` of a value decoded from JSON (map keys sorted by UTF-8 bytes, float64 numbers). */
export function goMarshal(value: unknown): string {
	if (value === null || value === undefined) return "null";
	if (typeof value === "string") return goJsonString(value);
	if (typeof value === "boolean") return value ? "true" : "false";
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error("non-finite number");
		return Object.is(value, -0) ? "-0" : String(value);
	}
	if (Array.isArray(value)) return `[${value.map(goMarshal).join(",")}]`;
	if (typeof value === "object") {
		const o = value as Record<string, unknown>;
		const keys = Object.keys(o).sort(compareBytes);
		return `{${keys.map((k) => `${goJsonString(k)}:${goMarshal(o[k])}`).join(",")}}`;
	}
	throw new Error(`unsupported value type ${typeof value}`);
}

const RFC3339 =
	/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;

/** Unix microseconds of an RFC 3339 timestamp (`time.UnixMicro` truncates sub-microsecond digits). */
export function parseMicros(ts: string): bigint | null {
	const m = RFC3339.exec(ts);
	if (!m) return null;
	const [, y, mo, d, h, mi, s, frac = "", zone = "Z"] = m;
	const base = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
	if (Number.isNaN(base)) return null;
	let offsetMin = 0;
	if (zone !== "Z") {
		offsetMin =
			(zone.startsWith("-") ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4)));
	}
	const seconds = BigInt(base / 1000) - BigInt(offsetMin * 60);
	const micros = BigInt(frac.padEnd(6, "0").slice(0, 6));
	return seconds * 1_000_000n + micros;
}

async function hmacHex(key: Uint8Array, message: string): Promise<string> {
	const k = await crypto.subtle.importKey(
		"raw",
		key as BufferSource,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return hex(await crypto.subtle.sign("HMAC", k, encoder.encode(message)));
}

/** `HMAC-SHA256(secret, "theauth.audit.pseudonym.v1:" + id)` in hex, empty ids stay empty. */
export async function goPseudonym(secret: Uint8Array, id: string): Promise<string> {
	return id === "" ? "" : hmacHex(secret, `theauth.audit.pseudonym.v1:${id}`);
}

function secretBytes(s: Uint8Array | string | undefined): Uint8Array | null {
	if (s === undefined) return null;
	if (typeof s !== "string") return s;
	if (!/^(?:[0-9a-fA-F]{2})+$/.test(s)) throw new Error("pseudonymSecret string must be hex");
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
	return out;
}

const str = (v: string | null | undefined): string => v ?? "";

interface Pseudonyms {
	actorUser: string;
	subject: string;
	actor: string;
	approver: string;
}

/** Marshal of `ChainPayload` in Go struct order. Strings are the stored JSON text, escaped again. */
function payloadString(row: GoAuditRow, chainKey: string, seq: number, p: Pseudonyms): string {
	const micros = parseMicros(row.createdAt);
	if (micros === null) throw new Error("createdAt is not RFC 3339");
	const meta = row.metadata == null ? "{}" : goMarshal(row.metadata);
	const chain = row.delegationChain == null ? "[]" : goMarshal(row.delegationChain);
	const prov = row.inputProvenance == null ? "{}" : goMarshal(row.inputProvenance);
	const s = goJsonString;
	return (
		`{"v":${GO_CHAIN_HASH_VERSION},"chainKey":${s(chainKey)},"seq":${seq},"prev":${s(str(row.prevHash))},` +
		`"id":${s(row.id)},"org":${s(chainKey)},"actorUserPseudonym":${s(p.actorUser)},` +
		`"actorSession":${s(str(row.actorSessionId))},"action":${s(row.action)},` +
		`"targetType":${s(str(row.targetType))},"targetId":${s(str(row.targetId))},"metadata":${s(meta)},` +
		`"ip":${s(str(row.ip))},"userAgent":${s(str(row.userAgent))},"createdAt":${micros.toString()},` +
		`"subjectPseudonym":${s(p.subject)},"actorPseudonym":${s(p.actor)},` +
		`"policyVersion":${s(str(row.policyVersion))},"approverPseudonym":${s(p.approver)},` +
		`"delegationChain":${s(chain)},"inputProvenance":${s(prov)}}`
	);
}

function isRecord(v: unknown): boolean {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Returns a problem description when the row cannot be hashed, else null. */
function malformed(row: GoAuditRow): string | null {
	if (!isRecord(row)) return "row is not an object";
	if (typeof row.id !== "string" || row.id === "") return "id missing";
	if (typeof row.action !== "string") return "action missing";
	if (typeof row.createdAt !== "string" || parseMicros(row.createdAt) === null) {
		return "createdAt missing or not RFC 3339";
	}
	if (typeof row.chainSeq !== "number" || !Number.isSafeInteger(row.chainSeq) || row.chainSeq < 1) {
		return "chainSeq missing or not a positive integer";
	}
	if (typeof row.hash !== "string") return "hash missing";
	for (const k of ["metadata", "inputProvenance"] as const) {
		const v = row[k];
		if (v != null && !isRecord(v)) return `${k} is not an object`;
	}
	if (row.delegationChain != null && !Array.isArray(row.delegationChain)) {
		return "delegationChain is not an array";
	}
	return null;
}

async function resolvePseudonyms(
	row: GoAuditRow,
	secret: Uint8Array | null,
): Promise<{ p: Pseudonyms; erased: boolean; unchecked: boolean; missing?: string; raw: Pair[] }> {
	const pairs: Pair[] = [
		{ name: "actorUserId", raw: str(row.actorUserId), given: row.actorUserPseudonym },
		{ name: "subjectId", raw: str(row.subjectId), given: row.subjectPseudonym },
		{ name: "actorId", raw: str(row.actorId), given: row.actorPseudonym },
		{ name: "approverId", raw: str(row.approverId), given: row.approverPseudonym },
	];
	const out: string[] = [];
	let missing: string | undefined;
	let unchecked = false;
	let erased = false;
	for (const c of pairs) {
		let value: string;
		if (typeof c.given === "string") {
			value = c.given;
			if (c.raw !== "" && secret === null) unchecked = true;
		} else if (c.raw === "") {
			value = "";
		} else if (secret !== null) {
			value = await goPseudonym(secret, c.raw);
		} else {
			value = "";
			missing ??= `${c.name} is set but no pseudonym and no pseudonymSecret was given`;
		}
		if (c.raw === "" && value !== "") erased = true;
		out.push(value);
	}
	const [actorUser = "", subject = "", actor = "", approver = ""] = out;
	return { p: { actorUser, subject, actor, approver }, erased, unchecked, missing, raw: pairs };
}

interface Pair {
	name: string;
	raw: string;
	given: string | null | undefined;
}

/**
 * Compute the exact Go pre-image string of a row. `chainKey` is the organization id or "".
 * Throws on a malformed row. Exposed for byte-level diffing against the Go vectors.
 */
export async function goChainPayload(
	row: GoAuditRow,
	options: GoChainVerifyOptions = {},
): Promise<string> {
	const problem = malformed(row);
	if (problem) throw new Error(problem);
	const secret = secretBytes(options.pseudonymSecret);
	const r = await resolvePseudonyms(row, secret);
	if (r.missing) throw new Error(r.missing);
	return payloadString(row, str(row.organizationId), row.chainSeq as number, r.p);
}

async function sha256Hex(text: string): Promise<string> {
	return hex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}

interface ChainState {
	wantSeq: number;
	wantPrev: string;
	lastSeq: number;
}

/**
 * Verify rows exported by theauth-go. Rows of one chain (organization id, or "" for global events)
 * must appear in chain order, chains may be interleaved. Reports the first failure and stops.
 * Check order matches Go's verifier: seq, prev, hash, then pseudonyms.
 */
export async function verifyGoAuditChain(
	rows: readonly GoAuditRow[],
	options: GoChainVerifyOptions = {},
): Promise<GoChainVerifyResult> {
	const secret = secretBytes(options.pseudonymSecret);
	const result: GoChainVerifyResult = {
		ok: true,
		checked: 0,
		unchained: 0,
		erased: 0,
		chains: 0,
		pseudonymsUnchecked: 0,
	};
	const states = new Map<string, ChainState>();
	for (let index = 0; index < rows.length; index++) {
		const row = rows[index] as GoAuditRow;
		const fail = (reason: GoChainFailureReason, detail?: string): GoChainVerifyResult => {
			result.ok = false;
			result.firstFailure = {
				reason,
				chainKey: isRecord(row) ? str(row.organizationId) : "",
				rowId: isRecord(row) && typeof row.id === "string" ? row.id : "",
				seq: isRecord(row) && typeof row.chainSeq === "number" ? row.chainSeq : 0,
				index,
				...(detail === undefined ? {} : { detail }),
			};
			return result;
		};
		if (isRecord(row) && !row.hash && !row.chainSeq) {
			result.unchained++;
			continue;
		}
		const problem = malformed(row);
		if (problem) {
			result.checked++;
			return fail("malformed_row", problem);
		}
		result.checked++;
		if (row.hashVersion != null && row.hashVersion !== GO_CHAIN_HASH_VERSION) {
			return fail("unsupported_hash_version", `hashVersion ${String(row.hashVersion)}`);
		}
		const chainKey = str(row.organizationId);
		const seq = row.chainSeq as number;
		let state = states.get(chainKey);
		if (!state) {
			state = options.allowPartialStart
				? { wantSeq: seq, wantPrev: str(row.prevHash), lastSeq: seq - 1 }
				: { wantSeq: 1, wantPrev: "", lastSeq: 0 };
			states.set(chainKey, state);
			result.chains++;
		}
		if (seq !== state.wantSeq) {
			return fail(seq === state.lastSeq ? "seq_duplicate" : "seq_gap", `want seq ${state.wantSeq}`);
		}
		if (str(row.prevHash) !== state.wantPrev) return fail("prev_hash_mismatch");
		const ps = await resolvePseudonyms(row, secret);
		if (ps.missing) return fail("missing_pseudonym_input", ps.missing);
		if ((await sha256Hex(payloadString(row, chainKey, seq, ps.p))) !== row.hash) {
			return fail("hash_mismatch");
		}
		if (secret !== null) {
			for (const c of ps.raw) {
				if (
					c.raw !== "" &&
					typeof c.given === "string" &&
					(await goPseudonym(secret, c.raw)) !== c.given
				) {
					return fail("pseudonym_mismatch", c.name);
				}
			}
		} else if (ps.unchecked) {
			result.pseudonymsUnchecked++;
		}
		if (ps.erased) result.erased++;
		state.lastSeq = seq;
		state.wantSeq = seq + 1;
		state.wantPrev = row.hash as string;
	}
	return result;
}
