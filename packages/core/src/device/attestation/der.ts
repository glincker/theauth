/**
 * Minimal DER reader (ITU-T X.690) for X.509 and attestation extensions. Definite lengths only,
 * every read is bounds checked, and nothing here allocates more than the input.
 */

export interface Tlv {
	/** Tag class: 0 universal, 1 application, 2 context specific, 3 private. */
	cls: number;
	constructed: boolean;
	/** Tag number, including high tag numbers (X.690 8.1.2.4). */
	tag: number;
	/** The whole element: identifier, length and content. */
	raw: Uint8Array;
	content: Uint8Array;
}

export class DerError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "DerError";
	}
}

/** Read one element at the start of `buf`. Returns it and the number of bytes consumed. */
export function readTlv(buf: Uint8Array): { tlv: Tlv; size: number } {
	let i = 0;
	const first = buf[i++];
	if (first === undefined) throw new DerError("empty input");
	const cls = first >> 6;
	const constructed = (first & 0x20) !== 0;
	let tag = first & 0x1f;
	if (tag === 0x1f) {
		tag = 0;
		for (let n = 0; ; n++) {
			const b = buf[i++];
			if (b === undefined || n > 3) throw new DerError("bad high tag number");
			tag = tag * 128 + (b & 0x7f);
			if ((b & 0x80) === 0) break;
		}
	}
	const lenByte = buf[i++];
	if (lenByte === undefined) throw new DerError("truncated length");
	let length = lenByte;
	if (lenByte & 0x80) {
		const count = lenByte & 0x7f;
		if (count === 0 || count > 4) throw new DerError("unsupported length form");
		length = 0;
		for (let n = 0; n < count; n++) {
			const b = buf[i++];
			if (b === undefined) throw new DerError("truncated length");
			length = length * 256 + b;
		}
	}
	const end = i + length;
	if (end > buf.length) throw new DerError("element runs past its parent");
	return {
		tlv: { cls, constructed, tag, raw: buf.subarray(0, end), content: buf.subarray(i, end) },
		size: end,
	};
}

/** Parse the whole buffer as exactly one element. */
export function parseOne(buf: Uint8Array): Tlv {
	const { tlv, size } = readTlv(buf);
	if (size !== buf.length) throw new DerError("trailing bytes after element");
	return tlv;
}

/** Children of a constructed element, in order. */
export function children(t: Tlv): Tlv[] {
	if (!t.constructed) throw new DerError("not a constructed element");
	const out: Tlv[] = [];
	let rest = t.content;
	while (rest.length > 0) {
		const { tlv, size } = readTlv(rest);
		out.push(tlv);
		rest = rest.subarray(size);
	}
	return out;
}

export function isUniversal(t: Tlv, tag: number): boolean {
	return t.cls === 0 && t.tag === tag;
}

export const TAG = {
	BOOLEAN: 1,
	INTEGER: 2,
	BIT_STRING: 3,
	OCTET_STRING: 4,
	NULL: 5,
	OID: 6,
	ENUMERATED: 10,
	UTF8_STRING: 12,
	SEQUENCE: 16,
	SET: 17,
	UTC_TIME: 23,
	GENERALIZED_TIME: 24,
} as const;

/** Unsigned or signed INTEGER as a bigint. */
export function bigIntOf(t: Tlv): bigint {
	if (t.content.length === 0) throw new DerError("empty INTEGER");
	let v = 0n;
	for (const b of t.content) v = (v << 8n) | BigInt(b);
	if ((t.content[0] ?? 0) & 0x80) v -= 1n << BigInt(8 * t.content.length);
	return v;
}

/** INTEGER or ENUMERATED that must fit in a safe JS integer. */
export function intOf(t: Tlv): number {
	const v = bigIntOf(t);
	if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < BigInt(Number.MIN_SAFE_INTEGER)) {
		throw new DerError("integer out of range");
	}
	return Number(v);
}

export function boolOf(t: Tlv): boolean {
	if (!isUniversal(t, TAG.BOOLEAN) || t.content.length !== 1) throw new DerError("bad BOOLEAN");
	return t.content[0] !== 0;
}

export function oidOf(t: Tlv): string {
	if (!isUniversal(t, TAG.OID) || t.content.length === 0) throw new DerError("bad OID");
	const arcs: number[] = [];
	let v = 0;
	for (const b of t.content) {
		v = v * 128 + (b & 0x7f);
		if (v > Number.MAX_SAFE_INTEGER / 128) throw new DerError("OID arc too large");
		if ((b & 0x80) === 0) {
			if (arcs.length === 0) {
				const first = v < 80 ? Math.floor(v / 40) : 2;
				arcs.push(first, v - first * 40);
			} else arcs.push(v);
			v = 0;
		}
	}
	return arcs.join(".");
}

export function stringOf(t: Tlv): string {
	return new TextDecoder("utf-8", { fatal: true }).decode(t.content);
}

/** The bytes of a BIT STRING without the leading unused-bits octet. */
export function bitStringBytes(t: Tlv): Uint8Array {
	if (!isUniversal(t, TAG.BIT_STRING) || t.content.length === 0)
		throw new DerError("bad BIT STRING");
	return t.content.subarray(1);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	return diff === 0;
}

export function toHexLower(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
