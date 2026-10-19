/**
 * BER to DER normalizer for CMS and PKCS#7 blobs that Apple (and OpenSSL streaming) emit with indefinite lengths. It resolves indefinite lengths, joins the chunks of constructed OCTET STRINGs into one primitive string and re-emits definite lengths, so the strict DER reader in `der.ts` can parse the result. Elements that were already definite and primitive are copied byte for byte, which keeps signed attributes and certificates identical to what was signed.
 */
import { DerError } from "./der.js";

const MAX_DEPTH = 24;
const MAX_SIZE = 1_048_576;

interface Header {
	/** Identifier octets as read. */
	id: Uint8Array;
	constructed: boolean;
	tagNumber: number;
	cls: number;
	/** Content length, or -1 for the indefinite form. */
	length: number;
	/** Offset of the first content byte. */
	start: number;
}

function readHeader(buf: Uint8Array, at: number): Header {
	let i = at;
	const first = buf[i++];
	if (first === undefined) throw new DerError("empty input");
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
	const id = buf.subarray(at, i);
	const lenByte = buf[i++];
	if (lenByte === undefined) throw new DerError("truncated length");
	let length = lenByte;
	if (lenByte === 0x80) length = -1;
	else if (lenByte & 0x80) {
		const count = lenByte & 0x7f;
		if (count > 4) throw new DerError("unsupported length form");
		length = 0;
		for (let n = 0; n < count; n++) {
			const b = buf[i++];
			if (b === undefined) throw new DerError("truncated length");
			length = length * 256 + b;
		}
	}
	return {
		id,
		constructed: (first & 0x20) !== 0,
		tagNumber: tag,
		cls: first >> 6,
		length,
		start: i,
	};
}

function encodeLength(n: number): Uint8Array {
	if (n < 128) return Uint8Array.of(n);
	const bytes: number[] = [];
	for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
	return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function join(parts: Uint8Array[]): Uint8Array {
	const total = parts.reduce((s, p) => s + p.length, 0);
	if (total > MAX_SIZE) throw new DerError("BER input is too large");
	const out = new Uint8Array(total);
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}

interface Node {
	/** The normalized element. */
	bytes: Uint8Array;
	/** Where the next sibling starts in the input. */
	next: number;
	/** Content of a primitive element, for joining OCTET STRING chunks. */
	primitive?: Uint8Array;
}

function element(buf: Uint8Array, at: number, depth: number): Node {
	if (depth > MAX_DEPTH) throw new DerError("BER nesting is too deep");
	const h = readHeader(buf, at);
	if (!h.constructed) {
		if (h.length < 0) throw new DerError("indefinite length on a primitive element");
		const end = h.start + h.length;
		if (end > buf.length) throw new DerError("element runs past its parent");
		return {
			bytes: buf.subarray(at, end),
			next: end,
			primitive: buf.subarray(h.start, end),
		};
	}
	const kids: Node[] = [];
	let i = h.start;
	let next: number;
	if (h.length < 0) {
		for (;;) {
			if (buf[i] === 0 && buf[i + 1] === 0) {
				next = i + 2;
				break;
			}
			if (i >= buf.length) throw new DerError("missing end of contents");
			const k = element(buf, i, depth + 1);
			kids.push(k);
			i = k.next;
		}
	} else {
		const end = h.start + h.length;
		if (end > buf.length) throw new DerError("element runs past its parent");
		while (i < end) {
			const k = element(buf.subarray(0, end), i, depth + 1);
			kids.push(k);
			i = k.next;
		}
		next = end;
	}
	// Constructed OCTET STRING (universal 4): one primitive string of the joined chunks.
	if (h.cls === 0 && h.tagNumber === 4) {
		const body = join(kids.map((k) => k.primitive ?? new Uint8Array()));
		const id = Uint8Array.of(0x04);
		return { bytes: join([id, encodeLength(body.length), body]), next, primitive: body };
	}
	const body = join(kids.map((k) => k.bytes));
	return { bytes: join([h.id, encodeLength(body.length), body]), next };
}

/** Normalize one BER element that spans the whole input. */
export function berToDer(input: Uint8Array): Uint8Array {
	const node = element(input, 0, 0);
	if (node.next !== input.length) throw new DerError("trailing bytes after element");
	return node.bytes;
}
