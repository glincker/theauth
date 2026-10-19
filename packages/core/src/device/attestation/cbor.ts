/**
 * Strict CBOR reader (RFC 8949) for attestation objects. Unlike the general decoder it reports how many bytes an item used (WebAuthn style authenticator data puts a CBOR key in the middle of a byte string), refuses duplicate map keys, indefinite lengths, floats and 64 bit integers beyond 2^53, and caps depth and size.
 */

const MAX_SIZE = 1_048_576;
const MAX_DEPTH = 16;

export class CborError extends Error {
	constructor(message: string) {
		super(`CBOR: ${message}`);
		this.name = "CborError";
	}
}

interface State {
	data: Uint8Array;
	offset: number;
}

function take(s: State, n: number): Uint8Array {
	if (n > s.data.length - s.offset) throw new CborError("unexpected end of data");
	const out = s.data.subarray(s.offset, s.offset + n);
	s.offset += n;
	return out;
}

function readArgument(s: State, info: number): number {
	if (info < 24) return info;
	if (info > 27) throw new CborError("indefinite or reserved length form");
	const bytes = take(s, 2 ** (info - 24));
	let v = 0;
	for (const b of bytes) v = v * 256 + b;
	if (!Number.isSafeInteger(v)) throw new CborError("integer beyond 2^53");
	return v;
}

function item(s: State, depth: number): unknown {
	if (depth > MAX_DEPTH) throw new CborError("nesting too deep");
	const head = take(s, 1)[0] as number;
	const major = head >> 5;
	const info = head & 0x1f;
	switch (major) {
		case 0:
			return readArgument(s, info);
		case 1:
			return -1 - readArgument(s, info);
		case 2:
			return take(s, readArgument(s, info)).slice();
		case 3:
			return new TextDecoder("utf-8", { fatal: true }).decode(take(s, readArgument(s, info)));
		case 4: {
			const count = readArgument(s, info);
			if (count > s.data.length - s.offset) throw new CborError("array longer than input");
			const out: unknown[] = [];
			for (let i = 0; i < count; i++) out.push(item(s, depth + 1));
			return out;
		}
		case 5: {
			const count = readArgument(s, info);
			if (count > s.data.length - s.offset) throw new CborError("map longer than input");
			const out = new Map<string | number, unknown>();
			for (let i = 0; i < count; i++) {
				const key = item(s, depth + 1);
				if (typeof key !== "string" && typeof key !== "number") throw new CborError("map key type");
				if (out.has(key)) throw new CborError("duplicate map key");
				out.set(key, item(s, depth + 1));
			}
			return out;
		}
		case 7:
			if (info === 20) return false;
			if (info === 21) return true;
			if (info === 22) return null;
			throw new CborError("unsupported simple or float value");
		default:
			throw new CborError(`unsupported major type ${major}`);
	}
}

/** Decode the item at the start of `data`. Returns it and the bytes it used. */
export function decodeCborPrefix(data: Uint8Array): { value: unknown; size: number } {
	if (data.length === 0 || data.length > MAX_SIZE) throw new CborError("bad input size");
	const s: State = { data, offset: 0 };
	const value = item(s, 0);
	return { value, size: s.offset };
}

/** Decode `data` as exactly one item. */
export function decodeCborExact(data: Uint8Array): unknown {
	const { value, size } = decodeCborPrefix(data);
	if (size !== data.length) throw new CborError("trailing bytes");
	return value;
}
