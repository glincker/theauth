/**
 * Minimal CBOR decoder (RFC 7049) for WebAuthn attestation objects.
 * Security limits:
 * - Maximum input size: 1 MB
 * - Maximum nesting depth: 32
 * - Indefinite-length items are rejected
 */

/** Maximum CBOR input size in bytes (1 MB). */
const MAX_CBOR_INPUT_SIZE = 1_048_576;

/** Maximum nesting depth for arrays/maps. */
const MAX_CBOR_DEPTH = 32;

interface DecoderState {
	data: Uint8Array;
	offset: number;
	depth: number;
}

function readByte(state: DecoderState): number {
	const byte = state.data[state.offset];
	if (byte === undefined) throw new Error("CBOR: unexpected end of data");
	state.offset++;
	return byte;
}

function readBytes(state: DecoderState, length: number): Uint8Array {
	if (length > state.data.length - state.offset) {
		throw new Error("CBOR: unexpected end of data");
	}
	const end = state.offset + length;
	const slice = state.data.slice(state.offset, end);
	state.offset = end;
	return slice;
}

function readUint(state: DecoderState, additionalInfo: number): number {
	if (additionalInfo <= 23) return additionalInfo;
	if (additionalInfo === 24) return readByte(state);
	if (additionalInfo === 25) {
		const b = readBytes(state, 2);
		return ((b[0] ?? 0) << 8) | (b[1] ?? 0);
	}
	if (additionalInfo === 26) {
		const b = readBytes(state, 4);
		return (((b[0] ?? 0) << 24) | ((b[1] ?? 0) << 16) | ((b[2] ?? 0) << 8) | (b[3] ?? 0)) >>> 0;
	}
	if (additionalInfo === 27) {
		// 64-bit -- we only handle values that fit in a JS number safely
		const b = readBytes(state, 8);
		const hi = ((b[0] ?? 0) * 0x1000000 + (b[1] ?? 0)) * 0x10000 + ((b[2] ?? 0) << 8) + (b[3] ?? 0);
		const lo = ((b[4] ?? 0) * 0x1000000 + (b[5] ?? 0)) * 0x10000 + ((b[6] ?? 0) << 8) + (b[7] ?? 0);
		return hi * 0x100000000 + lo;
	}
	if (additionalInfo === 31) {
		throw new Error("CBOR: indefinite-length items are not supported");
	}
	throw new Error(`CBOR: unsupported additional info ${additionalInfo} for uint`);
}

function decodeItem(state: DecoderState): unknown {
	const initialByte = readByte(state);
	const majorType = (initialByte >> 5) & 0x07;
	const additionalInfo = initialByte & 0x1f;

	switch (majorType) {
		case 0: {
			return readUint(state, additionalInfo);
		}

		case 1: {
			// Negative integer: -1 - n
			const n = readUint(state, additionalInfo);
			return -1 - n;
		}

		case 2: {
			if (additionalInfo === 31) {
				throw new Error("CBOR: indefinite-length byte strings are not supported");
			}
			const length = readUint(state, additionalInfo);
			return readBytes(state, length);
		}

		case 3: {
			if (additionalInfo === 31) {
				throw new Error("CBOR: indefinite-length text strings are not supported");
			}
			const length = readUint(state, additionalInfo);
			const bytes = readBytes(state, length);
			return new TextDecoder().decode(bytes);
		}

		case 4: {
			if (additionalInfo === 31) {
				throw new Error("CBOR: indefinite-length arrays are not supported");
			}
			state.depth++;
			if (state.depth > MAX_CBOR_DEPTH) {
				throw new Error(`CBOR: nesting depth exceeds maximum of ${MAX_CBOR_DEPTH}`);
			}
			const count = readUint(state, additionalInfo);
			const arr: unknown[] = [];
			for (let i = 0; i < count; i++) {
				arr.push(decodeItem(state));
			}
			state.depth--;
			return arr;
		}

		case 5: {
			if (additionalInfo === 31) {
				throw new Error("CBOR: indefinite-length maps are not supported");
			}
			state.depth++;
			if (state.depth > MAX_CBOR_DEPTH) {
				throw new Error(`CBOR: nesting depth exceeds maximum of ${MAX_CBOR_DEPTH}`);
			}
			const count = readUint(state, additionalInfo);
			const map = new Map<unknown, unknown>();
			for (let i = 0; i < count; i++) {
				const key = decodeItem(state);
				const value = decodeItem(state);
				map.set(key, value);
			}
			state.depth--;
			return map;
		}

		case 7: {
			if (additionalInfo === 20) return false;
			if (additionalInfo === 21) return true;
			if (additionalInfo === 22) return null;
			if (additionalInfo === 25) {
				// IEEE 754 half-precision float (16-bit)
				const b = readBytes(state, 2);
				const half = ((b[0] ?? 0) << 8) | (b[1] ?? 0);
				const exp = (half >> 10) & 0x1f;
				const mant = half & 0x3ff;
				const sign = half >> 15 ? -1 : 1;
				let val: number;
				if (exp === 0) val = sign * 5.96046e-8 * mant;
				else if (exp === 31) val = mant ? NaN : sign * Infinity;
				else val = sign * 2 ** (exp - 15) * (1 + mant / 1024);
				return val;
			}
			if (additionalInfo === 26) {
				const b = readBytes(state, 4);
				const buf = new ArrayBuffer(4);
				new Uint8Array(buf).set(b);
				return new DataView(buf).getFloat32(0, false);
			}
			if (additionalInfo === 27) {
				const b = readBytes(state, 8);
				const buf = new ArrayBuffer(8);
				new Uint8Array(buf).set(b);
				return new DataView(buf).getFloat64(0, false);
			}
			throw new Error(`CBOR: unsupported simple value ${additionalInfo}`);
		}

		default:
			throw new Error(`CBOR: unsupported major type ${majorType}`);
	}
}

/**
 * Decode a CBOR-encoded byte array into a JavaScript value.
 * Enforces size and depth limits to prevent denial of service.
 */
export function decodeCbor(data: Uint8Array): unknown {
	if (data.length > MAX_CBOR_INPUT_SIZE) {
		throw new Error(`CBOR: input size ${data.length} exceeds maximum of ${MAX_CBOR_INPUT_SIZE}`);
	}
	if (data.length === 0) {
		throw new Error("CBOR: empty input");
	}
	const state: DecoderState = { data, offset: 0, depth: 0 };
	return decodeItem(state);
}
