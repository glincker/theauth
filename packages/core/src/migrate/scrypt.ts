/**
 * scrypt (RFC 7914) on top of WebCrypto PBKDF2. Pure JS so it runs on Workers, Deno and Bun.
 * It is slower than native scrypt, which is fine for the one-time check on first login.
 */

const MAX_MEMORY_BYTES = 256 * 1024 * 1024;

function rotl(a: number, b: number): number {
	return (a << b) | (a >>> (32 - b));
}

function salsa20_8(b: Uint32Array): void {
	const x = new Uint32Array(b);
	for (let i = 0; i < 8; i += 2) {
		x[4] = (x[4] as number) ^ rotl(((x[0] as number) + (x[12] as number)) | 0, 7);
		x[8] = (x[8] as number) ^ rotl(((x[4] as number) + (x[0] as number)) | 0, 9);
		x[12] = (x[12] as number) ^ rotl(((x[8] as number) + (x[4] as number)) | 0, 13);
		x[0] = (x[0] as number) ^ rotl(((x[12] as number) + (x[8] as number)) | 0, 18);
		x[9] = (x[9] as number) ^ rotl(((x[5] as number) + (x[1] as number)) | 0, 7);
		x[13] = (x[13] as number) ^ rotl(((x[9] as number) + (x[5] as number)) | 0, 9);
		x[1] = (x[1] as number) ^ rotl(((x[13] as number) + (x[9] as number)) | 0, 13);
		x[5] = (x[5] as number) ^ rotl(((x[1] as number) + (x[13] as number)) | 0, 18);
		x[14] = (x[14] as number) ^ rotl(((x[10] as number) + (x[6] as number)) | 0, 7);
		x[2] = (x[2] as number) ^ rotl(((x[14] as number) + (x[10] as number)) | 0, 9);
		x[6] = (x[6] as number) ^ rotl(((x[2] as number) + (x[14] as number)) | 0, 13);
		x[10] = (x[10] as number) ^ rotl(((x[6] as number) + (x[2] as number)) | 0, 18);
		x[3] = (x[3] as number) ^ rotl(((x[15] as number) + (x[11] as number)) | 0, 7);
		x[7] = (x[7] as number) ^ rotl(((x[3] as number) + (x[15] as number)) | 0, 9);
		x[11] = (x[11] as number) ^ rotl(((x[7] as number) + (x[3] as number)) | 0, 13);
		x[15] = (x[15] as number) ^ rotl(((x[11] as number) + (x[7] as number)) | 0, 18);
		x[1] = (x[1] as number) ^ rotl(((x[0] as number) + (x[3] as number)) | 0, 7);
		x[2] = (x[2] as number) ^ rotl(((x[1] as number) + (x[0] as number)) | 0, 9);
		x[3] = (x[3] as number) ^ rotl(((x[2] as number) + (x[1] as number)) | 0, 13);
		x[0] = (x[0] as number) ^ rotl(((x[3] as number) + (x[2] as number)) | 0, 18);
		x[6] = (x[6] as number) ^ rotl(((x[5] as number) + (x[4] as number)) | 0, 7);
		x[7] = (x[7] as number) ^ rotl(((x[6] as number) + (x[5] as number)) | 0, 9);
		x[4] = (x[4] as number) ^ rotl(((x[7] as number) + (x[6] as number)) | 0, 13);
		x[5] = (x[5] as number) ^ rotl(((x[4] as number) + (x[7] as number)) | 0, 18);
		x[11] = (x[11] as number) ^ rotl(((x[10] as number) + (x[9] as number)) | 0, 7);
		x[8] = (x[8] as number) ^ rotl(((x[11] as number) + (x[10] as number)) | 0, 9);
		x[9] = (x[9] as number) ^ rotl(((x[8] as number) + (x[11] as number)) | 0, 13);
		x[10] = (x[10] as number) ^ rotl(((x[9] as number) + (x[8] as number)) | 0, 18);
		x[12] = (x[12] as number) ^ rotl(((x[15] as number) + (x[14] as number)) | 0, 7);
		x[13] = (x[13] as number) ^ rotl(((x[12] as number) + (x[15] as number)) | 0, 9);
		x[14] = (x[14] as number) ^ rotl(((x[13] as number) + (x[12] as number)) | 0, 13);
		x[15] = (x[15] as number) ^ rotl(((x[14] as number) + (x[13] as number)) | 0, 18);
	}
	for (let i = 0; i < 16; i++) b[i] = ((b[i] as number) + (x[i] as number)) | 0;
}

function blockMix(b: Uint32Array, out: Uint32Array, r: number): void {
	const x = b.slice((2 * r - 1) * 16, 2 * r * 16);
	for (let i = 0; i < 2 * r; i++) {
		for (let k = 0; k < 16; k++) x[k] = (x[k] as number) ^ (b[i * 16 + k] as number);
		salsa20_8(x);
		const dest = (i % 2 === 0 ? i / 2 : r + (i - 1) / 2) * 16;
		out.set(x, dest);
	}
}

function roMix(block: Uint32Array, n: number, r: number): void {
	const words = 32 * r;
	const v = new Uint32Array(n * words);
	let x = new Uint32Array(block);
	let y = new Uint32Array(words);
	for (let i = 0; i < n; i++) {
		v.set(x, i * words);
		blockMix(x, y, r);
		[x, y] = [y, x];
	}
	for (let i = 0; i < n; i++) {
		const j = (x[(2 * r - 1) * 16] as number) & (n - 1);
		for (let k = 0; k < words; k++) x[k] = (x[k] as number) ^ (v[j * words + k] as number);
		blockMix(x, y, r);
		[x, y] = [y, x];
	}
	block.set(x);
}

async function pbkdf2Sha256(pw: Uint8Array, salt: Uint8Array, len: number): Promise<Uint8Array> {
	const key = await globalThis.crypto.subtle.importKey("raw", pw as BufferSource, "PBKDF2", false, [
		"deriveBits",
	]);
	const bits = await globalThis.crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt: salt as BufferSource, iterations: 1, hash: "SHA-256" },
		key,
		len * 8,
	);
	return new Uint8Array(bits);
}

export interface ScryptParams {
	N: number;
	r: number;
	p: number;
	dkLen: number;
}

/** Returns null when the parameters are unusable or would need too much memory. */
export async function scrypt(
	password: Uint8Array,
	salt: Uint8Array,
	params: ScryptParams,
): Promise<Uint8Array | null> {
	const { N, r, p, dkLen } = params;
	const valid =
		Number.isInteger(N) &&
		N >= 2 &&
		(N & (N - 1)) === 0 &&
		Number.isInteger(r) &&
		r >= 1 &&
		Number.isInteger(p) &&
		p >= 1 &&
		dkLen >= 1;
	if (!valid || N * r * 128 > MAX_MEMORY_BYTES || p * r > 1024) return null;
	const b = await pbkdf2Sha256(password, salt, p * 128 * r);
	const words = new Uint32Array(b.buffer, b.byteOffset, b.byteLength / 4);
	for (let i = 0; i < p; i++) roMix(words.subarray(i * 32 * r, (i + 1) * 32 * r), N, r);
	const mixed = new Uint8Array(words.buffer, words.byteOffset, words.byteLength);
	return pbkdf2Sha256(password, mixed, dkLen);
}
