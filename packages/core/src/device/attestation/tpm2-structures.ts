/**
 * Parsers for the TPM 2.0 structures a quote needs, from the TCG TPM 2.0 Library specification
 * (https://trustedcomputinggroup.org/resource/tpm-library-specification/), Part 2 "Structures":
 * TPMT_PUBLIC (12.2.4), TPMS_ATTEST (10.12.8), TPMS_QUOTE_INFO (10.12.4) and TPMT_SIGNATURE (11.3.4).
 * All integers are big endian, every read is bounds checked and every parse must use all of its input.
 */

export const TPM_ALG = {
	rsa: 0x0001,
	aes: 0x0006,
	cfb: 0x0043,
	sha1: 0x0004,
	sha256: 0x000b,
	sha384: 0x000c,
	sha512: 0x000d,
	null: 0x0010,
	rsassa: 0x0014,
	rsapss: 0x0016,
	ecdsa: 0x0018,
	ecc: 0x0023,
} as const;

export type TpmHashName = "sha1" | "sha256" | "sha384" | "sha512";

export const HASH_BY_ALG: Record<number, TpmHashName> = {
	[TPM_ALG.sha1]: "sha1",
	[TPM_ALG.sha256]: "sha256",
	[TPM_ALG.sha384]: "sha384",
	[TPM_ALG.sha512]: "sha512",
};

export const HASH_SIZE: Record<TpmHashName, number> = {
	sha1: 20,
	sha256: 32,
	sha384: 48,
	sha512: 64,
};

/** TPMA_OBJECT bits (Part 2, 8.3.2). */
export const OBJECT_ATTR = {
	fixedTPM: 0x2,
	fixedParent: 0x10,
	sensitiveDataOrigin: 0x20,
	restricted: 0x10000,
	decrypt: 0x20000,
	sign: 0x40000,
} as const;

export const TPM_GENERATED = 0xff544347;
export const TPM_ST_ATTEST_QUOTE = 0x8018;
export const TPM_ST_ATTEST_CERTIFY = 0x8017;

class Reader {
	offset = 0;
	constructor(private readonly data: Uint8Array) {}

	take(n: number): Uint8Array {
		if (n < 0 || n > this.data.length - this.offset) throw new Error("TPM structure is truncated");
		const out = this.data.subarray(this.offset, this.offset + n);
		this.offset += n;
		return out;
	}
	u8(): number {
		return this.take(1)[0] as number;
	}
	u16(): number {
		const b = this.take(2);
		return ((b[0] as number) << 8) | (b[1] as number);
	}
	u32(): number {
		const b = this.take(4);
		return (
			(b[0] as number) * 2 ** 24 +
			((b[1] as number) << 16) +
			((b[2] as number) << 8) +
			(b[3] as number)
		);
	}
	u64(): bigint {
		let v = 0n;
		for (const b of this.take(8)) v = (v << 8n) | BigInt(b);
		return v;
	}
	/** TPM2B_*: a 16 bit size then that many bytes. */
	sized(): Uint8Array {
		return this.take(this.u16());
	}
	done(): void {
		if (this.offset !== this.data.length) throw new Error("TPM structure has trailing bytes");
	}
}

export interface TpmPublic {
	type: "rsa" | "ecc";
	nameAlg: number;
	attributes: number;
	/** The scheme the key is bound to, or undefined when the key accepts any (TPM_ALG_NULL). */
	scheme?: { alg: number; hash: number };
	rsa?: { n: Uint8Array; e: number; bits: number };
	ecc?: { curve: "P-256" | "P-384" | "P-521"; x: Uint8Array; y: Uint8Array };
	/** The exact TPMT_PUBLIC bytes, used to compute the key name. */
	raw: Uint8Array;
}

const CURVES: Record<number, "P-256" | "P-384" | "P-521"> = {
	3: "P-256",
	4: "P-384",
	5: "P-521",
};

export interface ParseTpmPublicOptions {
	/** Accept an AES symmetric definition, as a storage or endorsement key has. Signing keys must have none. */
	allowSymmetric?: boolean;
}

/** Accepts TPMT_PUBLIC, or TPM2B_PUBLIC (what `tpm2_readpublic` and TSS write), told apart by the leading size. */
export function parseTpmPublic(input: Uint8Array, opts: ParseTpmPublicOptions = {}): TpmPublic {
	let data = input;
	if (data.length > 2 && ((data[0] as number) << 8) + (data[1] as number) === data.length - 2) {
		data = data.subarray(2);
	}
	const r = new Reader(data);
	const typeCode = r.u16();
	const nameAlg = r.u16();
	const attributes = r.u32();
	r.sized(); // authPolicy
	const readSymmetric = () => {
		const alg = r.u16();
		if (alg === TPM_ALG.null) return;
		// TPMT_SYM_DEF_OBJECT: algorithm, keyBits, mode. Only AES in CFB, what an EK template uses.
		if (!opts.allowSymmetric || alg !== TPM_ALG.aes) {
			throw new Error("A signing key must have a null symmetric");
		}
		r.u16();
		if (r.u16() !== TPM_ALG.cfb) throw new Error("Unsupported symmetric mode");
	};
	const readScheme = () => {
		const alg = r.u16();
		if (alg === TPM_ALG.null) return undefined;
		if (alg !== TPM_ALG.rsassa && alg !== TPM_ALG.rsapss && alg !== TPM_ALG.ecdsa) {
			throw new Error("Unsupported signing scheme");
		}
		return { alg, hash: r.u16() };
	};
	let out: TpmPublic;
	if (typeCode === TPM_ALG.rsa) {
		readSymmetric();
		const scheme = readScheme();
		const bits = r.u16();
		const exponent = r.u32();
		const n = r.sized();
		out = {
			type: "rsa",
			nameAlg,
			attributes,
			...(scheme && { scheme }),
			rsa: { n, e: exponent === 0 ? 65537 : exponent, bits },
			raw: data,
		};
	} else if (typeCode === TPM_ALG.ecc) {
		readSymmetric();
		const scheme = readScheme();
		const curve = CURVES[r.u16()];
		if (!curve) throw new Error("Unsupported curve");
		if (r.u16() !== TPM_ALG.null) throw new Error("Unexpected key derivation function");
		const x = r.sized();
		const y = r.sized();
		out = {
			type: "ecc",
			nameAlg,
			attributes,
			...(scheme && { scheme }),
			ecc: { curve, x, y },
			raw: data,
		};
	} else {
		throw new Error("Unsupported key type");
	}
	r.done();
	return out;
}

export interface TpmSignature {
	alg: number;
	hash: number;
	/** RSASSA signature bytes, or r and s for ECDSA. */
	rsa?: Uint8Array;
	ecdsa?: { r: Uint8Array; s: Uint8Array };
}

export function parseTpmSignature(data: Uint8Array): TpmSignature {
	const r = new Reader(data);
	const alg = r.u16();
	const hash = r.u16();
	let out: TpmSignature;
	if (alg === TPM_ALG.rsassa) out = { alg, hash, rsa: r.sized() };
	else if (alg === TPM_ALG.ecdsa) out = { alg, hash, ecdsa: { r: r.sized(), s: r.sized() } };
	else throw new Error("Unsupported signature algorithm");
	r.done();
	return out;
}

export interface PcrSelection {
	hash: number;
	indexes: number[];
}

export interface TpmQuote {
	qualifiedSigner: Uint8Array;
	extraData: Uint8Array;
	clock: bigint;
	resetCount: number;
	restartCount: number;
	safe: boolean;
	firmwareVersion: bigint;
	selections: PcrSelection[];
	pcrDigest: Uint8Array;
}

/** TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE. The magic proves the TPM built it, if the signing key is restricted. */
export function parseTpmQuote(data: Uint8Array): TpmQuote {
	const r = new Reader(data);
	if (r.u32() !== TPM_GENERATED) throw new Error("Quote does not start with TPM_GENERATED_VALUE");
	if (r.u16() !== TPM_ST_ATTEST_QUOTE) throw new Error("Attestation is not a quote");
	const qualifiedSigner = r.sized();
	const extraData = r.sized();
	const clock = r.u64();
	const resetCount = r.u32();
	const restartCount = r.u32();
	const safe = r.u8() !== 0;
	const firmwareVersion = r.u64();
	const count = r.u32();
	if (count === 0 || count > 16)
		throw new Error("Quote selects an unreasonable number of PCR banks");
	const selections: PcrSelection[] = [];
	for (let i = 0; i < count; i++) {
		const hash = r.u16();
		const bitmap = r.take(r.u8());
		const indexes: number[] = [];
		bitmap.forEach((byte, bi) => {
			for (let bit = 0; bit < 8; bit++) if (byte & (1 << bit)) indexes.push(bi * 8 + bit);
		});
		selections.push({ hash, indexes });
	}
	const pcrDigest = r.sized();
	r.done();
	return {
		qualifiedSigner,
		extraData,
		clock,
		resetCount,
		restartCount,
		safe,
		firmwareVersion,
		selections,
		pcrDigest,
	};
}

export interface TpmCertify {
	qualifiedSigner: Uint8Array;
	extraData: Uint8Array;
	clock: bigint;
	resetCount: number;
	restartCount: number;
	safe: boolean;
	firmwareVersion: bigint;
	/** Name of the certified object: nameAlg then the digest of its TPMT_PUBLIC. */
	name: Uint8Array;
	qualifiedName: Uint8Array;
}

/** TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY (TPM2_Certify): the TPM vouches that an object with this name is loaded in it. */
export function parseTpmCertify(data: Uint8Array): TpmCertify {
	const r = new Reader(data);
	if (r.u32() !== TPM_GENERATED) throw new Error("Certify does not start with TPM_GENERATED_VALUE");
	if (r.u16() !== TPM_ST_ATTEST_CERTIFY) throw new Error("Attestation is not a certify");
	const qualifiedSigner = r.sized();
	const extraData = r.sized();
	const clock = r.u64();
	const resetCount = r.u32();
	const restartCount = r.u32();
	const safe = r.u8() !== 0;
	const firmwareVersion = r.u64();
	const name = r.sized();
	const qualifiedName = r.sized();
	r.done();
	return {
		qualifiedSigner,
		extraData,
		clock,
		resetCount,
		restartCount,
		safe,
		firmwareVersion,
		name,
		qualifiedName,
	};
}
