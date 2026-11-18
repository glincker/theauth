import { canonicalValue } from "./canonical.js";
import { base64url, concatBytes, sha256, utf8 } from "./encoding.js";
import type { Components, SignalV1 } from "./types.js";

type Value = string | number | boolean;

/** Byte order on UTF-8 names. Component names are ASCII so this equals code unit order. */
const byteCompare = (a: string, b: string): number => {
	const x = utf8(a);
	const y = utf8(b);
	const n = Math.min(x.length, y.length);
	for (let i = 0; i < n; i++) {
		const d = (x[i] ?? 0) - (y[i] ?? 0);
		if (d !== 0) return d;
	}
	return x.length - y.length;
};

export const toSignalV1 = async (
	components: Components,
	pepper: string,
	confidence: number,
	nowMs: number,
): Promise<SignalV1> => {
	const entries = (Object.entries(components) as Array<[string, Value | undefined]>)
		.filter((e): e is [string, Value] => e[1] !== undefined)
		.sort((a, b) => byteCompare(a[0], b[0]));
	const hashes = await Promise.all(
		entries.map(([name, value]) =>
			sha256(concatBytes([utf8(name), new Uint8Array([0]), utf8(canonicalValue(value))])),
		),
	);
	const digest = await sha256(concatBytes([utf8(pepper), new Uint8Array([0]), ...hashes]));
	return {
		v: 1,
		source: "browser",
		digest: base64url(digest),
		confidence,
		components: entries.length,
		ts: Math.floor(nowMs / 1000),
	};
};
