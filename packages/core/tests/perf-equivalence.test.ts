/**
 * Performance changes must not change answers. Each fast path here is compared with a frozen copy of the
 * code it replaced, over a seeded random corpus plus the awkward cases (empty segments, trailing colons,
 * surrogates, control characters, non ASCII keys).
 */
import { exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { canonicalApprovalJson } from "../src/approval/canonical.js";
import { compareBytes, goJsonString } from "../src/audit/go-chain-verify.js";
import { hmacSha256, importHmacKey } from "../src/crypto/web-crypto.js";
import { importSigningKey, localJwkSet } from "../src/device/key-cache.js";
import { matchResource } from "../src/policy/abac.js";
import { matchPathResource } from "../src/policy/resource-match.js";

function prng(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
		return s / 0x100000000;
	};
}

function legacyColon(pattern: string, resource: string): boolean {
	if (pattern === "*") return true;
	const pp = pattern.split(":");
	const rp = resource.split(":");
	for (let i = 0; i < pp.length; i++) {
		const part = pp[i];
		if (part === "*") return true;
		if (part !== rp[i]) return false;
	}
	return pp.length === rp.length;
}

/** The DP the path matcher used before the no-`**` shortcut. */
function legacyPathParts(pattern: string[], resource: string[]): boolean {
	const plain = (s: string) => s !== "" && s !== "." && s !== "..";
	const m = pattern.length;
	const n = resource.length;
	const ok: boolean[][] = Array.from({ length: m + 1 }, () =>
		new Array<boolean>(n + 1).fill(false),
	);
	(ok[m] as boolean[])[n] = true;
	for (let i = m - 1; i >= 0; i--) {
		const p = pattern[i] as string;
		for (let j = n - 1; j >= 0; j--) {
			const r = resource[j] as string;
			const row = ok[i] as boolean[];
			const below = ok[i + 1] as boolean[];
			if (p === "**") row[j] = plain(r) && (below[j + 1] === true || row[j + 1] === true);
			else if (p === "*") row[j] = r !== "**" && plain(r) && below[j + 1] === true;
			else row[j] = p === r && below[j + 1] === true;
		}
	}
	return (ok[0] as boolean[])[0] === true;
}

const ATOMS = ["a", "b", "tool", "*", "", "ab", "x*", "**", ".", ".."];

describe("matchColonResource", () => {
	it("agrees with the split based original on a random corpus", () => {
		const rnd = prng(7);
		const pick = () => ATOMS[Math.floor(rnd() * ATOMS.length)] as string;
		const make = () => Array.from({ length: 1 + Math.floor(rnd() * 4) }, pick).join(":");
		for (let i = 0; i < 20_000; i++) {
			const pattern = make();
			const resource = make();
			expect(matchResource(pattern, resource, "colon"), `${pattern} vs ${resource}`).toBe(
				legacyColon(pattern, resource),
			);
		}
	});

	it("agrees on edge shapes", () => {
		const cases = ["", ":", "a:", ":a", "a::b", "*", "*:a", "a:*", "a:*:b", "a", "a:b:c"];
		for (const p of cases)
			for (const r of cases) expect(matchResource(p, r)).toBe(legacyColon(p, r));
	});
});

/** The path matcher with the table based part matcher, as it was before the shortcut. */
function legacyPath(pattern: string, resource: string): boolean {
	if (pattern === "*") return true;
	const pp = pattern.split(":");
	const rp = resource.split(":");
	for (let i = 0; i < pp.length; i++) {
		const part = pp[i] as string;
		const last = i === pp.length - 1;
		if ((part === "*" || part === "**") && last) return true;
		const actual = rp[i];
		if (actual === undefined) return false;
		if (part === "*" || part === "**") {
			if (actual === "" || actual === "**") return false;
			continue;
		}
		if (part === actual) continue;
		if (!part.includes("/") || !actual.includes("/")) return false;
		if (!legacyPathParts(part.split("/"), actual.split("/"))) return false;
	}
	return pp.length === rp.length;
}

describe("matchPathResource", () => {
	it("agrees with the table based original on a random corpus", () => {
		const rnd = prng(11);
		const pick = () => ATOMS[Math.floor(rnd() * ATOMS.length)] as string;
		const seg = () => Array.from({ length: 1 + Math.floor(rnd() * 4) }, pick).join("/");
		const make = () =>
			Array.from({ length: 1 + Math.floor(rnd() * 2) }, () =>
				rnd() < 0.8 ? `/${seg()}` : seg(),
			).join(":");
		for (let i = 0; i < 30_000; i++) {
			const pattern = make();
			const resource = make();
			expect(matchPathResource(pattern, resource), `${pattern} vs ${resource}`).toBe(
				legacyPath(pattern, resource),
			);
		}
	});
});

describe("Go JSON string and byte order", () => {
	const reference = (s: string): string => {
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
			const hex = `\\u${c.toString(16).padStart(4, "0")}`;
			const map: Record<number, string> = {
				34: '\\"',
				92: "\\\\",
				10: "\\n",
				13: "\\r",
				9: "\\t",
				8: "\\b",
				12: "\\f",
			};
			if (map[c]) out += map[c];
			else if (c === 0x3c || c === 0x3e || c === 0x26 || c === 0x2028 || c === 0x2029) out += hex;
			else out += c < 0x20 ? hex : (s[i] as string);
		}
		return `${out}"`;
	};
	const samples = [
		"",
		"plain",
		"with space",
		'q"uote',
		"back\\slash",
		"<tag> & more",
		"line\nbreak\ttab",
		"\u0000\u001f\u007f",
		"\u2028\u2029",
		"caf\u00e9 \u4e2d\u6587",
		"emoji \ud83d\ude00",
		"lone \ud83d high",
		"lone \ude00 low",
	];

	it("encodes exactly like the character loop", () => {
		for (const s of samples) expect(goJsonString(s)).toBe(reference(s));
	});

	it("compareBytes orders like UTF-8 bytes, ASCII and not", () => {
		const enc = new TextEncoder();
		const byBytes = (a: string, b: string) => {
			const x = enc.encode(a);
			const y = enc.encode(b);
			for (let i = 0; i < Math.min(x.length, y.length); i++) {
				const d = (x[i] ?? 0) - (y[i] ?? 0);
				if (d !== 0) return d;
			}
			return x.length - y.length;
		};
		for (const a of samples)
			for (const b of samples) expect(compareBytes(a, b)).toBe(byBytes(a, b));
		expect(compareBytes("a", "ab")).toBe(-1);
		expect(compareBytes("b", "a")).toBe(1);
	});

	it("keeps the approval hash input stable (key order, escapes, surrogates)", () => {
		expect(
			canonicalApprovalJson({ b: 1, a: "x<y", "\u00e9": [null, undefined], z: "\ud83d" }),
		).toBe('{"a":"x\\u003cy","b":1,"z":"\ufffd","\u00e9":[null,null]}');
	});
});

describe("key caches", () => {
	it("an HMAC key for a string secret is reused and still signs correctly", async () => {
		const secret = "perf-test-secret-at-least-32-bytes-long!!";
		const a = await importHmacKey(secret);
		const b = await importHmacKey(secret);
		expect(b).toBe(a);
		const other = await importHmacKey(`${secret}-other`);
		expect(other).not.toBe(a);
		expect(await hmacSha256(secret, "data")).not.toBe(await hmacSha256(`${secret}-other`, "data"));
		expect(await hmacSha256(secret, "data")).toBe(await hmacSha256(secret, "data"));
	});

	it("a JWKS changed in place is not served from a stale resolver", async () => {
		const k1 = await generateKeyPair("ES256", { extractable: true });
		const k2 = await generateKeyPair("ES256", { extractable: true });
		const jwks = { keys: [{ ...(await exportJWK(k1.publicKey)), kid: "k", alg: "ES256" }] };
		const first = localJwkSet(jwks);
		expect(localJwkSet(jwks)).toBe(first);
		jwks.keys[0] = { ...(await exportJWK(k2.publicKey)), kid: "k", alg: "ES256" };
		expect(localJwkSet(jwks)).not.toBe(first);
	});

	it("a signing JWK changed in place is re-imported", async () => {
		const k1 = await generateKeyPair("ES256", { extractable: true });
		const k2 = await generateKeyPair("ES256", { extractable: true });
		const jwk = await exportJWK(k1.privateKey);
		const first = await importSigningKey(jwk, "ES256");
		expect(await importSigningKey(jwk, "ES256")).toBe(first);
		Object.assign(jwk, await exportJWK(k2.privateKey));
		expect(await importSigningKey(jwk, "ES256")).not.toBe(first);
	});
});
