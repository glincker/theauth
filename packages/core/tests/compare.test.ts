import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/audit/chain.js";
import { compareCodeUnits } from "../src/compare.js";

// Mixed case, digits, punctuation, accents, CJK and an astral code point (a surrogate pair,
// whose UTF-16 order differs from code point order and from localeCompare).
const SAMPLE = [
	"b",
	"B",
	"a",
	"A",
	"10",
	"9",
	"_x",
	"-x",
	"é",
	"e",
	"z",
	"Z",
	"日",
	"\u{1F600}",
	"～",
	"",
];

describe("compareCodeUnits", () => {
	it("orders exactly like a bare sort() (UTF-16 code unit order)", () => {
		expect([...SAMPLE].sort(compareCodeUnits)).toEqual([...SAMPLE].sort());
	});

	it("is not locale order", () => {
		expect(["b", "B", "a", "A"].sort(compareCodeUnits)).toEqual(["A", "B", "a", "b"]);
		expect(["a", "B"].sort((x, y) => x.localeCompare(y))).not.toEqual(
			["a", "B"].sort(compareCodeUnits),
		);
	});

	it("returns 0 for equal strings", () => {
		expect(compareCodeUnits("abc", "abc")).toBe(0);
	});
});

describe("canonicalJson key ordering (hash chain input)", () => {
	it("sorts keys in code unit order, independent of insertion order", () => {
		const a = canonicalJson({ b: 1, B: 2, a: 3, A: 4, é: 5, "10": 6, "9": 7 });
		const b = canonicalJson({ "9": 7, é: 5, A: 4, a: 3, B: 2, b: 1, "10": 6 });
		expect(a).toBe('{"10":6,"9":7,"A":4,"B":2,"a":3,"b":1,"é":5}');
		expect(b).toBe(a);
	});

	it("matches the pre-comparator output for nested objects and astral keys", () => {
		const value = { z: { y: 1, Y: 2 }, "\u{1F600}": 1, "～": 2, a: [{ d: 1, c: 2 }] };
		const legacy = (v: unknown): string => {
			if (v === null || v === undefined) return "null";
			if (Array.isArray(v)) return `[${v.map(legacy).join(",")}]`;
			if (typeof v === "object") {
				const o = v as Record<string, unknown>;
				return `{${Object.keys(o)
					.sort()
					.map((k) => `${JSON.stringify(k)}:${legacy(o[k])}`)
					.join(",")}}`;
			}
			return JSON.stringify(v);
		};
		expect(canonicalJson(value)).toBe(legacy(value));
	});
});
