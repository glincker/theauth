/**
 * The approval hash must equal the one theauth-go computes. The fixture
 * (tests/fixtures/approval-hash-vectors.json, generator in scripts/approval-hash-vectors) holds the
 * pre-image and hash that the real Go `HashApprovalAction` wrote for each input, decoded two ways:
 * plain `json.Unmarshal` (float64) and `UseNumber` (source number text). A failure here is a
 * cross language divergence, with the input name in the test title.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { canonicalApprovalJson } from "../src/approval/canonical.js";
import { hashApprovalAction } from "../src/approval/consume.js";
import { sha256 } from "../src/crypto/web-crypto.js";

interface GoResult {
	canonical?: string;
	hash?: string;
	error?: string;
}
interface Case {
	name: string;
	action: string;
	resource: string;
	argumentsJson: string;
	numberTextCase?: boolean;
	float64: GoResult;
	useNumber: GoResult;
}

const vectors = JSON.parse(
	readFileSync(
		fileURLToPath(new URL("./fixtures/approval-hash-vectors.json", import.meta.url)),
		"utf8",
	),
) as { cases: Case[] };

const args = (c: Case): Record<string, unknown> | null =>
	JSON.parse(c.argumentsJson) as Record<string, unknown> | null;

describe("approval hash vectors from theauth-go", () => {
	it("has the edge cases", () => {
		expect(vectors.cases.length).toBeGreaterThanOrEqual(45);
		for (const c of vectors.cases) expect(c.float64.error).toBeUndefined();
	});

	for (const c of vectors.cases) {
		it(`float64 ${c.name}`, async () => {
			const got = await hashApprovalAction(c.action, c.resource, args(c));
			expect(got).toBe(c.float64.hash);
		});
		// Number text that is not already canonical float64 text ("1.0", "1e2", integers beyond 2^53)
		// is a Go side gap, see docs-local/tasks/w5-go-hash-patch.md. The TS side never sees the text,
		// JSON.parse has turned it into a double.
		if (!c.numberTextCase) {
			it(`useNumber ${c.name}`, async () => {
				const got = await hashApprovalAction(c.action, c.resource, args(c));
				expect(got).toBe(c.useNumber.hash);
			});
		}
	}
});

describe("approval hash, inputs JSON cannot express", () => {
	const h = (a: Record<string, unknown> | undefined) =>
		hashApprovalAction("execute", "bank:transfer", a);

	it("an undefined property hashes like an absent one", async () => {
		expect(await h({ a: 1, b: undefined })).toBe(await h({ a: 1 }));
	});

	it("an undefined array element hashes like null", async () => {
		expect(await h({ a: [undefined] })).toBe(await h({ a: [null] }));
	});

	it("NaN and Infinity throw instead of hashing like null", async () => {
		await expect(h({ a: Number.NaN })).rejects.toThrow(TypeError);
		await expect(h({ a: Number.POSITIVE_INFINITY })).rejects.toThrow(TypeError);
	});

	it("a bigint is its decimal digits, equal to the same number text", async () => {
		const exact = 9223372036854775807n;
		expect(canonicalApprovalJson({ n: exact })).toBe('{"n":9223372036854775807}');
		const go = vectors.cases.find((c) => c.name === "int_int64_max");
		expect(go?.useNumber.canonical).toContain('"arguments":{"n":9223372036854775807}');
	});

	it("a cycle throws and a shared sibling does not", async () => {
		const loop: Record<string, unknown> = {};
		loop.self = loop;
		await expect(h(loop)).rejects.toThrow(TypeError);
		const shared = { x: 1 };
		await expect(h({ a: shared, b: shared })).resolves.toMatch(/^[0-9a-f]{64}$/);
	});

	it("matches the Go pre-image bytes", async () => {
		const c = vectors.cases.find((x) => x.name === "html_chars");
		const pre = canonicalApprovalJson({
			action: c?.action,
			resource: c?.resource,
			arguments: args(c as Case),
		});
		expect(pre).toBe(c?.float64.canonical);
		expect(await sha256(pre)).toBe(c?.float64.hash);
	});

	it("approvals for arguments that differ only in a reserved key stay equal", async () => {
		expect(await h({ a: 1, theauthX: 2 })).toBe(await h({ a: 1 }));
	});
});
