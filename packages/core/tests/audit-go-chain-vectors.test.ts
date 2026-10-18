/**
 * Verifies the Go audit chain vectors (tests/fixtures/go-audit-chain-vectors.json), produced by the
 * real theauth-go hashing code (see scripts/go-chain-vectors). Positive rows must verify with the
 * TypeScript verifier and rebuild the exact Go pre-image bytes, negative vectors must fail with
 * the recorded reason at the recorded row.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { GoAuditRow } from "../src/audit/go-chain-verify.js";
import { goChainPayload, goMarshal, verifyGoAuditChain } from "../src/audit/go-chain-verify.js";

interface VecRow {
	row: GoAuditRow;
	payload: string;
	hash: string;
}
interface Chain {
	name: string;
	chainKey: string;
	rows: VecRow[];
}
interface Mutation {
	kind: "set_field" | "swap_rows" | "drop_row" | "dup_row";
	row?: number;
	a?: number;
	b?: number;
	field?: string;
	value?: unknown;
}
interface Negative {
	name: string;
	chain: number;
	mutate: Mutation;
	expect: string;
	failsAtRow: number;
}
interface Vectors {
	format: string;
	formatVersion: number;
	pseudonymSecretHex: string;
	chains: Chain[];
	negative: Negative[];
}

const vectors = JSON.parse(
	readFileSync(
		fileURLToPath(new URL("./fixtures/go-audit-chain-vectors.json", import.meta.url)),
		"utf8",
	),
) as Vectors;

const plainRows = (c: Chain): GoAuditRow[] => c.rows.map((r) => structuredClone(r.row));

function mutate(rows: GoAuditRow[], m: Mutation): GoAuditRow[] {
	const out = [...rows];
	switch (m.kind) {
		case "set_field": {
			const target = { ...(out[m.row as number] as GoAuditRow) } as Record<string, unknown>;
			target[m.field as string] = m.value;
			out[m.row as number] = target as unknown as GoAuditRow;
			return out;
		}
		case "swap_rows": {
			const a = out[m.a as number] as GoAuditRow;
			out[m.a as number] = out[m.b as number] as GoAuditRow;
			out[m.b as number] = a;
			return out;
		}
		case "drop_row":
			out.splice(m.row as number, 1);
			return out;
		case "dup_row":
			out.splice(m.row as number, 0, out[m.row as number] as GoAuditRow);
			return out;
	}
}

describe("go audit chain vectors", () => {
	it("has the expected format and coverage", () => {
		expect(vectors.format).toBe("theauth.audit.go-chain-vectors");
		expect(vectors.formatVersion).toBe(1);
		expect(vectors.chains.length).toBe(3);
		expect(vectors.chains.reduce((n, c) => n + c.rows.length, 0)).toBe(11);
		expect(vectors.negative.length).toBe(13);
	});

	for (const chain of vectors.chains) {
		it(`rebuilds Go pre-image bytes and hashes: ${chain.name}`, async () => {
			for (const r of chain.rows) {
				expect(await goChainPayload(r.row)).toBe(r.payload);
			}
		});

		it(`verifies without a secret (pseudonyms as exported): ${chain.name}`, async () => {
			const res = await verifyGoAuditChain(plainRows(chain));
			expect(res.firstFailure).toBeUndefined();
			expect(res.ok).toBe(true);
			expect(res.checked).toBe(chain.rows.length);
		});

		it(`verifies with the pseudonym secret: ${chain.name}`, async () => {
			const res = await verifyGoAuditChain(plainRows(chain), {
				pseudonymSecret: vectors.pseudonymSecretHex,
			});
			expect(res.ok).toBe(true);
			expect(res.pseudonymsUnchecked).toBe(0);
		});
	}

	it("counts erased rows (raw ids blank, pseudonyms kept)", async () => {
		const res = await verifyGoAuditChain(plainRows(vectors.chains[0] as Chain), {
			pseudonymSecret: vectors.pseudonymSecretHex,
		});
		expect(res.erased).toBe(2);
	});

	it("verifies interleaved chains", async () => {
		const [a, b] = vectors.chains as [Chain, Chain];
		const ra = plainRows(a);
		const rb = plainRows(b);
		const mixed: GoAuditRow[] = [];
		for (let i = 0; i < Math.max(ra.length, rb.length); i++) {
			if (ra[i]) mixed.push(ra[i] as GoAuditRow);
			if (rb[i]) mixed.push(rb[i] as GoAuditRow);
		}
		const res = await verifyGoAuditChain(mixed);
		expect(res.ok).toBe(true);
		expect(res.chains).toBe(2);
	});

	it("is insensitive to JSON key order in exported metadata", async () => {
		const rows = plainRows(vectors.chains[0] as Chain);
		const second = rows[1] as GoAuditRow;
		second.metadata = Object.fromEntries(Object.entries(second.metadata ?? {}).reverse());
		expect((await verifyGoAuditChain(rows)).ok).toBe(true);
	});

	it("allows a window when allowPartialStart is set", async () => {
		const rows = plainRows(vectors.chains[0] as Chain).slice(2);
		expect((await verifyGoAuditChain(rows)).firstFailure?.reason).toBe("seq_gap");
		expect((await verifyGoAuditChain(rows, { allowPartialStart: true })).ok).toBe(true);
	});

	it("skips rows with no hash as unchained", async () => {
		const rows = plainRows(vectors.chains[1] as Chain);
		const legacy = { id: "x", action: "old", createdAt: "2020-01-01T00:00:00Z" } as GoAuditRow;
		const res = await verifyGoAuditChain([legacy, ...rows]);
		expect(res.ok).toBe(true);
		expect(res.unchained).toBe(1);
	});

	for (const neg of vectors.negative) {
		it(`rejects ${neg.name} as ${neg.expect}`, async () => {
			const chain = vectors.chains[neg.chain] as Chain;
			const rows = mutate(plainRows(chain), neg.mutate);
			const res = await verifyGoAuditChain(rows, { pseudonymSecret: vectors.pseudonymSecretHex });
			expect(res.ok).toBe(false);
			expect(res.firstFailure?.reason).toBe(neg.expect);
			expect(res.firstFailure?.index).toBe(neg.failsAtRow);
		});
	}

	it("reports a missing pseudonym input when ids are present but no pseudonym or secret", async () => {
		const rows = plainRows(vectors.chains[1] as Chain);
		for (const r of rows) {
			r.actorPseudonym = undefined;
		}
		const res = await verifyGoAuditChain(rows);
		expect(res.firstFailure?.reason).toBe("missing_pseudonym_input");
	});
});

describe("goMarshal (Go encoding/json rules)", () => {
	it("sorts keys by UTF-8 bytes, escapes HTML and formats numbers like Go", () => {
		expect(goMarshal({ b: 1, a: [1.5, 1e21, 1e-7, -0], "\u{1F600}": "<&> " })).toBe(
			'{"a":[1.5,1e+21,1e-7,-0],"b":1,"\u{1F600}":"\\u003c\\u0026\\u003e\\u2028"}',
		);
	});
	it("sorts astral keys after BMP keys above the surrogate range (byte order, not UTF-16)", () => {
		expect(goMarshal({ "\u{10000}": 1, "￿": 2 })).toBe('{"￿":2,"\u{10000}":1}');
	});
});
