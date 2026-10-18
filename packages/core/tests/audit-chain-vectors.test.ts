/**
 * TypeScript audit chain conformance vectors (tests/fixtures/audit-chain-vectors.json).
 * The committed file must equal what scripts/gen-audit-chain-vectors.mjs produces now, and a
 * reference verifier written with node:crypto only (no library hashing) must accept every
 * positive row and reject every negative vector with the recorded reason.
 */

import { execFileSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { AuditInsert } from "../src/audit/chain.js";
import { chainPayload } from "../src/audit/chain.js";

interface VectorRow {
	seq: number;
	prev: string | null;
	input: Record<string, unknown>;
	payload: string;
	hash: string;
	erasedInput?: Record<string, unknown>;
}
interface VectorChain {
	name: string;
	hashFormat: string;
	hashVersion: number;
	hmacKey: string | null;
	pseudonymKey: string | null;
	rows: VectorRow[];
}
type Mutation =
	| { kind: "set_input"; field: string; value: unknown }
	| { kind: "set_payload"; payload: string }
	| { kind: "set_key"; hmacKey: string | null }
	| { kind: "set_seq"; seq: number }
	| { kind: "drop_row"; index: number };
interface Negative {
	name: string;
	chain: string;
	failsAtRow: number;
	mutate: Mutation;
	expect: string;
}
interface Vectors {
	format: string;
	formatVersion: number;
	chains: VectorChain[];
	negative: Negative[];
}

const FIXTURE = fileURLToPath(new URL("./fixtures/audit-chain-vectors.json", import.meta.url));
const SCRIPT = fileURLToPath(
	new URL("../../../scripts/gen-audit-chain-vectors.mjs", import.meta.url),
);
const TSX = fileURLToPath(new URL("../../../node_modules/.bin/tsx", import.meta.url));
const PSEUDONYM_FIELDS = ["userId", "agentId", "subjectId", "actorId", "approverId"] as const;

const committed = readFileSync(FIXTURE, "utf8");
const vectors = JSON.parse(committed) as Vectors;

function digest(payload: string, hmacKey: string | null): string {
	return hmacKey
		? createHmac("sha256", hmacKey).update(payload, "utf8").digest("hex")
		: createHash("sha256").update(payload, "utf8").digest("hex");
}

interface Outcome {
	ok: boolean;
	reason?: string;
	index?: number;
}

/** Reference verifier: the algorithm documented in docs/audit-receipts.mdx. */
function verify(
	chain: VectorChain,
	rows: VectorRow[],
	opts: {
		hmacKey?: string | null;
		payload?: { index: number; value: string };
		seq?: { index: number; value: number };
	} = {},
): Outcome {
	const key = opts.hmacKey === undefined ? chain.hmacKey : opts.hmacKey;
	for (let i = 0; i < rows.length; i++) {
		const row = rows[i] as VectorRow;
		const expectedPrev = i === 0 ? null : (rows[i - 1] as VectorRow).hash;
		if (row.prev !== expectedPrev) return { ok: false, reason: "prev_hash_mismatch", index: i };
		const seq = opts.seq?.index === i ? opts.seq.value : row.seq;
		const payload =
			opts.payload?.index === i
				? opts.payload.value
				: chainPayload(row.input as unknown as AuditInsert, seq, row.prev);
		if (digest(payload, key) !== row.hash) return { ok: false, reason: "hash_mismatch", index: i };
		if (chain.hashVersion >= 2 && chain.pseudonymKey) {
			const stored = (row.input.idPseudonyms ?? {}) as Record<string, string>;
			for (const field of PSEUDONYM_FIELDS) {
				const raw = row.input[field];
				if (typeof raw !== "string" || raw.startsWith("[deleted-")) continue;
				const expected = createHmac("sha256", chain.pseudonymKey)
					.update(`theauth.audit.pseudonym.v1:${raw}`, "utf8")
					.digest("hex");
				if (expected !== stored[field])
					return { ok: false, reason: "pseudonym_mismatch", index: i };
			}
		}
	}
	return { ok: true };
}

function applyNegative(n: Negative): Outcome {
	const chain = vectors.chains.find((c) => c.name === n.chain) as VectorChain;
	const rows: VectorRow[] = structuredClone(chain.rows).map((r) => ({ ...r }));
	const m = n.mutate;
	switch (m.kind) {
		case "set_input":
			(rows[n.failsAtRow] as VectorRow).input[m.field] = m.value;
			return verify(chain, rows);
		case "set_payload":
			return verify(chain, rows, { payload: { index: n.failsAtRow, value: m.payload } });
		case "set_key":
			return verify(chain, rows, { hmacKey: m.hmacKey });
		case "set_seq":
			return verify(chain, rows, { seq: { index: n.failsAtRow, value: m.seq } });
		default:
			rows.splice(m.index, 1);
			return verify(chain, rows);
	}
}

describe("audit chain vectors", () => {
	it("committed file equals a fresh regeneration", () => {
		const fresh = execFileSync(TSX, [SCRIPT, "--stdout"], {
			encoding: "utf8",
			cwd: fileURLToPath(new URL("../../..", import.meta.url)),
			maxBuffer: 16 * 1024 * 1024,
		});
		expect(fresh).toBe(committed);
	});

	it("declares its format", () => {
		expect(vectors.format).toBe("theauth.audit.chain-vectors");
		expect(vectors.formatVersion).toBe(1);
		expect(vectors.chains.map((c) => c.hashFormat).sort()).toEqual([
			"ts-v1",
			"ts-v1",
			"ts-v2",
			"ts-v2",
		]);
		expect(vectors.chains.some((c) => c.hmacKey) && vectors.chains.some((c) => !c.hmacKey)).toBe(
			true,
		);
	});

	it.each(
		vectors.chains.map((c) => [c.name, c] as const),
	)("chain %s: payload, hash and links verify", (_name, chain) => {
		expect(verify(chain, chain.rows)).toEqual({ ok: true });
		for (const row of chain.rows) {
			expect(row.payload).toBe(
				chainPayload(row.input as unknown as AuditInsert, row.seq, row.prev),
			);
			expect(digest(row.payload, chain.hmacKey)).toBe(row.hash);
		}
		expect(chain.rows[0]?.prev).toBeNull();
	});

	it("v2 hash survives erasure of the raw id columns", () => {
		for (const chain of vectors.chains.filter((c) => c.hashVersion >= 2)) {
			const last = chain.rows[chain.rows.length - 1] as VectorRow;
			expect(last.erasedInput).toBeDefined();
			const erased = last.erasedInput as Record<string, unknown>;
			expect(
				digest(chainPayload(erased as unknown as AuditInsert, last.seq, last.prev), chain.hmacKey),
			).toBe(last.hash);
		}
	});

	it("v1 and v2 payloads differ in the id fields they cover", () => {
		const v1 = vectors.chains.find((c) => c.name === "v1-plain")?.rows[0] as VectorRow;
		const v2 = vectors.chains.find((c) => c.name === "v2-plain")?.rows[0] as VectorRow;
		expect(v1.payload).toContain('"userId":"user-');
		expect(v2.payload).not.toContain('"userId":"user-');
		expect(v2.payload).toContain('"idPseudonyms"');
	});

	it.each(vectors.negative.map((n) => [n.name, n] as const))("negative %s", (_name, n) => {
		const out = applyNegative(n);
		expect(out.ok).toBe(false);
		expect(out.reason).toBe(n.expect);
		expect(out.index).toBe(n.failsAtRow);
	});
});
