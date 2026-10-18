#!/usr/bin/env node
/**
 * Generates packages/core/tests/fixtures/audit-chain-vectors.json from the TypeScript audit chain
 * code (hash versions 1 and 2, plain SHA-256 and HMAC-SHA256, pseudonymized ids).
 *
 *   npx tsx scripts/gen-audit-chain-vectors.mjs            write the fixture
 *   npx tsx scripts/gen-audit-chain-vectors.mjs --stdout   print it instead
 *
 * Output is deterministic: fixed ids, keys and timestamps. Format is documented in docs/audit-receipts.mdx.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chainPayload, computeRowHash } from "../packages/core/src/audit/chain.ts";
import { computePseudonyms } from "../packages/core/src/audit/pseudonym.ts";

const OUT = fileURLToPath(
	new URL("../packages/core/tests/fixtures/audit-chain-vectors.json", import.meta.url),
);
const T0 = Date.UTC(2026, 9, 1, 0, 0, 0);
const HMAC_KEY = "vector-hmac-key-do-not-use";
const PSEUDONYM_SECRET = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/** One input row. Only fields that exist on the audit_logs row; timestamp is whole seconds in ms. */
function rows(agentId, userId) {
	const base = { agentId, userId, resource: "mcp:github:repos", result: "allowed", durationMs: 12 };
	return [
		{ ...base, id: "r1", action: "execute", parameters: { b: 2, a: 1 }, timestamp: T0 },
		{
			...base,
			id: "r2",
			action: "café 🚀",
			parameters: {
				note: '<tag> &   "q"',
				n: Number.MAX_SAFE_INTEGER,
				nested: { z: null, y: [3, { k: 1, a: 2 }] },
			},
			reason: "ok",
			tokensCost: 1.5,
			ip: "203.0.113.7",
			userAgent: "vector/1",
			cacheHit: true,
			policyVersion: "p-7",
			delegationChain: [],
			inputProvenance: { source: "user", trace: { b: 1, a: 0 } },
			timestamp: T0 + 1000,
		},
		{
			...base,
			id: "r3",
			action: "write",
			parameters: null,
			delegationChain: ["d1", "d2"],
			timestamp: T0 + 2000,
		},
		{ ...base, id: "r4", action: "execute", parameters: {}, timestamp: T0 + 3000 },
	];
}

async function buildChain(spec) {
	const { name, hashVersion, hmacKey, pseudonymKey } = spec;
	const agentId = `agent-${name}`;
	const out = [];
	let prev = null;
	let seq = 0;
	for (const base of rows(agentId, `user-${name}`)) {
		seq += 1;
		const input = { ...base, hashVersion };
		if (hashVersion >= 2) input.idPseudonyms = await computePseudonyms(input, pseudonymKey);
		const payload = chainPayload(input, seq, prev);
		const hash = await computeRowHash(input, seq, prev, hmacKey ?? undefined);
		out.push({ seq, prev, input, payload, hash });
		prev = hash;
	}
	if (hashVersion >= 2) {
		// Erasure blanks the raw id columns after the write. The hash does not cover them in v2, so it still verifies.
		const last = out[out.length - 1];
		last.erasedInput = { ...last.input, userId: "[deleted-vector]", agentId: "[deleted-vector]" };
	}
	return {
		name,
		hashFormat: `ts-v${hashVersion}`,
		agentId,
		hashVersion,
		hmacKey: hmacKey ?? null,
		pseudonymKey: hashVersion >= 2 ? pseudonymKey : null,
		rows: out,
	};
}

async function negatives(chains) {
	const byName = Object.fromEntries(chains.map((c) => [c.name, c]));
	const v1 = byName["v1-plain"];
	const v1Row = v1.rows[1];
	const parsed = JSON.parse(v1Row.payload);
	const topLevel = JSON.stringify({
		v: parsed.v,
		seq: parsed.seq,
		prev: parsed.prev,
		row: parsed.row,
	});
	const rowKeys = JSON.stringify({
		...parsed,
		row: Object.fromEntries(Object.entries(parsed.row).reverse()),
	});
	return [
		{
			name: "tampered_field_v1",
			chain: "v1-plain",
			failsAtRow: 1,
			mutate: { kind: "set_input", field: "result", value: "denied" },
			expect: "hash_mismatch",
		},
		{
			name: "tampered_field_v2",
			chain: "v2-hmac",
			failsAtRow: 2,
			mutate: { kind: "set_input", field: "action", value: "delete" },
			expect: "hash_mismatch",
		},
		{
			name: "tampered_parameters_v2",
			chain: "v2-hmac",
			failsAtRow: 1,
			mutate: { kind: "set_input", field: "parameters", value: { note: "changed" } },
			expect: "hash_mismatch",
		},
		{
			name: "reordered_top_level_keys_v1",
			chain: "v1-plain",
			failsAtRow: 1,
			mutate: { kind: "set_payload", payload: topLevel },
			expect: "hash_mismatch",
		},
		{
			name: "reordered_row_keys_v1",
			chain: "v1-plain",
			failsAtRow: 1,
			mutate: { kind: "set_payload", payload: rowKeys },
			expect: "hash_mismatch",
		},
		{
			name: "pretty_printed_v1",
			chain: "v1-plain",
			failsAtRow: 1,
			mutate: { kind: "set_payload", payload: JSON.stringify(JSON.parse(v1Row.payload), null, 1) },
			expect: "hash_mismatch",
		},
		{
			name: "wrong_hmac_key",
			chain: "v2-hmac",
			failsAtRow: 0,
			mutate: { kind: "set_key", hmacKey: "another-key" },
			expect: "hash_mismatch",
		},
		{
			name: "missing_hmac_key",
			chain: "v1-hmac",
			failsAtRow: 0,
			mutate: { kind: "set_key", hmacKey: null },
			expect: "hash_mismatch",
		},
		{
			name: "wrong_seq_in_payload",
			chain: "v1-plain",
			failsAtRow: 2,
			mutate: { kind: "set_seq", seq: 9 },
			expect: "hash_mismatch",
		},
		{
			name: "dropped_middle_row",
			chain: "v1-plain",
			failsAtRow: 1,
			mutate: { kind: "drop_row", index: 1 },
			expect: "prev_hash_mismatch",
		},
		{
			name: "dropped_first_row",
			chain: "v2-plain",
			failsAtRow: 0,
			mutate: { kind: "drop_row", index: 0 },
			expect: "prev_hash_mismatch",
		},
		{
			name: "raw_id_edited_after_pseudonym",
			chain: "v2-plain",
			failsAtRow: 1,
			mutate: { kind: "set_input", field: "userId", value: "someone-else" },
			expect: "pseudonym_mismatch",
		},
	];
}

export async function generate() {
	const specs = [
		{ name: "v1-plain", hashVersion: 1, hmacKey: null },
		{ name: "v1-hmac", hashVersion: 1, hmacKey: HMAC_KEY },
		{ name: "v2-plain", hashVersion: 2, hmacKey: null, pseudonymKey: PSEUDONYM_SECRET },
		{ name: "v2-hmac", hashVersion: 2, hmacKey: HMAC_KEY, pseudonymKey: HMAC_KEY },
	];
	const chains = [];
	for (const spec of specs) chains.push(await buildChain(spec));
	return {
		format: "theauth.audit.chain-vectors",
		formatVersion: 1,
		producer: "@glinr/theauth core",
		description:
			"TypeScript audit chain row-hash vectors. See docs/audit-receipts.mdx for the algorithm. These are the TypeScript formats ts-v1 and ts-v2, not the Go chain format.",
		chains,
		negative: await negatives(chains),
	};
}

const text = `${JSON.stringify(await generate(), null, "\t")}\n`;
if (process.argv.includes("--stdout")) process.stdout.write(text);
else {
	writeFileSync(OUT, text);
	process.stdout.write(`wrote ${OUT}\n`);
}
