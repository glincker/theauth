import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseAuditArgs } from "../src/audit-commands.js";
import { parseGoExport, parseHeadKeys, runVerifyGo } from "../src/audit-verify-go.js";

const fixture = JSON.parse(
	readFileSync(
		fileURLToPath(
			new URL("../../core/tests/fixtures/go-audit-chain-vectors.json", import.meta.url),
		),
		"utf8",
	),
) as { chains: { rows: { row: Record<string, unknown> }[] }[] };

function write(name: string, body: string): string {
	const p = join(mkdtempSync(join(tmpdir(), "go-audit-")), name);
	writeFileSync(p, body);
	return p;
}

describe("audit verify-go", () => {
	const rows = (fixture.chains[1]?.rows ?? []).map((r) => r.row);

	it("parses the file argument and flags", () => {
		const a = parseAuditArgs(["verify-go", "x.json", "--partial", "--secret-hex", "ab"]);
		expect(a.error).toBeNull();
		expect(a).toMatchObject({
			subcommand: "verify-go",
			file: "x.json",
			partial: true,
			secretHex: "ab",
		});
		expect(parseAuditArgs(["verify-go"]).error).toMatch(/needs a file/);
	});

	it("verifies a JSON array and NDJSON", async () => {
		const json = write("e.json", JSON.stringify(rows));
		const nd = write("e.ndjson", rows.map((r) => JSON.stringify(r)).join("\n"));
		for (const f of [json, nd]) {
			const out = await runVerifyGo(parseAuditArgs(["verify-go", f]));
			expect(out.code).toBe(0);
			expect(out.output).toMatch(/^OK: 3 rows/);
		}
	});

	it("exits 1 on a tampered row and 2 on a missing file", async () => {
		const bad = rows.map((r) => ({ ...r }));
		(bad[1] as Record<string, unknown>).action = "evil";
		const out = await runVerifyGo(
			parseAuditArgs(["verify-go", write("b.json", JSON.stringify(bad))]),
		);
		expect(out.code).toBe(1);
		expect(out.output).toMatch(/hash_mismatch/);
		expect((await runVerifyGo(parseAuditArgs(["verify-go", "/nonexistent/x.json"]))).code).toBe(2);
	});

	it("accepts an object wrapper", () => {
		expect(parseGoExport(JSON.stringify({ rows }))).toHaveLength(3);
	});
});

describe("audit verify-go --head", () => {
	const rows = (fixture.chains[1]?.rows ?? []).map((r) => r.row);
	const last = rows[rows.length - 1] as { organizationId?: string; chainSeq: number; hash: string };

	async function signedHead(
		seq: number,
		hash: string,
	): Promise<{ head: string; keys: string; other: string }> {
		const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
		const jwk = await crypto.subtle.exportKey("jwk", (pair as CryptoKeyPair).publicKey);
		const body = {
			version: 1,
			alg: "Ed25519",
			keyId: "k1",
			timestamp: 1760000000000,
			heads: [{ chainKey: last.organizationId ?? "", seq, hash }],
		};
		// Sorted keys at every depth, no whitespace: the Go canonical JSON.
		const canonical = `{"alg":"Ed25519","heads":[{"chainKey":${JSON.stringify(body.heads[0]?.chainKey)},"hash":"${hash}","seq":${seq}}],"keyId":"k1","timestamp":1760000000000,"version":1}`;
		const sig = new Uint8Array(
			await crypto.subtle.sign(
				{ name: "Ed25519" },
				(pair as CryptoKeyPair).privateKey,
				new TextEncoder().encode(`theauth.audit.head.v1\n${canonical}`),
			),
		);
		const head = { ...body, signature: Buffer.from(sig).toString("base64url") };
		const key = { keyId: "k1", publicKey: { kty: "OKP", crv: "Ed25519", x: jwk.x } };
		return {
			head: write("head.json", JSON.stringify(head)),
			keys: write("key.json", JSON.stringify(key)),
			other: write("keys.json", JSON.stringify({ keys: [key] })),
		};
	}

	it("parses the flags and wants both", () => {
		const a = parseAuditArgs(["verify-go", "x.json", "--head", "h.json", "--head-key", "k.json"]);
		expect(a).toMatchObject({ error: null, head: "h.json", headKey: "k.json" });
		expect(parseAuditArgs(["verify-go", "x.json", "--head", "h.json"]).error).toMatch(
			/go together/,
		);
		expect(parseAuditArgs(["verify-go", "x.json", "--head-key"]).error).toMatch(/needs a file/);
	});

	it("passes when the export reaches the signed head", async () => {
		const f = await signedHead(last.chainSeq, last.hash);
		const file = write("e.json", JSON.stringify(rows));
		for (const keys of [f.keys, f.other]) {
			const out = await runVerifyGo(
				parseAuditArgs(["verify-go", file, "--head", f.head, "--head-key", keys]),
			);
			expect(out.code).toBe(0);
			expect(out.output).toMatch(/head checkpoint signature is valid/);
		}
		const json = await runVerifyGo(
			parseAuditArgs(["verify-go", file, "--head", f.head, "--head-key", f.keys, "--json"]),
		);
		expect(JSON.parse(json.output).head).toEqual({ valid: true });
	});

	it("reports tail truncation with a valid chain, exit 1", async () => {
		const f = await signedHead(last.chainSeq, last.hash);
		const cut = write("cut.json", JSON.stringify(rows.slice(0, -1)));
		const out = await runVerifyGo(
			parseAuditArgs(["verify-go", cut, "--head", f.head, "--head-key", f.keys]),
		);
		expect(out.code).toBe(1);
		expect(out.output).toMatch(/^OK: 2 rows/);
		expect(out.output).toMatch(/head checkpoint chain_truncated in chain/);
	});

	it("reports a head with another hash and a wrong key, exit 1", async () => {
		const bad = await signedHead(last.chainSeq, "a".repeat(64));
		const file = write("e.json", JSON.stringify(rows));
		const mismatch = await runVerifyGo(
			parseAuditArgs(["verify-go", file, "--head", bad.head, "--head-key", bad.keys]),
		);
		expect(mismatch.code).toBe(1);
		expect(mismatch.output).toMatch(/head_mismatch/);
		const good = await signedHead(last.chainSeq, last.hash);
		const wrong = await runVerifyGo(
			parseAuditArgs(["verify-go", file, "--head", good.head, "--head-key", bad.keys]),
		);
		expect(wrong.code).toBe(1);
		expect(wrong.output).toMatch(/bad_signature/);
	});

	it("exits 2 on an unreadable head or key file", async () => {
		const file = write("e.json", JSON.stringify(rows));
		const out = await runVerifyGo(
			parseAuditArgs(["verify-go", file, "--head", "/nonexistent/h.json", "--head-key", "/x"]),
		);
		expect(out.code).toBe(2);
		expect(() => parseHeadKeys("[]")).toThrow(/no public key/);
	});
});
