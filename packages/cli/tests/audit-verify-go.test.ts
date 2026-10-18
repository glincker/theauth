import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseAuditArgs } from "../src/audit-commands.js";
import { parseGoExport, runVerifyGo } from "../src/audit-verify-go.js";

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
