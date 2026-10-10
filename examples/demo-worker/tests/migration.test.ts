import { readFileSync } from "node:fs";
import { createTables } from "@glinr/theauth";
import { describe, expect, it } from "vitest";

function normalize(sql: string): string {
	return sql
		.replace(/\s+/g, " ")
		.replace(/\s*;\s*$/, "")
		.trim();
}

describe("D1 migration", () => {
	it("matches the statements the SDK would run for the sqlite dialect", async () => {
		const captured: string[] = [];
		const recorder = { session: { client: { run: (sql: string) => captured.push(sql) } } };
		// The demo's database config drives which feature tables exist.
		await createTables(recorder as never, "sqlite", {
			database: { provider: "d1", binding: {} as never },
			agents: { enabled: true, auditAll: true },
		});

		const expected = captured
			.filter((s) => /^\s*CREATE /.test(s))
			.map(normalize)
			// The first index is emitted by the upgrade pass before its table exists.
			.filter((s, i) => !(i === 0 && s.includes("theauth_audit_logs_chain")));

		const file = readFileSync(new URL("../migrations/0001_init.sql", import.meta.url), "utf8");
		const actual = file
			.split(";")
			.map((s) =>
				s
					.split("\n")
					.filter((line) => !line.trim().startsWith("--"))
					.join("\n"),
			)
			.map(normalize)
			.filter((s) => s.length > 0);

		expect(actual).toEqual(expected);
	});
});
