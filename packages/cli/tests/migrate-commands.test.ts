import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseMigrateArgs, runMigrate } from "../src/migrate-commands.js";

const CLERK = `id,first_name,last_name,username,primary_email_address,verified_email_addresses,password_digest,password_hasher
user_1,Ada,Test,ada,ada@example.test,ada@example.test,$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234,bcrypt
user_2,Bob,,bob,bob@example.test,,,
`;

function fixture(): { dir: string; file: string; db: string } {
	const dir = mkdtempSync(join(tmpdir(), "theauth-migrate-"));
	const file = join(dir, "clerk.csv");
	writeFileSync(file, CLERK);
	return { dir, file, db: join(dir, "t.db") };
}

describe("parseMigrateArgs", () => {
	it("parses plan and import flags", () => {
		expect(parseMigrateArgs(["plan", "--from", "auth0", "./export.json", "--json"])).toMatchObject({
			subcommand: "plan",
			from: "auth0",
			file: "./export.json",
			json: true,
			error: null,
		});
		expect(
			parseMigrateArgs(["import", "--from=clerk", "x.csv", "--apply", "--on-conflict", "update"]),
		).toMatchObject({
			apply: true,
			onConflict: "update",
		});
	});
	it("reports bad input", () => {
		expect(parseMigrateArgs(["plan", "./x"]).error).toMatch(/--from/);
		expect(parseMigrateArgs(["plan", "--from", "nope", "x"]).error).toMatch(/--from/);
		expect(parseMigrateArgs(["plan", "--from", "auth0"]).error).toMatch(/export file/);
		expect(parseMigrateArgs(["wat"]).error).toMatch(/Unknown/);
		expect(parseMigrateArgs([]).help).toBe(true);
	});
});

describe("runMigrate", () => {
	it("plan reports counts and gaps without personal data", async () => {
		const f = fixture();
		const r = await runMigrate(parseMigrateArgs(["plan", "--from", "clerk", f.file]), {});
		expect(r.code).toBe(0);
		expect(r.output).toContain("would create 2");
		expect(r.output).toContain("bcrypt");
		expect(r.output).not.toContain("example.test");
		expect(r.output).not.toContain("$2b$");
	});

	it("import is a dry run until --apply, verify and status then see the data", async () => {
		const f = fixture();
		const env = {};
		const dry = await runMigrate(
			parseMigrateArgs(["import", "--from", "clerk", f.file, "--db", f.db]),
			env,
		);
		expect(dry.output).toContain("Nothing was written");
		const empty = await runMigrate(
			parseMigrateArgs(["verify", "--from", "clerk", f.file, "--db", f.db]),
			env,
		);
		expect(empty.code).toBe(1);

		const applied = await runMigrate(
			parseMigrateArgs(["import", "--from", "clerk", f.file, "--db", f.db, "--apply"]),
			env,
		);
		expect(applied.code).toBe(0);
		const again = await runMigrate(
			parseMigrateArgs(["import", "--from", "clerk", f.file, "--db", f.db, "--apply", "--json"]),
			env,
		);
		expect(JSON.parse(again.output)).toMatchObject({ created: 0, skipped: 2 });

		const ok = await runMigrate(
			parseMigrateArgs(["verify", "--from", "clerk", f.file, "--db", f.db]),
			env,
		);
		expect(ok.code).toBe(0);

		const outFile = join(f.dir, "status.json");
		const status = await runMigrate(
			parseMigrateArgs(["status", "--db", f.db, "--out", outFile]),
			env,
		);
		expect(status.output).toContain("pending 2");
		const saved = JSON.parse(readFileSync(outFile, "utf-8")) as { pending: number };
		expect(saved.pending).toBe(2);
		expect(readFileSync(outFile, "utf-8")).not.toContain("example.test");
	});

	it("explains that postgres needs a custom store", async () => {
		const f = fixture();
		const r = await runMigrate(parseMigrateArgs(["status", "--db", "postgres://x/y"]), {});
		expect(r.code).toBe(2);
		void f;
	});
});
