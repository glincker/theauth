import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeDb, parseDbArgs } from "../src/db-commands.js";

describe("parseDbArgs", () => {
	it("parses subcommands and flags", () => {
		expect(parseDbArgs(["sql", "--dialect", "mysql", "--from", "0002", "--json"])).toMatchObject({
			subcommand: "sql",
			dialect: "mysql",
			from: "0002",
			json: true,
			error: null,
		});
		expect(parseDbArgs(["up", "--to", "0001", "--dry-run", "--db", "x.db"])).toMatchObject({
			subcommand: "up",
			to: "0001",
			dryRun: true,
			db: "x.db",
		});
	});

	it("reports bad input", () => {
		expect(parseDbArgs(["sql", "--dialect", "oracle"]).error).toMatch(/--dialect/);
		expect(parseDbArgs(["status", "--bogus"]).error).toMatch(/Unknown option/);
		expect(parseDbArgs(["frobnicate"]).error).toMatch(/Unknown argument/);
		expect(parseDbArgs(["up", "--to"]).error).toMatch(/needs a value/);
	});
});

describe("theauth db", () => {
	let dir: string;
	let file: string;
	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "theauth-db-"));
		file = join(dir, "app.db");
	});
	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("prints help and fails with usage when no subcommand is given", async () => {
		const help = await executeDb(parseDbArgs(["--help"]), {});
		expect(help.code).toBe(0);
		expect(help.out).toContain("theauth db status");
		const none = await executeDb(parseDbArgs([]), {});
		expect(none.code).toBe(2);
	});

	it("sql prints the ledger and every migration for each dialect, with --from honored", async () => {
		for (const dialect of ["sqlite", "postgres", "mysql"] as const) {
			const all = await executeDb(parseDbArgs(["sql", "--dialect", dialect]), {});
			expect(all.code).toBe(0);
			expect(all.out).toContain("theauth_schema_migrations");
			expect(all.out).toContain("/* Migration 0000: baseline");
			expect(all.out).toContain("/* Migration 0003: audit-recorded-at-ms");
		}
		const from = await executeDb(
			parseDbArgs(["sql", "--dialect", "postgres", "--from", "0002"]),
			{},
		);
		expect(from.out).not.toContain("/* Migration 0001");
		expect(from.out).toContain("/* Migration 0002");
		const bad = await executeDb(parseDbArgs(["sql", "--from", "0099"]), {});
		expect(bad.code).toBe(2);
		expect(bad.err).toMatch(/unknown migration id/);
	});

	it("sql infers the dialect from DATABASE_URL and emits JSON on request", async () => {
		const result = await executeDb(parseDbArgs(["sql", "--json"]), {
			DATABASE_URL: "mysql://u:p@h/db",
		});
		const body = JSON.parse(result.out) as { dialect: string; sql: string };
		expect(body.dialect).toBe("mysql");
		expect(body.sql).toContain("NOW(3)");
	});

	it("status and up work against a SQLite file", async () => {
		const env = { DATABASE_URL: file };
		const before = await executeDb(parseDbArgs(["status", "--json"]), env);
		expect(before.code).toBe(1);
		const pending = (JSON.parse(before.out) as { pending: Array<{ id: string }> }).pending;
		expect(pending.map((p) => p.id)).toEqual(["0000", "0001", "0002", "0003"]);

		const dry = await executeDb(parseDbArgs(["up", "--dry-run"]), env);
		expect(dry.code).toBe(0);
		expect(dry.out).toContain("CREATE TABLE IF NOT EXISTS theauth_users");

		const up = await executeDb(parseDbArgs(["up"]), env);
		expect(up.err).toBe("");
		expect(up.out).toBe("Applied 0000, 0001, 0002, 0003.\n");

		const after = await executeDb(parseDbArgs(["status"]), env);
		expect(after.code).toBe(0);
		expect(after.out).toContain("Pending (0):");
		expect(after.out).toContain("0002  audit-decision-code");

		const again = await executeDb(parseDbArgs(["up"]), env);
		expect(again.out).toBe("Schema already up to date.\n");
	});

	it("up --to stops early and --config narrows the feature set", async () => {
		const partial = await executeDb(parseDbArgs(["up", "--to", "0001", "--db", file]), {});
		expect(partial.out).toBe("Applied 0000, 0001.\n");

		const configFile = join(dir, "config.mjs");
		await writeFile(
			configFile,
			`export default { database: { provider: "sqlite-native", url: ${JSON.stringify(file)} } };\n`,
		);
		const status = await executeDb(parseDbArgs(["status", "--config", configFile]), {});
		// No agents in the config, so the audit migrations do not apply.
		expect(status.code).toBe(0);
		expect(status.out).toContain("Pending (0):");
	});

	it("reports a missing database and a bad config", async () => {
		const none = await executeDb(parseDbArgs(["status"]), {});
		expect(none.code).toBe(2);
		expect(none.err).toMatch(/No database/);
		const bad = await executeDb(parseDbArgs(["status", "--config", join(dir, "missing.mjs")]), {});
		expect(bad.code).toBe(2);
		expect(bad.err).toMatch(/Could not load/);
	});
});
