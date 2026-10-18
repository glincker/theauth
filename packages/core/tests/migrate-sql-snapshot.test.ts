import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { baselineStatements } from "../src/db/ddl/index.js";
import { generatedSqlFiles, SQL_DIALECTS } from "../src/db/migrate/files.js";
import { MIGRATIONS, migrationSql } from "../src/db/migrate/index.js";

const ROOT = join(__dirname, "..", "src", "db", "migrations");
// Escaped on purpose: the repo bans literal em and en dashes, even inside patterns.
const DASHES = /[\u2013\u2014]/;
const UPDATE = process.env.UPDATE_MIGRATION_SQL === "1";

describe("committed migration SQL equals the generated SQL", () => {
	const generated = generatedSqlFiles();

	if (UPDATE) {
		it("rewrites the committed files (UPDATE_MIGRATION_SQL=1)", () => {
			for (const [path, content] of Object.entries(generated)) {
				mkdirSync(dirname(join(ROOT, path)), { recursive: true });
				writeFileSync(join(ROOT, path), content);
			}
		});
		return;
	}

	for (const [path, content] of Object.entries(generated)) {
		it(`${path}`, () => {
			expect(readFileSync(join(ROOT, path), "utf8")).toBe(content);
		});
	}

	it("has no stray files next to the generated ones", () => {
		for (const dialect of SQL_DIALECTS) {
			const committed = readdirSync(join(ROOT, "sql", dialect)).sort();
			expect(committed).toEqual(MIGRATIONS.map((m) => `${m.id}.sql`));
		}
	});
});

describe("generated SQL", () => {
	it("migrationSql() is the concatenation of the per migration files", () => {
		for (const dialect of SQL_DIALECTS) {
			const joined = MIGRATIONS.map((m) =>
				readFileSync(join(ROOT, "sql", dialect, `${m.id}.sql`), "utf8"),
			).join("\n");
			expect(migrationSql(dialect)).toBe(joined);
		}
	});

	it("creates the ledger first and records every migration", () => {
		for (const dialect of SQL_DIALECTS) {
			const sql = migrationSql(dialect);
			expect(sql.indexOf("CREATE TABLE IF NOT EXISTS theauth_schema_migrations")).toBeGreaterThan(
				-1,
			);
			for (const m of MIGRATIONS) {
				expect(sql).toContain(`VALUES ('${m.id}', '${m.name}', '`);
			}
		}
	});

	it("`from` starts at that id and stamps everything before it", () => {
		const sql = migrationSql("postgres", { from: "0002" });
		expect(sql).not.toContain("/* Migration 0001");
		expect(sql).toContain("/* Migration 0002");
		expect(sql).toContain("VALUES ('0000'");
		expect(sql).toContain("VALUES ('0001'");
		expect(sql.indexOf("VALUES ('0001'")).toBeLessThan(sql.indexOf("/* Migration 0002"));
	});

	it("contains no em or en dashes", () => {
		for (const dialect of SQL_DIALECTS) {
			expect(migrationSql(dialect)).not.toMatch(DASHES);
		}
	});
});

describe("baseline DDL", () => {
	it("creates a table after every table its foreign keys point at", () => {
		for (const dialect of SQL_DIALECTS) {
			const created = new Set<string>();
			for (const { sql } of baselineStatements(dialect)) {
				const table = /CREATE TABLE (?:IF NOT EXISTS )?(theauth_\w+)/.exec(sql)?.[1];
				if (!table) continue;
				for (const ref of sql.matchAll(/REFERENCES (theauth_\w+)/g)) {
					const target = ref[1] as string;
					expect(
						created.has(target),
						`${dialect}: ${table} references ${target} before it exists`,
					).toBe(true);
				}
				created.add(table);
			}
			expect(created.size).toBeGreaterThan(55);
		}
	});

	it("tags every statement with a feature and keeps SQLite free of dialect types", () => {
		for (const { feature, sql } of baselineStatements("sqlite")) {
			expect(feature).toBeTruthy();
			expect(sql).not.toMatch(/JSONB|TIMESTAMPTZ|DATETIME\(3\)|TINYINT/);
		}
	});

	it("keeps the columns migrations 0001, 0002 and 0004 add out of the baseline", () => {
		const audit = baselineStatements("sqlite").find((s) =>
			s.sql.includes("CREATE TABLE IF NOT EXISTS theauth_audit_logs "),
		);
		expect(audit?.sql).not.toMatch(/decision_code|recorded_at_ms|cache_hit/);
		const permissions = baselineStatements("sqlite").find((s) =>
			s.sql.includes("CREATE TABLE IF NOT EXISTS theauth_permissions"),
		);
		expect(permissions?.sql).not.toContain("relation");
	});
});
