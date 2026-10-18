import { describe, expect, it } from "vitest";
import { baselineStatements, MYSQL_TABLE_OPTIONS } from "../../src/db/ddl/index.js";
import { MIGRATIONS } from "../../src/db/migrate/index.js";

/** Reserved words of MySQL 8.4 that a TheAuth column or table could plausibly collide with. */
const RESERVED = new Set(
	`add all alter and as asc between by call cascade case change check column condition constraint create cross current_date current_time current_timestamp current_user database databases default delete desc describe distinct drop else exists explain false for foreign from grant group having if ignore in index inner insert interval into is join key keys kill left like limit lock match not null on option or order outer primary procedure range read references regexp rename repeat replace require restrict return revoke right rlike schema select set show table then to trigger true union unique unlock update usage use using values when where while with write rank groups system window row rows of over lead lag function generated virtual cube grouping`.split(
		/\s+/,
	),
);

const mysql = baselineStatements("mysql");
const tables = mysql.filter((s) => s.sql.startsWith("CREATE TABLE"));
const indexes = mysql.filter((s) => /^CREATE (UNIQUE )?INDEX/.test(s.sql));

interface Column {
	table: string;
	name: string;
	type: string;
	rest: string;
}

function columnsOf(sql: string): { table: string; columns: Column[]; constraints: string[] } {
	const m = /^CREATE TABLE (?:IF NOT EXISTS )?(\w+) \(\n([\s\S]*)\n\) /.exec(sql);
	const table = m?.[1] ?? "";
	const columns: Column[] = [];
	const constraints: string[] = [];
	for (const raw of (m?.[2] ?? "").split("\n")) {
		const line = raw.replace(/,\s*$/, "").trim();
		if (/^(UNIQUE|PRIMARY KEY|FOREIGN KEY)\b/i.test(line)) {
			constraints.push(line);
			continue;
		}
		const c = /^(\w+)\s+([A-Z]+(?:\(\d+\))?)(.*)$/.exec(line);
		if (c) columns.push({ table, name: c[1] as string, type: c[2] as string, rest: c[3] ?? "" });
	}
	return { table, columns, constraints };
}

const parsed = tables.map((t) => columnsOf(t.sql));

describe("MySQL baseline DDL (static, no server needed)", () => {
	it("parses every table", () => {
		expect(parsed.length).toBeGreaterThan(40);
		for (const p of parsed) expect(p.columns.length).toBeGreaterThan(0);
	});

	it("never gives TEXT a key, unique, default or reference (MySQL rejects it)", () => {
		for (const { columns } of parsed) {
			for (const c of columns.filter((x) => x.type === "TEXT")) {
				expect(c.rest, `${c.table}.${c.name}`).not.toMatch(
					/PRIMARY KEY|UNIQUE|REFERENCES|DEFAULT/i,
				);
			}
		}
	});

	it("never indexes a TEXT column", () => {
		const byTable = new Map(parsed.map((p) => [p.table, p.columns]));
		for (const { sql } of indexes) {
			const m = /ON (\w+)\s*\(([^)]*)\)/.exec(sql.replace(/\s+/g, " "));
			const cols = (m?.[2] ?? "").split(",").map((c) =>
				c
					.trim()
					.replace(/\s+(ASC|DESC)$/i, "")
					.replace(/\(\d+\)$/, ""),
			);
			for (const name of cols) {
				const col = byTable.get(m?.[1] ?? "")?.find((c) => c.name === name);
				expect(col, `${m?.[1]}.${name}`).toBeDefined();
				expect(col?.type, `${m?.[1]}.${name}`).not.toBe("TEXT");
			}
		}
	});

	it("declares foreign keys at table level with matching child and parent types", () => {
		const types = new Map<string, string>();
		for (const p of parsed) for (const c of p.columns) types.set(`${p.table}.${c.name}`, c.type);
		let count = 0;
		for (const p of parsed) {
			for (const c of p.columns) expect(c.rest).not.toMatch(/REFERENCES/i);
			for (const fk of p.constraints.filter((x) => x.startsWith("FOREIGN KEY"))) {
				const m = /^FOREIGN KEY \((\w+)\) REFERENCES (\w+)\((\w+)\)/.exec(fk);
				expect(m, fk).not.toBeNull();
				const child = types.get(`${p.table}.${m?.[1]}`);
				const parent = types.get(`${m?.[2]}.${m?.[3]}`);
				expect(parent, `${p.table}: ${fk}`).toBeDefined();
				expect(child, `${p.table}: ${fk}`).toBe(parent);
				count += 1;
			}
		}
		expect(count).toBeGreaterThan(20);
	});

	it("keeps ON DELETE actions when it moves a reference to table level", () => {
		const all = parsed.flatMap((p) => p.constraints);
		expect(all.some((c) => /ON DELETE CASCADE/.test(c))).toBe(true);
	});

	it("has no CREATE INDEX IF NOT EXISTS (MySQL has no such clause)", () => {
		for (const { sql } of indexes) expect(sql).not.toMatch(/IF NOT EXISTS/i);
		for (const m of MIGRATIONS) {
			for (const sql of m.up.mysql) {
				expect(sql, m.id).not.toMatch(/CREATE (UNIQUE )?INDEX IF NOT EXISTS/i);
				expect(sql, m.id).not.toMatch(/ADD COLUMN IF NOT EXISTS/i);
			}
		}
	});

	it("gives every table InnoDB, utf8mb4 and a binary collation", () => {
		for (const t of tables) expect(t.sql.endsWith(`) ${MYSQL_TABLE_OPTIONS}`)).toBe(true);
		for (const m of MIGRATIONS) {
			for (const sql of m.up.mysql.filter((s) => s.startsWith("CREATE TABLE"))) {
				expect(sql, m.id).toContain("COLLATE=utf8mb4_bin");
			}
		}
	});

	it("uses no Postgres or SQLite only syntax", () => {
		const all = [...mysql.map((s) => s.sql), ...MIGRATIONS.flatMap((m) => m.up.mysql)].join("\n");
		expect(all).not.toMatch(/JSONB|TIMESTAMPTZ|BOOLEAN|RETURNING|strftime|NOW\(\)|ON CONFLICT/);
		expect(all).not.toMatch(/DEFAULT (TRUE|FALSE)/);
	});

	it("uses no reserved word as a table or column name", () => {
		for (const p of parsed) {
			expect(RESERVED.has(p.table), p.table).toBe(false);
			for (const c of p.columns) expect(RESERVED.has(c.name), `${p.table}.${c.name}`).toBe(false);
		}
	});

	it("matches the portable column set: the conversion only changes types and constraints", () => {
		const portable = baselineStatements("postgres").filter((s) => s.sql.startsWith("CREATE TABLE"));
		expect(tables.map((t) => /(theauth_\w+)/.exec(t.sql)?.[1])).toEqual(
			portable.map((t) => /(theauth_\w+)/.exec(t.sql)?.[1]),
		);
		for (let i = 0; i < portable.length; i++) {
			const mine = parsed[i]?.columns.map((c) => c.name);
			const theirs = columnsOf(
				`${(portable[i] as { sql: string }).sql} ${MYSQL_TABLE_OPTIONS}`,
			).columns.map((c) => c.name);
			expect(mine).toEqual(theirs);
		}
	});

	it("keeps indexed VARCHAR keys inside the 3072 byte InnoDB limit", () => {
		const byTable = new Map(parsed.map((p) => [p.table, p.columns]));
		const width = (table: string, name: string): number => {
			const col = byTable.get(table)?.find((c) => c.name === name);
			const n = Number(/\((\d+)\)/.exec(col?.type ?? "")?.[1] ?? 8);
			return n * 4;
		};
		for (const p of parsed) {
			for (const c of p.constraints.filter((x) => /^(UNIQUE|PRIMARY KEY)/.test(x))) {
				const cols = /\(([^)]*)\)/.exec(c)?.[1]?.split(",") ?? [];
				const total = cols.reduce((n, name) => n + width(p.table, name.trim()), 0);
				expect(total, `${p.table} ${c}`).toBeLessThanOrEqual(3072);
			}
		}
	});
});
