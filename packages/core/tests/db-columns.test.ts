import Database from "better-sqlite3";
import { getTableColumns, lt } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { describe, expect, it } from "vitest";
import type { ColumnKind } from "../src/db/schema/columns.js";
import {
	bigintNumber,
	bool,
	columnKind,
	flag01,
	json,
	timestampMs,
	timestampSec,
} from "../src/db/schema/columns.js";
import * as schema from "../src/db/schema.js";

interface Payload {
	a: number;
	nested: { b: string[] };
}

const oldTable = sqliteTable("t_old", {
	id: text("id").primaryKey(),
	ts: integer("ts", { mode: "timestamp" }).notNull(),
	tsMs: integer("ts_ms", { mode: "timestamp_ms" }).notNull(),
	big: integer("big").notNull(),
	flagBool: integer("flag_bool", { mode: "boolean" }).notNull(),
	flagNum: integer("flag_num").notNull().default(0),
	doc: text("doc", { mode: "json" }).$type<Payload>().notNull(),
});

const newTable = sqliteTable("t_new", {
	id: text("id").primaryKey(),
	ts: timestampSec("ts").notNull(),
	tsMs: timestampMs("ts_ms").notNull(),
	big: bigintNumber("big").notNull(),
	flagBool: bool("flag_bool").notNull(),
	flagNum: flag01("flag_num").notNull().default(0),
	doc: json<Payload>("doc").notNull(),
});

const DDL = (name: string) =>
	`CREATE TABLE ${name} (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, ts_ms INTEGER NOT NULL, big INTEGER NOT NULL, flag_bool INTEGER NOT NULL, flag_num INTEGER NOT NULL DEFAULT 0, doc TEXT NOT NULL)`;

const when = new Date(1790858096789);
const doc: Payload = { a: 1, nested: { b: ["x", "y"] } };

function setup() {
	const sqlite = new Database(":memory:");
	sqlite.exec(DDL("t_old"));
	sqlite.exec(DDL("t_new"));
	return { sqlite, db: drizzle(sqlite) };
}

function rawRow(sqlite: Database.Database, table: string) {
	return sqlite
		.prepare(
			`SELECT typeof(ts) AS t1, quote(ts) AS q1, typeof(ts_ms) AS t2, quote(ts_ms) AS q2, typeof(big) AS t3, quote(big) AS q3, typeof(flag_bool) AS t4, quote(flag_bool) AS q4, typeof(flag_num) AS t5, quote(flag_num) AS q5, typeof(doc) AS t6, quote(doc) AS q6 FROM ${table}`,
		)
		.all();
}

describe("SQLite storage is byte identical to the old builders", () => {
	it("stores the same bytes for every kind", () => {
		const { sqlite, db } = setup();
		db.insert(oldTable)
			.values({
				id: "1",
				ts: when,
				tsMs: when,
				big: 1790858096000,
				flagBool: true,
				flagNum: 1,
				doc,
			})
			.run();
		db.insert(newTable)
			.values({
				id: "1",
				ts: when,
				tsMs: when,
				big: 1790858096000,
				flagBool: true,
				flagNum: 1,
				doc,
			})
			.run();
		expect(rawRow(sqlite, "t_new")).toEqual(rawRow(sqlite, "t_old"));
		const [row] = rawRow(sqlite, "t_new") as Record<string, unknown>[];
		expect(row?.q1).toBe("1790858096");
		expect(row?.q2).toBe("1790858096789");
		expect(row?.q6).toBe(`'{"a":1,"nested":{"b":["x","y"]}}'`);
	});

	it("stores identical false values and defaults", () => {
		const { sqlite, db } = setup();
		const v = { id: "2", ts: when, tsMs: when, big: 5, flagBool: false, doc };
		db.insert(oldTable).values(v).run();
		db.insert(newTable).values(v).run();
		expect(rawRow(sqlite, "t_new")).toEqual(rawRow(sqlite, "t_old"));
		const [row] = rawRow(sqlite, "t_new") as Record<string, unknown>[];
		expect(row?.q4).toBe("0");
		expect(row?.q5).toBe("0");
	});

	it("reads back the same values as the old builders", () => {
		const { db } = setup();
		const v = { id: "3", ts: when, tsMs: when, big: 7, flagBool: true, flagNum: 1, doc };
		db.insert(oldTable).values(v).run();
		db.insert(newTable).values(v).run();
		const o = db.select().from(oldTable).get();
		const n = db.select().from(newTable).get();
		expect(n).toEqual({ ...o, id: "3" });
		expect(n?.ts.getTime()).toBe(1790858096000);
	});

	it("encodes lt(col, Date) as seconds like the old builder", () => {
		const { db } = setup();
		const q = db.select().from(newTable).where(lt(newTable.ts, when)).toSQL();
		const o = db.select().from(oldTable).where(lt(oldTable.ts, when)).toSQL();
		expect(q.params).toEqual([1790858096]);
		expect(q.params).toEqual(o.params);
	});

	it("updates through the encoder", () => {
		const { sqlite, db } = setup();
		db.insert(newTable)
			.values({ id: "4", ts: when, tsMs: when, big: 1, flagBool: false, doc })
			.run();
		db.update(newTable)
			.set({ flagBool: true, flagNum: 1, ts: new Date(2000) })
			.run();
		const r = sqlite.prepare("SELECT ts, flag_bool, flag_num FROM t_new").get();
		expect(r).toEqual({ ts: 2, flag_bool: 1, flag_num: 1 });
	});
});

describe("decoders accept whatever a driver returns", () => {
	const dec = <T>(col: { mapFromDriverValue: (v: unknown) => T }, v: unknown): T =>
		col.mapFromDriverValue(v);
	const cols = getTableColumns(newTable);

	it("timestampSec", () => {
		for (const v of [1790858096, "1790858096", 1790858096n]) {
			expect((dec(cols.ts, v) as Date).getTime()).toBe(1790858096000);
		}
	});
	it("timestampMs", () => {
		for (const v of [1790858096789, "1790858096789", 1790858096789n]) {
			expect((dec(cols.tsMs, v) as Date).getTime()).toBe(1790858096789);
		}
	});
	it("bigintNumber", () => {
		for (const v of [5, "5", 5n]) expect(dec(cols.big, v)).toBe(5);
	});
	it("bool", () => {
		for (const v of [true, 1, "1", "t", 1n]) expect(dec(cols.flagBool, v)).toBe(true);
		for (const v of [false, 0, "0", "f", 0n, null]) expect(dec(cols.flagBool, v)).toBe(false);
	});
	it("flag01", () => {
		for (const v of [true, 1, "1", "t", 1n]) expect(dec(cols.flagNum, v)).toBe(1);
		for (const v of [false, 0, "0", "f", 0n]) expect(dec(cols.flagNum, v)).toBe(0);
	});
	it("json accepts JSON text and parsed objects", () => {
		expect(dec(cols.doc, JSON.stringify(doc))).toEqual(doc);
		expect(dec(cols.doc, doc)).toEqual(doc);
		expect(dec(cols.doc, [1, 2])).toEqual([1, 2]);
	});
});

describe("columnKind", () => {
	it("tags every helper and falls back to text or integer", () => {
		const c = getTableColumns(newTable);
		const expected: Record<string, ColumnKind> = {
			id: "text",
			ts: "timestampSec",
			tsMs: "timestampMs",
			big: "bigint",
			flagBool: "bool",
			flagNum: "flag01",
			doc: "json",
		};
		for (const [k, kind] of Object.entries(expected)) {
			expect(columnKind(c[k as keyof typeof c])).toBe(kind);
		}
		expect(columnKind(getTableColumns(oldTable).big)).toBe("integer");
	});

	it("no schema column still uses a sqlite codec mode", () => {
		const tables = Object.values(schema).filter(
			(t): t is typeof newTable => typeof t === "object" && t !== null && "getSQL" in t,
		);
		expect(tables.length).toBeGreaterThan(20);
		for (const t of tables) {
			for (const col of Object.values(getTableColumns(t))) {
				expect([
					"text",
					"integer",
					"timestampSec",
					"timestampMs",
					"bigint",
					"json",
					"bool",
					"flag01",
				]).toContain(columnKind(col));
				expect(col.columnType).not.toBe("SQLiteTimestamp");
				expect(col.columnType).not.toBe("SQLiteBoolean");
				expect(col.columnType).not.toBe("SQLiteTextJson");
			}
		}
	});
});
