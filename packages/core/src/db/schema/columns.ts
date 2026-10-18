import type { Column } from "drizzle-orm";
import { customType } from "drizzle-orm/sqlite-core";

/**
 * Dialect-neutral column helpers. The schema is declared once with sqlite-core builders and
 * runs on SQLite, D1, Postgres and MySQL. Each decoder accepts whatever any driver returns:
 * numbers, numeric strings (int8 on pg drivers), bigint, booleans, parsed JSON or JSON text.
 *
 * The `dataType` tags are never emitted as DDL: theAuth writes DDL by hand (src/db/ddl) and
 * does not use drizzle-kit. They exist so `columnKind()` can tell the helpers apart.
 */

type IntLike = number | string | bigint;

const truthy = (v: unknown): boolean => v === true || v === 1 || v === "1" || v === "t" || v === 1n;

const TAG_TS_S = "theauth_ts_s";
const TAG_TS_MS = "theauth_ts_ms";
const TAG_BIGINT = "theauth_bigint";
const TAG_BOOL = "theauth_bool";
const TAG_FLAG01 = "theauth_flag01";
const TAG_JSON = "theauth_json";

/** Date stored as integer epoch seconds on every dialect (SQLite INTEGER, Postgres and MySQL BIGINT). */
export const timestampSec = customType<{ data: Date; driverData: IntLike }>({
	dataType: () => TAG_TS_S,
	toDriver: (d) => Math.floor(d.getTime() / 1000),
	fromDriver: (v) => new Date(Number(v) * 1000),
});

/** Date stored as integer epoch milliseconds. */
export const timestampMs = customType<{ data: Date; driverData: IntLike }>({
	dataType: () => TAG_TS_MS,
	toDriver: (d) => d.getTime(),
	fromDriver: (v) => new Date(Number(v)),
});

/** Plain number in a BIGINT column (int8 arrives as a string on pg drivers). */
export const bigintNumber = customType<{ data: number; driverData: IntLike }>({
	dataType: () => TAG_BIGINT,
	toDriver: (n) => n,
	fromDriver: (v) => Number(v),
});

/** Boolean stored as 0/1 on SQLite and MySQL, BOOLEAN on Postgres (which accepts '1' and '0'). */
export const bool = customType<{ data: boolean; driverData: unknown }>({
	dataType: () => TAG_BOOL,
	toDriver: (b) => (b ? 1 : 0),
	fromDriver: truthy,
});

/** Legacy 0/1 number flags stored as BOOLEAN on Postgres. Keeps the TS type `number`. */
export const flag01 = customType<{ data: number; driverData: unknown }>({
	dataType: () => TAG_FLAG01,
	toDriver: (n) => (n ? 1 : 0),
	fromDriver: (v) => (truthy(v) ? 1 : 0),
});

/** JSON text on SQLite, JSONB on Postgres, JSON on MySQL. Drivers that parse JSON hand back objects. */
export function json<T>(name: string) {
	return customType<{ data: T; driverData: unknown }>({
		dataType: () => TAG_JSON,
		toDriver: (v) => JSON.stringify(v),
		fromDriver: (v) => (typeof v === "string" ? (JSON.parse(v) as T) : (v as T)),
	})(name);
}

export type ColumnKind =
	| "text"
	| "integer"
	| "timestampSec"
	| "timestampMs"
	| "bigint"
	| "json"
	| "bool"
	| "flag01";

const KIND_BY_TAG: Readonly<Record<string, ColumnKind>> = {
	[TAG_TS_S]: "timestampSec",
	[TAG_TS_MS]: "timestampMs",
	[TAG_BIGINT]: "bigint",
	[TAG_BOOL]: "bool",
	[TAG_FLAG01]: "flag01",
	[TAG_JSON]: "json",
};

/** Used by the schema parity test: maps a Drizzle column to the helper kind that declared it. */
export function columnKind(col: Column): ColumnKind {
	const sqlType = col.getSQLType();
	const tagged = KIND_BY_TAG[sqlType];
	if (tagged) return tagged;
	return sqlType === "text" ? "text" : "integer";
}
