import type { FeatureKey } from "../migrate/features.js";
import type { Dialect } from "../migrate/types.js";

/** One baseline statement, tagged with the feature that needs it. */
export interface TaggedStatement {
	feature: FeatureKey;
	sql: string;
}

/** Dialect specific column types shared by every DDL module. */
export interface DdlTypes {
	dialect: Dialect;
	isPostgres: boolean;
	isMysql: boolean;
	/** Timestamp column type: integer epoch seconds on every dialect (BIGINT on Postgres and MySQL). */
	ts: string;
	/** Nullable timestamp column type (same type, kept for readability at call sites). */
	tsNull: string;
	/** 64 bit integer column (epoch milliseconds, micro-dollar costs). */
	big: string;
	json: string;
	bool: string;
	/** `IF NOT EXISTS` clause. */
	ifne: string;
	/** Indexed text columns need a bounded type on MySQL. */
	vc: string;
}

export function ddlTypes(dialect: Dialect): DdlTypes {
	const isPostgres = dialect === "postgres";
	const isMysql = dialect === "mysql";
	const big = isPostgres || isMysql ? "BIGINT" : "INTEGER";
	return {
		dialect,
		isPostgres,
		isMysql,
		ts: big,
		tsNull: big,
		big,
		json: isPostgres ? "JSONB" : isMysql ? "JSON" : "TEXT",
		bool: isPostgres ? "BOOLEAN" : isMysql ? "TINYINT(1)" : "INTEGER",
		ifne: "IF NOT EXISTS",
		vc: isMysql ? "VARCHAR(191)" : "TEXT",
	};
}
