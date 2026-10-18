import { TIMESTAMP_COLUMNS } from "../ddl/index.js";
import type { Migration } from "../migrate/types.js";

/** One DO block per table, kept on a single line: statements are joined with a semicolon and newline, and the hand apply path splits on that. */
function postgresStatements(): string[] {
	const byTable = new Map<string, string[]>();
	for (const { table, column, unit } of TIMESTAMP_COLUMNS) {
		const list = byTable.get(table) ?? [];
		list.push(`('${column}', ${unit === "ms" ? 1000 : 1})`);
		byTable.set(table, list);
	}
	return [...byTable].map(
		([table, values]) =>
			`DO $$ DECLARE c record; BEGIN FOR c IN SELECT v.col AS col, v.mult AS mult FROM (VALUES ${values.join(", ")}) AS v(col, mult) JOIN information_schema.columns i ON i.table_schema = current_schema() AND i.table_name = '${table}' AND i.column_name = v.col AND i.data_type = 'timestamp with time zone' LOOP EXECUTE format('ALTER TABLE ${table} ALTER COLUMN %I DROP DEFAULT, ALTER COLUMN %I TYPE BIGINT USING floor(extract(epoch FROM %I) * %s)::bigint', c.col, c.col, c.col, c.mult); END LOOP; END $$`,
	);
}

/**
 * Timestamps are integer epoch values on every dialect (seconds, or milliseconds for login history), the representation SQLite always used. Databases created by 1.2.0 on Postgres have TIMESTAMPTZ columns; this converts them in place from the explicit column list in the DDL module (never a prefix scan, because other tools may own tables with the same prefix).
 *
 * Each block only touches columns that are still TIMESTAMPTZ, so fresh databases (already BIGINT), reruns and tables of disabled features are no-ops. SQLite already stores integers, and no working 1.2.0 MySQL database can exist (its baseline was rejected by the server), so both dialects have nothing to do.
 */
export const epochTimestamps: Migration = {
	id: "0003",
	name: "epoch-timestamps",
	up: {
		sqlite: [],
		postgres: postgresStatements(),
		mysql: [],
	},
};
