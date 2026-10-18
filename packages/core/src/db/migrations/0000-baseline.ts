import { baselineStatements } from "../ddl/index.js";
import { upgradePreLedgerColumns } from "../migrate/legacy.js";
import type { Dialect, Migration } from "../migrate/types.js";

function allStatements(dialect: Dialect): string[] {
	return baselineStatements(dialect).map((s) => s.sql);
}

/**
 * Every table TheAuth had when the ledger was introduced (the 1.x schema, plus the columns 0001 to 0003 add on top, which fresh databases get from the CREATE statements).
 * At runtime only tables for enabled features are created; the generated SQL carries all of them.
 */
export const baseline: Migration = {
	id: "0000",
	name: "baseline",
	up: {
		sqlite: allStatements("sqlite"),
		postgres: allStatements("postgres"),
		mysql: allStatements("mysql"),
	},
	statementsFor: (dialect, features) =>
		baselineStatements(dialect)
			.filter((s) => features[s.feature])
			.map((s) => s.sql),
	// Databases from before the audit chain and single use approvals need columns first,
	// because the baseline indexes reference them.
	run: async (exec, ctx) => {
		await upgradePreLedgerColumns(exec, ctx.features);
	},
};
