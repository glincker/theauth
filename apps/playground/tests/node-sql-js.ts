// Node stand-in for src/edge/sql-js.ts: the regular sql.js build finds its own wasm.
import initSqlJs from "sql.js";

export function loadSqlJs() {
	return initSqlJs();
}
