// App edge shim for `sql.js`. Core calls `initSqlJs()` with no arguments, which in a
// browser looks for the .wasm file next to the page. This wrapper points it at the
// file Vite bundles. In Node (the smoke test) the alias is not applied.
import initSqlJs from "sql.js/dist/sql-wasm-browser.js";
import wasmUrl from "sql.js/dist/sql-wasm-browser.wasm?url";

type InitConfig = Parameters<typeof initSqlJs>[0];

export default function init(config?: InitConfig) {
	return initSqlJs({ locateFile: () => wasmUrl, ...config });
}
