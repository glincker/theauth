// Browser sql.js loader handed to `createTheAuth({ sqlJs })`. The default init cannot find
// the .wasm file in a browser, so this points it at the file Vite bundles.
import initSqlJs from "sql.js/dist/sql-wasm-browser.js";
import wasmUrl from "sql.js/dist/sql-wasm-browser.wasm?url";

export function loadSqlJs() {
	return initSqlJs({ locateFile: () => wasmUrl });
}
