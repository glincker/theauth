import { fileURLToPath } from "node:url";
import type { Plugin } from "vite";
import { defineConfig } from "vite";

// Optional server-side drivers that core imports lazily. A browser never reaches them
// (the playground only uses the in-memory sql.js store), so they resolve to an empty module.
const SERVER_ONLY = new Set([
	"nodemailer",
	"pg",
	"mysql2",
	"mysql2/promise",
	"better-sqlite3",
	"@libsql/client",
	"drizzle-orm/better-sqlite3",
	"drizzle-orm/node-postgres",
	"drizzle-orm/mysql2",
	"drizzle-orm/libsql",
]);
const EMPTY = "\0playground-empty";
// core's root bundle statically imports deflateRaw from zlib (used only by chunked cookie
// compression, which needs a server). The stub throws if anything ever calls it.
const ZLIB = "\0playground-zlib";

function serverOnlyStub(): Plugin {
	return {
		name: "playground-server-only-stub",
		enforce: "pre",
		resolveId(id) {
			if (id === "zlib") return ZLIB;
			return SERVER_ONLY.has(id) ? EMPTY : null;
		},
		load(id) {
			if (id === ZLIB) {
				return 'export function deflateRaw() { throw new Error("zlib is not available in the browser"); }';
			}
			return id === EMPTY ? "export default {};" : null;
		},
	};
}

// core opens SQLite through `import("sql.js")` and calls initSqlJs() with no arguments.
// In a browser that cannot find the .wasm file, so the app aliases sql.js to a thin
// wrapper (src/edge/sql-js.ts) that supplies locateFile. Nothing else is stubbed.
export default defineConfig({
	base: "./",
	plugins: [serverOnlyStub()],
	resolve: {
		alias: [
			{
				find: /^sql\.js$/,
				replacement: fileURLToPath(new URL("./src/edge/sql-js.ts", import.meta.url)),
			},
		],
	},
	build: { target: "es2022", chunkSizeWarningLimit: 1500 },
});
