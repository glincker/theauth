import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The browser wasm loader (src/edge/sql-js.ts) cannot run in Node, so tests swap in a shim.
export default defineConfig({
	resolve: {
		alias: [
			{
				find: /^\.\/edge\/sql-js\.js$/,
				replacement: fileURLToPath(new URL("./tests/node-sql-js.ts", import.meta.url)),
			},
		],
	},
	test: { environment: "node", include: ["tests/**/*.test.ts"] },
});
