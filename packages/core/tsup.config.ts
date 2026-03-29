import { defineConfig } from "tsup";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		"agent/index": "src/agent/index.ts",
		"auth/index": "src/auth/index.ts",
		"mcp/index": "src/mcp/index.ts",
		"permission/index": "src/permission/index.ts",
		"audit/index": "src/audit/index.ts",
		"a2a/index": "src/a2a/index.ts",
		"vc/index": "src/vc/index.ts",
		"crypto/index": "src/crypto/index.ts",
		"redirect/index": "src/redirect/index.ts",
	},
	format: ["esm"],
	dts: true,
	clean: true,
	sourcemap: true,
	splitting: true,
	treeshake: true,
	target: "es2022",
	external: ["better-sqlite3", "pg", "mysql2", "mysql2/promise", "@libsql/client"],
});
