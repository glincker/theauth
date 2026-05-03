import { defineConfig } from "tsup";

export default defineConfig([
	// Main entry — Node.js runtime, includes server-only server exports.
	{
		entry: { index: "src/index.ts" },
		format: ["esm"],
		dts: true,
		sourcemap: true,
		splitting: false,
		treeshake: true,
		target: "node20",
		external: ["next", "react", "server-only"],
	},
	// Middleware entry — Edge-runtime safe, no next/headers, no server-only.
	{
		entry: { middleware: "src/middleware.ts" },
		format: ["esm"],
		dts: true,
		sourcemap: true,
		splitting: false,
		treeshake: true,
		target: "es2022",
		external: ["next", "react"],
	},
]);
