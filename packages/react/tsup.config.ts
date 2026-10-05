import { defineConfig } from "tsup";
export default defineConfig({
	entry: { index: "src/index.ts", query: "src/query/index.ts" },
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["react", "@tanstack/react-query", "@glinr/theauth-client"],
	target: "es2022",
});
