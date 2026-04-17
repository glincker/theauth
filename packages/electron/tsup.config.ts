import { defineConfig } from "tsup";
export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["electron", "react", "@kavachos/react"],
	target: "es2022",
});
