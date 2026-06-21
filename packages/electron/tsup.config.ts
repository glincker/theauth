import { defineConfig } from "tsup";
export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["electron", "react", "@glinr/theauth-react"],
	target: "es2022",
});
