import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts", "src/store-contract/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["react", "@glinr/theauth-react", "vitest"],
	target: "es2022",
});
