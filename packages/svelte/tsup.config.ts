import { defineConfig } from "tsup";
export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["svelte", "svelte/store", "@glinr/theauth-client"],
	target: "es2022",
});
