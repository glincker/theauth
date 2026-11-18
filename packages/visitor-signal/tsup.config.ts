import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	splitting: false,
	treeshake: true,
	target: "es2022",
	platform: "neutral",
	minify: true,
});
