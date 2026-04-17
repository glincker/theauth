import { defineConfig } from "tsup";

export default defineConfig({
	entry: {
		index: "src/index.ts",
	},
	format: ["esm"],
	dts: true,
	sourcemap: true,
	splitting: false,
	treeshake: true,
	target: "node22",
});
