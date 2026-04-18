import { defineConfig } from "tsup";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		bin: "src/bin.ts",
	},
	format: ["esm"],
	target: "node22",
	dts: true,
	clean: true,
	banner: {
		js: "#!/usr/bin/env node",
	},
});
