import { defineConfig } from "tsup";

export default defineConfig([
	{
		entry: { index: "src/index.ts" },
		format: ["esm"],
		dts: true,
		target: "node20",
		clean: true,
	},
	{
		entry: { bin: "src/bin.ts" },
		format: ["esm"],
		target: "node20",
		clean: false,
		banner: { js: "#!/usr/bin/env node" },
	},
]);
