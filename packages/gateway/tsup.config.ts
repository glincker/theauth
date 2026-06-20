import { defineConfig } from "tsup";

export default defineConfig([
	{
		entry: ["src/index.ts"],
		format: ["esm"],
		dts: true,
		sourcemap: true,
		splitting: false,
		treeshake: true,
		target: "node22",
		external: ["theauth", "zod"],
	},
	{
		entry: ["src/cli.ts"],
		format: ["esm"],
		dts: false,
		clean: false,
		sourcemap: true,
		splitting: false,
		treeshake: true,
		target: "node22",
		external: ["theauth", "zod"],
		banner: {
			js: "#!/usr/bin/env node",
		},
	},
]);
