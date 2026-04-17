import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	splitting: false,
	treeshake: true,
	target: "node22",
	external: [
		"kavachos",
		"@nestjs/common",
		"@nestjs/core",
		"rxjs",
		"reflect-metadata",
		"zod",
		"express",
	],
});
