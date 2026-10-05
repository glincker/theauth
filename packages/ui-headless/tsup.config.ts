import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["react", "@tanstack/react-query", "@glinr/theauth-react", "@glinr/theauth-client"],
	jsx: "automatic",
	target: "es2022",
});
