import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	splitting: false,
	treeshake: true,
	// esnext: ensures no Node-only polyfills are injected, making the output
	// compatible with both Node.js and Cloudflare Workers runtime.
	target: "esnext",
	external: ["theauth", "zod", "hono"],
});
