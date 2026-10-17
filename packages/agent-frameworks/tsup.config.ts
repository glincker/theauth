import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts", "src/langchain.ts", "src/mastra.ts"],
	format: ["esm"],
	dts: true,
	sourcemap: true,
	external: ["@glinr/theauth", "@langchain/langgraph", "@mastra/core"],
	target: "es2022",
});
