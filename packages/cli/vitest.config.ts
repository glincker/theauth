import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		environment: "node",
		globals: true,
		include: ["tests/**/*.test.ts"],
		// CI runners import the core build slowly; the default 5s flaked.
		testTimeout: 20_000,
	},
});
