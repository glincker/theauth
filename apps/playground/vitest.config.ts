import { defineConfig } from "vitest/config";

// No sql.js alias here: in Node core loads the regular sql.js build.
export default defineConfig({
	test: { environment: "node", include: ["tests/**/*.test.ts"] },
});
