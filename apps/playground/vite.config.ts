import { defineConfig } from "vite";

// core's `@glinr/theauth/browser` entry imports no Node-only driver, and the app hands it
// the sql.js WASM loader (src/edge/sql-js.ts), so nothing needs stubbing here.
export default defineConfig({
	base: "./",
	build: { target: "es2022", chunkSizeWarningLimit: 1500 },
});
