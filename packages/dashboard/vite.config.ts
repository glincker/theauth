import { resolve } from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
	const isLib = mode === "lib";

	return {
		plugins: [react(), tailwindcss()],
		define: {
			"process.env.NODE_ENV": JSON.stringify(mode === "production" ? "production" : "development"),
		},
		build: isLib
			? {
					// Library mode: bundle as importable component for embedding
					lib: {
						entry: resolve(import.meta.dirname, "src/index.ts"),
						name: "TheAuthDashboard",
						formats: ["es"],
						fileName: (format) => `index.${format}.js`,
					},
					rollupOptions: {
						// Externalize deps that should not be bundled
						external: ["react", "react-dom", "react/jsx-runtime"],
						output: {
							globals: {
								react: "React",
								"react-dom": "ReactDOM",
							},
						},
					},
				}
			: {
					// App mode: standalone SPA build
					outDir: "dist/app",
					rollupOptions: {
						input: resolve(import.meta.dirname, "index.html"),
					},
				},
	};
});
