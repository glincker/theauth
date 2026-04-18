import type { Config } from "tailwindcss";

const config: Config = {
	content: ["./src/**/*.{ts,tsx}"],
	theme: {
		extend: {
			colors: {
				brand: {
					DEFAULT: "#C9A84C",
					light: "#E0C56A",
					dark: "#8B6914",
				},
			},
			fontFamily: {
				mono: ["JetBrains Mono", "ui-monospace", "monospace"],
				sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
			},
		},
	},
	plugins: [],
};

export default config;
