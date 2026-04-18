import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
	testDir: "./tests",
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	workers: 1,
	reporter: process.env.CI ? "github" : "list",
	use: {
		baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3001",
		trace: "on-first-retry",
	},
	projects: [
		{
			name: "chromium",
			use: { ...devices["Desktop Chrome"] },
		},
	],
	webServer: process.env.CI
		? undefined
		: {
				command: "pnpm dev",
				url: "http://localhost:3001",
				reuseExistingServer: !process.env.CI,
				timeout: 60000,
			},
});
