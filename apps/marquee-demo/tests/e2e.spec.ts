import { expect, test } from "@playwright/test";

/**
 * Full five-step demo scenario.
 * Each assertion verifies that the panel reaches its green-check state in order.
 * The final assertion confirms the reset button returns panel 1 to its initial state.
 *
 * Run with: pnpm --filter marquee-demo test:e2e
 */

const BASE = process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3001";

test.describe("KavachOS marquee demo", () => {
	test.beforeEach(async ({ page }) => {
		// Clear any existing session before each test
		await page.goto(BASE);
		const resetBtn = page.getByTestId("reset-button");
		if (await resetBtn.isVisible()) {
			await resetBtn.click();
			await page.waitForTimeout(500);
		}
	});

	test("step 1, passkey sign-up", async ({ page }) => {
		await page.goto(BASE);

		// Panel 1 is visible and initially not done
		const panel1 = page.getByTestId("panel-1");
		await expect(panel1).toBeVisible();
		await expect(panel1).toHaveAttribute("data-done", "false");

		// Fill in username and sign up
		await page.getByTestId("username-input").fill("Test User");
		await page.getByTestId("signup-button").click();

		// Panel 1 should reach done state
		await expect(panel1).toHaveAttribute("data-done", "true", { timeout: 8000 });
	});

	test("step 2, spawn agent", async ({ page }) => {
		await page.goto(BASE);

		// Complete step 1
		await page.getByTestId("username-input").fill("Test User");
		await page.getByTestId("signup-button").click();
		await expect(page.getByTestId("panel-1")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		// Spawn agent
		await page.getByTestId("spawn-agent-button").click();
		await expect(page.getByTestId("panel-2")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});
	});

	test("step 3, three tool calls with audit log", async ({ page }) => {
		await page.goto(BASE);

		await page.getByTestId("username-input").fill("Test User");
		await page.getByTestId("signup-button").click();
		await expect(page.getByTestId("panel-1")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		await page.getByTestId("spawn-agent-button").click();
		await expect(page.getByTestId("panel-2")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		// Make three tool calls
		for (let i = 0; i < 3; i++) {
			await page.getByTestId("tool-call-button").click();
			// Brief wait between calls
			await page.waitForTimeout(500);
		}

		await expect(page.getByTestId("panel-3")).toHaveAttribute("data-done", "true", {
			timeout: 10000,
		});

		// Audit entries should be present
		const auditEntries = page.getByTestId("audit-entry");
		await expect(auditEntries).toHaveCount(3, { timeout: 8000 });
	});

	test("step 4, delegation to sub-agent", async ({ page }) => {
		await page.goto(BASE);

		await page.getByTestId("username-input").fill("Test User");
		await page.getByTestId("signup-button").click();
		await expect(page.getByTestId("panel-1")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		await page.getByTestId("spawn-agent-button").click();
		await expect(page.getByTestId("panel-2")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		for (let i = 0; i < 3; i++) {
			await page.getByTestId("tool-call-button").click();
			await page.waitForTimeout(400);
		}
		await expect(page.getByTestId("panel-3")).toHaveAttribute("data-done", "true", {
			timeout: 10000,
		});

		await page.getByTestId("delegate-button").click();
		await expect(page.getByTestId("panel-4")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});
	});

	test("step 5, full scenario and export", async ({ page }) => {
		await page.goto(BASE);

		await page.getByTestId("username-input").fill("Test User");
		await page.getByTestId("signup-button").click();
		await expect(page.getByTestId("panel-1")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		await page.getByTestId("spawn-agent-button").click();
		await expect(page.getByTestId("panel-2")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		for (let i = 0; i < 3; i++) {
			await page.getByTestId("tool-call-button").click();
			await page.waitForTimeout(400);
		}
		await expect(page.getByTestId("panel-3")).toHaveAttribute("data-done", "true", {
			timeout: 10000,
		});

		await page.getByTestId("delegate-button").click();
		await expect(page.getByTestId("panel-4")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		// Export, verify download
		const downloadPromise = page.waitForEvent("download");
		await page.getByTestId("export-button").click();
		const download = await downloadPromise;
		expect(download.suggestedFilename()).toBe("kavachos-audit-export.json");

		await expect(page.getByTestId("panel-5")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});
	});

	test("reset button clears state, panel 1 returns to initial", async ({ page }) => {
		await page.goto(BASE);

		// Complete step 1
		await page.getByTestId("username-input").fill("Test User");
		await page.getByTestId("signup-button").click();
		await expect(page.getByTestId("panel-1")).toHaveAttribute("data-done", "true", {
			timeout: 8000,
		});

		// Reset
		await page.getByTestId("reset-button").click();

		// Panel 1 should be back to initial (not done)
		await expect(page.getByTestId("panel-1")).toHaveAttribute("data-done", "false", {
			timeout: 5000,
		});

		// Input should be available again
		await expect(page.getByTestId("username-input")).toBeEnabled({ timeout: 5000 });
	});
});
