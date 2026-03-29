import type { Page } from "@playwright/test";
import { expect, test } from "@playwright/test";

const SESSION_KEY = "kavachos_dashboard_secret";
const THEME_KEY = "kavachos-theme";

const STATS_FIXTURE = {
	totalAgents: 3,
	activeAgents: 2,
	totalAuditEvents: 42,
	recentAuditEvents: 5,
	authAllowedRate: 80,
	activeDelegations: 1,
};

const AGENTS_FIXTURE = [
	{
		id: "agent-1",
		name: "Test Agent",
		type: "llm",
		status: "active",
		permissionsCount: 2,
		lastActiveAt: "2026-03-29T12:00:00.000Z",
		createdAt: "2026-03-20T12:00:00.000Z",
		expiresAt: null,
		metadata: {},
	},
];

const AUDIT_FIXTURE = {
	entries: [
		{
			id: "audit-1",
			timestamp: "2026-03-29T12:05:00.000Z",
			agentId: "agent-1",
			agentName: "Test Agent",
			action: "read",
			resource: "users:123",
			result: "allowed",
			durationMs: 12,
			metadata: {},
		},
	],
	total: 1,
	limit: 10,
	offset: 0,
};

const SETTINGS_FIXTURE = {
	database: {
		adapter: "sqlite",
		url: ":memory:",
		version: "3.45.0",
	},
	tokenExpirySeconds: 3600,
	rateLimitRequestsPerMinute: 60,
	rateLimitWindowSeconds: 60,
	auditRetentionDays: 30,
	maxAgentsPerTenant: 100,
};

async function mockAuthenticatedDashboard(page: Page) {
	await page.route("**/api/**", (route) => {
		const { pathname } = new URL(route.request().url());

		switch (pathname) {
			case "/api/dashboard/auth":
				return route.fulfill({ status: 200 });
			case "/api/dashboard/stats":
				return route.fulfill({
					status: 200,
					contentType: "application/json",
					body: JSON.stringify(STATS_FIXTURE),
				});
			case "/api/audit":
				return route.fulfill({
					status: 200,
					contentType: "application/json",
					body: JSON.stringify(AUDIT_FIXTURE),
				});
			case "/api/agents":
				return route.fulfill({
					status: 200,
					contentType: "application/json",
					body: JSON.stringify(AGENTS_FIXTURE),
				});
			case "/api/users":
			case "/api/permissions/templates":
			case "/api/delegations":
			case "/api/mcp/servers":
				return route.fulfill({
					status: 200,
					contentType: "application/json",
					body: JSON.stringify([]),
				});
			case "/api/settings":
				return route.fulfill({
					status: 200,
					contentType: "application/json",
					body: JSON.stringify(SETTINGS_FIXTURE),
				});
			default:
				return route.fulfill({
					status: 404,
					contentType: "application/json",
					body: JSON.stringify({ code: "UNMOCKED_ROUTE", message: pathname }),
				});
		}
	});
}

async function gotoAuthenticatedDashboard(page: Page) {
	await page.goto("/");
	await page.evaluate(
		([sessionKey, themeKey]) => {
			sessionStorage.setItem(sessionKey, "test-secret");
			localStorage.removeItem(themeKey);
		},
		[SESSION_KEY, THEME_KEY],
	);
	await page.reload();
	await expect(page.locator("aside nav")).toBeVisible();
	await expect(page.locator("main h1", { hasText: "Overview" })).toBeVisible();
}

// ─── Login page (unauthenticated) ─────────────────────────────────────────────

test.describe("login screen", () => {
	test.beforeEach(async ({ page }) => {
		// Clear any stored session so we always land on login
		await page.context().clearCookies();
		await page.goto("/");
		await page.evaluate((sessionKey) => sessionStorage.removeItem(sessionKey), SESSION_KEY);
		await page.reload();
	});

	test("shows KavachOS branding", async ({ page }) => {
		await expect(page.locator("h1", { hasText: "KavachOS" })).toBeVisible();
		await expect(page.locator("text=Admin Dashboard")).toBeVisible();
	});

	test("shows secret input and submit button", async ({ page }) => {
		await expect(page.locator("#kavachos-secret")).toBeVisible();
		await expect(page.locator('button[type="submit"]')).toBeVisible();
		await expect(page.locator('button[type="submit"]')).toHaveText("Access dashboard");
	});

	test("submit button is disabled when secret is empty", async ({ page }) => {
		await expect(page.locator('button[type="submit"]')).toBeDisabled();
	});

	test("submit button enables when secret is typed", async ({ page }) => {
		await page.fill("#kavachos-secret", "some-secret");
		await expect(page.locator('button[type="submit"]')).toBeEnabled();
	});

	test("shows toggle to reveal secret", async ({ page }) => {
		const input = page.locator("#kavachos-secret");
		await expect(input).toHaveAttribute("type", "password");

		await page.click('button[aria-label="Show secret"]');
		await expect(input).toHaveAttribute("type", "text");

		await page.click('button[aria-label="Hide secret"]');
		await expect(input).toHaveAttribute("type", "password");
	});

	test("shows error on invalid secret", async ({ page }) => {
		await page.fill("#kavachos-secret", "wrong-secret");
		await page.click('button[type="submit"]');

		// Error appears once the request resolves - either API error or network error
		await expect(page.locator("text=/Invalid secret|Could not reach the API/")).toBeVisible({
			timeout: 10_000,
		});
	});
});

// ─── Authenticated shell ───────────────────────────────────────────────────────

test.describe("authenticated dashboard", () => {
	test.beforeEach(async ({ page }) => {
		await mockAuthenticatedDashboard(page);
		await gotoAuthenticatedDashboard(page);
	});

	test("shows sidebar with KavachOS logo", async ({ page }) => {
		await expect(page.locator("aside")).toBeVisible();
		await expect(page.locator("aside", { hasText: "KavachOS" })).toBeVisible();
	});

	test("sidebar has all main nav items", async ({ page }) => {
		const nav = page.locator("aside nav");
		await expect(nav.locator("button", { hasText: "Overview" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Agents" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Users" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Permissions" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Delegations" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "MCP Servers" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Audit Log" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Security" })).toBeVisible();
		await expect(nav.locator("button", { hasText: "Settings" })).toBeVisible();
	});

	test("sidebar shows system online indicator", async ({ page }) => {
		await expect(page.locator("aside", { hasText: "System Online" })).toBeVisible();
	});

	test("header has theme toggle and sign out button", async ({ page }) => {
		await expect(page.locator('button[aria-label*="mode"]')).toBeVisible();
		await expect(page.locator("button", { hasText: "Sign out" })).toBeVisible();
	});

	test("overview is the default active page", async ({ page }) => {
		const overviewBtn = page.locator("aside nav button", { hasText: "Overview" });
		await expect(overviewBtn).toHaveClass(/bg-zinc/);
	});

	test("navigates to agents page", async ({ page }) => {
		const agentsBtn = page.locator("aside nav button", { hasText: "Agents" });
		await agentsBtn.click();
		await expect(agentsBtn).toHaveClass(/bg-zinc/);
		await expect(page.locator("main h1", { hasText: "Agents" })).toBeVisible();
	});

	test("navigates to audit log page", async ({ page }) => {
		const auditBtn = page.locator("aside nav button", { hasText: "Audit Log" });
		await auditBtn.click();
		await expect(auditBtn).toHaveClass(/bg-zinc/);
		await expect(page.locator("main h1", { hasText: "Audit Log" })).toBeVisible();
	});

	test("navigates to settings page", async ({ page }) => {
		const settingsBtn = page.locator("aside nav button", { hasText: "Settings" });
		await settingsBtn.click();
		await expect(settingsBtn).toHaveClass(/bg-zinc/);
		await expect(page.locator("main h1", { hasText: "Settings" })).toBeVisible();
	});

	test("sign out returns to login screen", async ({ page }) => {
		await page.locator("button", { hasText: "Sign out" }).click();
		await expect(page.locator("#kavachos-secret")).toBeVisible();
	});

	test("theme toggle switches between light and dark", async ({ page }) => {
		const html = page.locator("html");
		// Start in dark (default)
		await expect(html).toHaveClass(/dark/);

		const toggleBtn = page.locator('button[aria-label*="mode"]');
		await toggleBtn.click();
		await expect(html).not.toHaveClass(/dark/);

		await toggleBtn.click();
		await expect(html).toHaveClass(/dark/);
	});
});
