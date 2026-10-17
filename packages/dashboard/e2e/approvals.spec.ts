import { expect, test } from "@playwright/test";

const SOON = new Date(Date.now() + 240_000).toISOString();

const APPROVAL = {
	id: "apr_1",
	action: "admin:revoke_agent",
	resource: "agent:abc",
	requestedBy: "user_ops",
	createdAt: new Date().toISOString(),
	expiresAt: SOON,
	arguments: '{"reason":"leaked key"}',
	argumentsTruncated: false,
};

async function mockApprovals(page: import("@playwright/test").Page, state: { pending: unknown[] }) {
	const decisions: string[] = [];
	await page.route("**/api/dashboard/auth", (route) =>
		route.fulfill({ status: 200, contentType: "application/json", body: '{"ok":true}' }),
	);
	await page.route("**/api/**", (route) => {
		const { pathname } = new URL(route.request().url());
		if (pathname === "/api/approvals") {
			return route.fulfill({
				status: 200,
				contentType: "application/json",
				body: JSON.stringify(state.pending),
			});
		}
		if (pathname.startsWith("/api/approvals/") && route.request().method() === "POST") {
			decisions.push(pathname);
			state.pending = [];
			return route.fulfill({
				status: 200,
				contentType: "application/json",
				body: JSON.stringify({ id: "apr_1", status: "approved", respondedAt: SOON }),
			});
		}
		return route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
	});
	return decisions;
}

test.describe("approvals page", () => {
	test("approves a request after a confirm step", async ({ page }) => {
		const decisions = await mockApprovals(page, { pending: [APPROVAL] });
		await page.goto("/");
		await page.locator("aside nav button", { hasText: "Approvals" }).click();
		await expect(page.locator("main h1", { hasText: "Approvals" })).toBeVisible();
		await expect(page.getByText("admin:revoke_agent")).toBeVisible();
		await page.getByRole("button", { name: /Show arguments/ }).click();
		await expect(page.getByText("leaked key")).toBeVisible();

		await page.getByRole("button", { name: /^Approve admin:revoke_agent/ }).click();
		expect(decisions).toHaveLength(0);
		await page.getByRole("button", { name: /^Confirm approve/ }).click();
		await expect(page.getByText("No pending approvals")).toBeVisible();
		expect(decisions).toEqual(["/api/approvals/apr_1/approve"]);
	});

	test("shows the empty state", async ({ page }) => {
		await mockApprovals(page, { pending: [] });
		await page.goto("/");
		await page.locator("aside nav button", { hasText: "Approvals" }).click();
		await expect(page.getByText("No pending approvals")).toBeVisible();
	});
});
