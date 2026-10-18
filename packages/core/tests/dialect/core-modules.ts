import { describe, expect, it } from "vitest";
import { createCostAttributionModule } from "../../src/auth/cost-attribution.js";
import type { CoreBooter } from "./core-boot.js";
import { defineMcpCoreTests } from "./core-mcp.js";

const HOUR = 3_600_000;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function defineModuleCoreTests(booter: CoreBooter): void {
	const { boot } = booter;

	defineMcpCoreTests(booter);

	describe("approvals", () => {
		it("consumes an approval exactly once under concurrency", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "apr@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "pay",
				type: "autonomous",
				permissions: [
					{
						resource: "mcp:payments:*",
						actions: ["execute"],
						constraints: { requireApproval: true },
					},
				],
			});
			const req = await auth.approval.request({
				agentId: agent.id,
				userId: user.id,
				action: "execute",
				resource: "mcp:payments:refund",
			});
			await auth.approval.approve(req.id, "human-1");
			const call = () =>
				auth.authorize(agent.id, {
					action: "execute",
					resource: "mcp:payments:refund",
					approvalId: req.id,
				});
			const results = await Promise.all([call(), call(), call(), call()]);
			expect(results.filter((r) => r.allowed)).toHaveLength(1);
			for (const r of results.filter((x) => !x.allowed)) {
				expect(r.reason).toBe("APPROVAL_ALREADY_USED");
			}
			const row = await auth.approval.get(req.id);
			expect(row?.status).toBe("approved");
		});
	});

	describe("email flows", () => {
		it("email OTP code is single use and creates a session", async () => {
			const { auth, mail } = await boot();
			const emailOtp = auth.emailOtp;
			if (!emailOtp) throw new Error("emailOtp module missing");
			expect(await emailOtp.sendCode("otp@example.com")).toMatchObject({ sent: true });
			const code = mail.otpCodes.at(-1) ?? "";
			expect(code).toMatch(/^\d{6}$/);
			const first = await emailOtp.verifyCode("otp@example.com", code);
			expect(first?.user.email).toBe("otp@example.com");
			expect(first?.session.expiresAt.getTime()).toBeGreaterThan(Date.now());
			expect(await emailOtp.verifyCode("otp@example.com", code)).toBeNull();
			expect((await auth.user.get("otp@example.com"))?.id).toBe(first?.user.id);
		});

		it("magic link token is single use, also under concurrency", async () => {
			const { auth, mail } = await boot();
			const magicLink = auth.magicLink;
			if (!magicLink) throw new Error("magicLink module missing");
			expect(await magicLink.sendLink("ml@example.com")).toEqual({ sent: true });
			const token = mail.magicTokens.at(-1) ?? "";
			const results = await Promise.all([
				magicLink.verify(token),
				magicLink.verify(token),
				magicLink.verify(token),
			]);
			expect(results.filter((r) => r !== null)).toHaveLength(1);
			expect(await magicLink.verify(token)).toBeNull();
		});
	});

	describe("secondary storage", () => {
		it("counts inside a window, expires keys and deletes", async () => {
			const { auth } = await boot();
			const store = auth.secondaryStorage.for("rateLimit");
			expect((await store.incr("c", 60)).count).toBe(1);
			const second = await store.incr("c", 60);
			expect(second.count).toBe(2);
			expect(second.expiresAt).toBeGreaterThan(Date.now());
			expect(await store.get("c")).toBe("2");

			const burst = await Promise.all(Array.from({ length: 5 }, () => store.incr("burst", 60)));
			expect(Math.max(...burst.map((b) => b.count))).toBe(5);
			expect(await store.get("burst")).toBe("5");

			await store.set("short", "x", 1);
			expect(await store.get("short")).toBe("x");
			await sleep(1_300);
			expect(await store.get("short")).toBeNull();
			expect((await store.incr("c2", 1)).count).toBe(1);
			await sleep(1_300);
			expect((await store.incr("c2", 1)).count).toBe(1);

			await store.delete("c");
			expect(await store.get("c")).toBeNull();
		});
	});

	describe("admin", () => {
		it("bans and unbans a user", async () => {
			const { auth } = await boot();
			const admin = auth.admin;
			if (!admin) throw new Error("admin module missing");
			const user = await auth.user.create({ email: "ban@example.com" });
			await admin.banUser(user.id, "spam", new Date(Date.now() + HOUR));
			const banned = await auth.user.get(user.id);
			expect(Boolean(banned?.banned)).toBe(true);
			expect(banned?.banReason).toBe("spam");
			expect(banned?.banExpiresAt?.getTime()).toBeGreaterThan(Date.now());
			const listed = await admin.listUsers({ limit: 10 });
			expect(Number(listed.total)).toBeGreaterThanOrEqual(1);

			await admin.unbanUser(user.id);
			const lifted = await auth.user.get(user.id);
			expect(Boolean(lifted?.banned)).toBe(false);
			expect(lifted?.banReason ?? null).toBeNull();
		});
	});

	describe("cost attribution", () => {
		it("totals cost per agent, owner and tool", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "cost@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "spender",
				type: "autonomous",
				permissions: [],
			});
			const cost = createCostAttributionModule(auth.db);
			for (const [tool, usd] of [
				["openai:gpt-4o", 0.25],
				["openai:gpt-4o", 0.5],
				["mcp:github", 1.25],
			] as const) {
				const rec = await cost.recordCost({
					agentId: agent.id,
					tool,
					costUsd: usd,
					inputTokens: 10,
				});
				expect(rec.success).toBe(true);
			}
			const report = await cost.getAgentCost(agent.id);
			if (!report.success) throw new Error(report.error.message);
			expect(report.data.totalCostUsd).toBeCloseTo(2, 6);
			expect(typeof report.data.totalCostUsd).toBe("number");
			const gpt = report.data.byTool.find((t) => t.tool === "openai:gpt-4o");
			expect(gpt?.callCount).toBe(2);
			expect(typeof gpt?.callCount).toBe("number");
			expect(gpt?.costUsd).toBeCloseTo(0.75, 6);
			expect(report.data.byDay).toHaveLength(1);

			const owner = await cost.getOwnerCost(user.id);
			expect(owner.success && owner.data.totalCostUsd).toBeCloseTo(2, 6);
			const top = await cost.getTopAgentsByCost(5);
			expect(top.success && top.data[0]?.agentId).toBe(agent.id);
			expect((await cost.checkBudget(agent.id)).success).toBe(true);
		});

		it("stores a single event above the int4 microdollar range", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "big@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "big",
				type: "autonomous",
				permissions: [],
			});
			const cost = createCostAttributionModule(auth.db);
			expect((await cost.recordCost({ agentId: agent.id, tool: "t", costUsd: 5000 })).success).toBe(
				true,
			);
			const report = await cost.getAgentCost(agent.id);
			expect(report.success && report.data.totalCostUsd).toBeCloseTo(5000, 3);
		});
	});
}
