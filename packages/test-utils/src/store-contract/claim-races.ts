import { describe, expect, it } from "vitest";
import type { StoreContractTarget } from "./types.js";

type Make = () => Promise<StoreContractTarget>;

let counter = 0;
/** Unique per call, so suites can share one database without reading each other's rows. */
export function uniqueEmail(tag: string): string {
	counter += 1;
	return `${tag}-${Date.now().toString(36)}-${counter}-${Math.random().toString(36).slice(2, 8)}@contract.test`;
}

/**
 * Single-use state: `parallel` callers hit one row, exactly one may win. Mirrors the Go suite's RunClaimRaces.
 */
export function defineClaimRaces(make: Make, parallel: number): void {
	describe("claim races", () => {
		it("redeems a magic link once", async () => {
			const t = await make();
			try {
				const ml = t.auth.magicLink;
				if (!ml) throw new Error("target has no magicLink module");
				const email = uniqueEmail("ml");
				await ml.sendLink(email);
				const token = t.mail.magicTokens.at(-1) ?? "";
				const results = await Promise.all(Array.from({ length: parallel }, () => ml.verify(token)));
				expect(results.filter((r) => r !== null)).toHaveLength(1);
				expect(await ml.verify(token)).toBeNull();
			} finally {
				await t.close();
			}
		});

		it("accepts an email OTP once", async () => {
			const t = await make();
			try {
				const otp = t.auth.emailOtp;
				if (!otp) throw new Error("target has no emailOtp module");
				const email = uniqueEmail("otp");
				await otp.sendCode(email);
				const code = t.mail.otpCodes.at(-1) ?? "";
				const results = await Promise.all(
					Array.from({ length: parallel }, () => otp.verifyCode(email, code)),
				);
				expect(results.filter((r) => r !== null)).toHaveLength(1);
				expect(await otp.verifyCode(email, code)).toBeNull();
			} finally {
				await t.close();
			}
		});

		it("counts every parallel wrong OTP guess, so the attempt limit holds", async () => {
			const t = await make();
			try {
				const otp = t.auth.emailOtp;
				if (!otp) throw new Error("target has no emailOtp module");
				const email = uniqueEmail("guess");
				await otp.sendCode(email);
				const code = t.mail.otpCodes.at(-1) ?? "";
				const wrong = code === "000000" ? "111111" : "000000";
				await Promise.all(Array.from({ length: parallel + 6 }, () => otp.verifyCode(email, wrong)));
				// The default limit is below the guess count, so the right code is refused once the guesses are spent.
				expect(await otp.verifyCode(email, code)).toBeNull();
			} finally {
				await t.close();
			}
		});

		it("lets one parallel approve or deny decide an approval", async () => {
			const t = await make();
			try {
				const { approval, agent, user } = t.auth;
				const owner = await user.create({ email: uniqueEmail("apr") });
				const a = await agent.create({
					ownerId: owner.id,
					name: "contract-decide",
					type: "autonomous",
					permissions: [
						{ resource: "mcp:pay:*", actions: ["execute"], constraints: { requireApproval: true } },
					],
				});
				const req = await approval.request({
					agentId: a.id,
					userId: owner.id,
					action: "execute",
					resource: "mcp:pay:refund",
				});
				const settled = await Promise.allSettled(
					Array.from({ length: parallel }, (_, i) =>
						i % 2 === 0 ? approval.approve(req.id, `h${i}`) : approval.deny(req.id, `h${i}`),
					),
				);
				expect(settled.filter((s) => s.status === "fulfilled")).toHaveLength(1);
				expect(["approved", "denied"]).toContain((await approval.get(req.id))?.status);
			} finally {
				await t.close();
			}
		});

		it("consumes an approved approval once across parallel authorize calls", async () => {
			const t = await make();
			try {
				const { approval, agent, user, authorize } = t.auth;
				const owner = await user.create({ email: uniqueEmail("use") });
				const a = await agent.create({
					ownerId: owner.id,
					name: "contract-consume",
					type: "autonomous",
					permissions: [
						{ resource: "mcp:pay:*", actions: ["execute"], constraints: { requireApproval: true } },
					],
				});
				const req = await approval.request({
					agentId: a.id,
					userId: owner.id,
					action: "execute",
					resource: "mcp:pay:refund",
				});
				await approval.approve(req.id, "human-1");
				const results = await Promise.all(
					Array.from({ length: parallel }, () =>
						authorize(a.id, { action: "execute", resource: "mcp:pay:refund", approvalId: req.id }),
					),
				);
				expect(results.filter((r) => r.allowed)).toHaveLength(1);
			} finally {
				await t.close();
			}
		});

		it("rotates a refresh token once and treats every loser as replay", async () => {
			const t = await make();
			try {
				const fam = t.tokenFamilies;
				if (!fam) return; // optional capability, not every target exposes it
				const owner = await t.auth.user.create({ email: uniqueEmail("rt") });
				const { ok, others } = await fam.rotateOnce(owner.id, parallel);
				expect(ok).toBe(1);
				for (const s of others) expect(["reuse", "revoked"]).toContain(s);
			} finally {
				await t.close();
			}
		});
	});
}
