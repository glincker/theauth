import { describe, expect, it } from "vitest";
import { uniqueEmail } from "./claim-races.js";
import type { StoreContractTarget } from "./types.js";

type Make = () => Promise<StoreContractTarget>;

/**
 * Races on the paths that flip an approval request: the admin API decision and the quorum
 * completing vote. Each has its own conditional UPDATE, so a read-then-write version of either
 * lets a deny and an approve both succeed on one request.
 */
export function defineApprovalRaces(make: Make, parallel: number): void {
	async function openRequest(t: StoreContractTarget, tag: string, requiredApprovals?: number) {
		const { approval, agent, user } = t.auth;
		const owner = await user.create({ email: uniqueEmail(tag) });
		const a = await agent.create({
			ownerId: owner.id,
			name: `contract-${tag}`,
			type: "autonomous",
			permissions: [
				{ resource: "mcp:pay:*", actions: ["execute"], constraints: { requireApproval: true } },
			],
		});
		return approval.request({
			agentId: a.id,
			userId: owner.id,
			action: "execute",
			resource: "mcp:pay:refund",
			...(requiredApprovals !== undefined && { requiredApprovals }),
		});
	}

	describe("approval flip races", () => {
		it("lets one parallel admin approve or deny decide an approval", async () => {
			const t = await make();
			try {
				const admin = t.adminDecisions;
				if (!admin) return; // optional capability, the admin API plugin may be absent
				const req = await openRequest(t, "adm");
				const accepted = await Promise.all(
					Array.from({ length: parallel }, (_, i) =>
						admin.decide(req.id, `admin-${i}`, i % 2 === 0 ? "approved" : "denied"),
					),
				);
				expect(accepted.filter(Boolean)).toHaveLength(1);
				expect(["approved", "denied"]).toContain((await t.auth.approval.get(req.id))?.status);
			} finally {
				await t.close();
			}
		});

		it("lets a completing quorum vote and a deny race, with one winner", async () => {
			const t = await make();
			try {
				const { approval } = t.auth;
				const req = await openRequest(t, "quorum", 2);
				await approval.approve(req.id, "voter-0");
				const calls = [
					() => approval.approve(req.id, "voter-1"),
					...Array.from(
						{ length: parallel - 1 },
						(_, i) => () => approval.deny(req.id, `denier-${i}`),
					),
				];
				const settled = await Promise.allSettled(calls.map((c) => c()));
				const status = (await approval.get(req.id))?.status;
				// The flip is one conditional UPDATE: the completing vote and a deny cannot both land.
				expect(settled.filter((s) => s.status === "fulfilled")).toHaveLength(1);
				const approveWon = settled[0]?.status === "fulfilled";
				expect(status).toBe(approveWon ? "approved" : "denied");
			} finally {
				await t.close();
			}
		});

		it("completes a quorum once when many distinct approvers vote together", async () => {
			const t = await make();
			try {
				const { approval } = t.auth;
				const req = await openRequest(t, "many", 2);
				const settled = await Promise.allSettled(
					Array.from({ length: parallel }, (_, i) => approval.approve(req.id, `voter-${i}`)),
				);
				expect((await approval.get(req.id))?.status).toBe("approved");
				// The caller whose UPDATE flips the row completes it, and a loser still reports approved when
				// it is among the first two counted votes: at most three. A flip that is not one conditional
				// UPDATE lets every voter that read "pending" complete it.
				const completed = settled.filter(
					(s) => s.status === "fulfilled" && s.value.status === "approved",
				);
				expect(completed.length).toBeGreaterThanOrEqual(1);
				expect(completed.length).toBeLessThanOrEqual(3);
			} finally {
				await t.close();
			}
		});
	});
}
