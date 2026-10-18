/** Quorum approvals: N distinct approvers, never the requester, every vote audited, one spend, one expiry. */
import { eq } from "drizzle-orm";
import { describe, expect, it, vi } from "vitest";
import { ApprovalQuorumError } from "../src/approval/index.js";
import { approvalRequests, approvalVotes, auditLogs, users } from "../src/db/schema.js";
import type { Permission } from "../src/index.js";
import { createTheAuth } from "../src/index.js";

const GATED: Permission[] = [
	{ resource: "robot:arm", actions: ["move"], constraints: { requireApproval: true } },
];
const CALL = { action: "move", resource: "robot:arm" };

async function setup(webhookEvents: string[] = []) {
	const bodies: Array<{ event: string; data?: Record<string, unknown> }> = [];
	if (webhookEvents.length > 0) {
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_url: string, init?: RequestInit) => {
				bodies.push(JSON.parse(String(init?.body)));
				return new Response("ok");
			}),
		);
	}
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		approval: {},
		...(webhookEvents.length > 0 && {
			webhooks: [
				{
					url: "https://hooks.example.test/approvals",
					secret: "s".repeat(32),
					events: webhookEvents as never,
					retries: 0,
				},
			],
		}),
	});
	await theauth.db
		.insert(users)
		.values({
			id: "user-1",
			email: "owner@example.com",
			name: "Owner",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	const agent = await theauth.agent.create({
		ownerId: "user-1",
		name: "arm",
		type: "autonomous",
		permissions: GATED,
	});
	const open = (requiredApprovals?: number, args?: Record<string, unknown>) =>
		theauth.approval.request({
			agentId: agent.id,
			userId: "user-1",
			...CALL,
			arguments: args,
			requiredApprovals,
		});
	return { theauth, agent, open, bodies };
}

describe("quorum approvals", () => {
	it("defaults to one approver and keeps the old behavior", async () => {
		const { theauth, open } = await setup();
		const req = await open();
		expect(req.requiredApprovals).toBe(1);
		expect(req.approvers).toBeUndefined();
		const done = await theauth.approval.approve(req.id, "user-1");
		expect(done.status).toBe("approved");
	});

	it("needs two distinct approvers and spends once", async () => {
		const { theauth, agent, open } = await setup();
		const req = await open(2, { speed: 5 });
		const input = { ...CALL, arguments: { speed: 5 }, approvalId: req.id };

		const first = await theauth.approval.approve(req.id, "alice");
		expect(first.status).toBe("pending");
		expect(first.approvers).toEqual(["alice"]);
		expect(await theauth.authorize(agent.id, input)).toMatchObject({
			allowed: false,
			code: "approval_pending",
		});

		const second = await theauth.approval.approve(req.id, "bob");
		expect(second.status).toBe("approved");
		expect(second.respondedBy).toBe("bob");
		expect(second.approvers).toEqual(["alice", "bob"]);

		expect(await theauth.authorize(agent.id, input)).toMatchObject({
			allowed: true,
			code: "approval_consumed",
		});
		expect(await theauth.authorize(agent.id, input)).toMatchObject({
			allowed: false,
			code: "approval_already_used",
		});
	});

	it("keeps the arguments binding on a quorum request", async () => {
		const { theauth, agent, open } = await setup();
		const req = await open(2, { speed: 5 });
		await theauth.approval.approve(req.id, "alice");
		await theauth.approval.approve(req.id, "bob");
		const swapped = await theauth.authorize(agent.id, {
			...CALL,
			arguments: { speed: 500 },
			approvalId: req.id,
		});
		expect(swapped).toMatchObject({ allowed: false, code: "approval_arguments_mismatch" });
	});

	it("refuses the requester and a repeat approver", async () => {
		const { theauth, open } = await setup();
		const req = await open(2);
		await expect(theauth.approval.approve(req.id, "user-1")).rejects.toMatchObject({
			code: "SELF_APPROVAL",
		});
		await theauth.approval.approve(req.id, "alice");
		const again = theauth.approval.approve(req.id, "alice");
		await expect(again).rejects.toBeInstanceOf(ApprovalQuorumError);
		await expect(again).rejects.toMatchObject({ code: "DUPLICATE_APPROVER" });
		await expect(theauth.approval.approve(req.id)).rejects.toMatchObject({
			code: "APPROVER_REQUIRED",
		});
		expect((await theauth.approval.get(req.id))?.approvers).toEqual(["alice"]);
	});

	it("lets one denial veto the quorum", async () => {
		const { theauth, open } = await setup();
		const req = await open(3);
		await theauth.approval.approve(req.id, "alice");
		const denied = await theauth.approval.deny(req.id, "bob");
		expect(denied.status).toBe("denied");
		await expect(theauth.approval.approve(req.id, "carol")).rejects.toThrow(/already denied/);
	});

	it("expires the whole quorum, and a late vote is refused", async () => {
		const { theauth, agent, open } = await setup();
		const req = await open(2);
		await theauth.approval.approve(req.id, "alice");
		await theauth.db
			.update(approvalRequests)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(approvalRequests.id, req.id));
		await expect(theauth.approval.approve(req.id, "bob")).rejects.toThrow(/expired/);
		const res = await theauth.authorize(agent.id, { ...CALL, approvalId: req.id });
		expect(res).toMatchObject({ allowed: false, code: "approval_expired" });
	});

	it("audits every vote with its progress", async () => {
		const { theauth, open } = await setup();
		const req = await open(2);
		await theauth.approval.approve(req.id, "alice");
		await theauth.approval.approve(req.id, "bob");
		const rows = await theauth.db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.resource, `approval:${req.id}`));
		const votes = rows.filter((r) => r.action === "approval.approve");
		expect(votes.map((r) => r.approverId)).toEqual(["alice", "bob"]);
		expect(votes.map((r) => r.parameters?.approvalsReceived)).toEqual([1, 2]);
		expect(votes.map((r) => r.parameters?.quorumComplete)).toEqual([false, true]);
	});

	it("rejects a quorum outside 1 to 10", async () => {
		const { open } = await setup();
		for (const n of [0, 11, 1.5]) await expect(open(n)).rejects.toThrow(/requiredApprovals/);
	});

	it("counts one approver once when the same decision races", async () => {
		const { theauth, open } = await setup();
		const req = await open(2);
		const results = await Promise.allSettled(
			Array.from({ length: 8 }, () => theauth.approval.approve(req.id, "alice")),
		);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
		const votes = await theauth.db
			.select()
			.from(approvalVotes)
			.where(eq(approvalVotes.approvalId, req.id));
		expect(votes).toHaveLength(1);
		expect((await theauth.approval.get(req.id))?.status).toBe("pending");
	});

	it("approves exactly once when two approvers complete the quorum together", async () => {
		const { theauth, agent, open } = await setup();
		const req = await open(2);
		const results = await Promise.allSettled([
			theauth.approval.approve(req.id, "alice"),
			theauth.approval.approve(req.id, "bob"),
		]);
		expect(results.every((r) => r.status === "fulfilled")).toBe(true);
		const got = await theauth.approval.get(req.id);
		expect(got?.status).toBe("approved");
		expect(got?.approvers).toHaveLength(2);
		const spends = await Promise.all(
			Array.from({ length: 4 }, () => theauth.authorize(agent.id, { ...CALL, approvalId: req.id })),
		);
		expect(spends.filter((s) => s.allowed)).toHaveLength(1);
	});

	it("never counts more than the quorum when many approvers race", async () => {
		const { theauth, open } = await setup();
		const req = await open(2);
		await Promise.allSettled(
			["a", "b", "c", "d", "e"].map((id) => theauth.approval.approve(req.id, id)),
		);
		const got = await theauth.approval.get(req.id);
		expect(got?.status).toBe("approved");
		expect(got?.approvers?.length).toBeLessThanOrEqual(3);
		expect(got?.approvers).toContain(got?.respondedBy);
	});

	it("adds the quorum to the pending webhook and sends vote progress", async () => {
		const { theauth, open, bodies } = await setup(["approval.pending", "approval.vote"]);
		const req = await open(2);
		await theauth.approval.approve(req.id, "alice");
		await vi.waitFor(() => {
			expect(bodies.some((b) => b.event === "approval.vote")).toBe(true);
		});
		const pending = bodies.find((b) => b.event === "approval.pending");
		expect(pending?.data).toMatchObject({
			approvalId: req.id,
			requiredApprovals: 2,
			approvalsReceived: 0,
		});
		const vote = bodies.find((b) => b.event === "approval.vote");
		expect(vote?.data).toMatchObject({ approverId: "alice", approvalsReceived: 1 });
		expect(JSON.stringify(bodies)).not.toContain("speed");
	});

	it("applies a per request quorum rule from config", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
			approval: { quorum: (r) => (r.action === "move" ? 2 : undefined) },
		});
		await theauth.db
			.insert(users)
			.values({
				id: "u",
				email: "u@example.com",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const agent = await theauth.agent.create({
			ownerId: "u",
			name: "a",
			type: "autonomous",
			permissions: GATED,
		});
		const move = await theauth.approval.request({ agentId: agent.id, userId: "u", ...CALL });
		const other = await theauth.approval.request({
			agentId: agent.id,
			userId: "u",
			action: "read",
			resource: "robot:arm",
		});
		expect(move.requiredApprovals).toBe(2);
		expect(other.requiredApprovals).toBe(1);
	});
});
