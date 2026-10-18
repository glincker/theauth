import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { approvalRequests, auditLogs } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTestTheAuth } from "./helpers.js";

const RESOURCE = "mcp:payments:refund";

describe("approvalId consumption", () => {
	let theauth: TheAuth;
	let agentId: string;
	let otherAgentId: string;

	async function approved(overrides?: { action?: string; resource?: string; agent?: string }) {
		const req = await theauth.approval.request({
			agentId: overrides?.agent ?? agentId,
			userId: "user-1",
			action: overrides?.action ?? "execute",
			resource: overrides?.resource ?? RESOURCE,
		});
		await theauth.approval.approve(req.id, "human-1");
		return req.id;
	}

	beforeEach(async () => {
		theauth = await createTestTheAuth();
		const perms = [
			{
				resource: "mcp:payments:*",
				actions: ["execute"],
				constraints: { requireApproval: true },
			},
		];
		agentId = (
			await theauth.agent.create({
				ownerId: "user-1",
				name: "a",
				type: "autonomous",
				permissions: perms,
			})
		).id;
		otherAgentId = (
			await theauth.agent.create({
				ownerId: "user-1",
				name: "b",
				type: "autonomous",
				permissions: perms,
			})
		).id;
	});

	describe("authorize", () => {
		const call = (
			approvalId?: string,
			over?: { action?: string; resource?: string; agent?: string },
		) =>
			theauth.authorize(over?.agent ?? agentId, {
				action: over?.action ?? "execute",
				resource: over?.resource ?? RESOURCE,
				approvalId,
			});

		it("still holds the action without an approvalId", async () => {
			const r = await call();
			expect(r.allowed).toBe(false);
			expect(r.reason).toContain("human approval");
		});

		it("allows once with an approved request and denies the replay", async () => {
			const id = await approved();
			expect((await call(id)).allowed).toBe(true);
			const replay = await call(id);
			expect(replay.allowed).toBe(false);
			expect(replay.reason).toBe("APPROVAL_ALREADY_USED");
			const row = await theauth.approval.get(id);
			expect(row?.status).toBe("approved");
		});

		it("denies an unknown id", async () => {
			expect((await call("apr_missing")).reason).toBe("APPROVAL_NOT_FOUND");
		});

		it("denies a request for another resource", async () => {
			const id = await approved({ resource: "mcp:payments:other" });
			expect((await call(id)).reason).toBe("APPROVAL_MISMATCH");
		});

		it("denies a request for another action", async () => {
			const id = await approved({ action: "read" });
			expect((await call(id)).reason).toBe("APPROVAL_MISMATCH");
		});

		it("denies a request that belongs to another agent", async () => {
			const id = await approved({ agent: otherAgentId });
			expect((await call(id)).reason).toBe("APPROVAL_MISMATCH");
		});

		it("denies pending and denied requests", async () => {
			const pending = await theauth.approval.request({
				agentId,
				userId: "user-1",
				action: "execute",
				resource: RESOURCE,
			});
			expect((await call(pending.id)).reason).toBe("APPROVAL_PENDING");
			await theauth.approval.deny(pending.id, "human-1");
			expect((await call(pending.id)).reason).toBe("APPROVAL_DENIED");
		});

		it("denies an expired approval", async () => {
			const id = await approved();
			await theauth.db
				.update(approvalRequests)
				.set({ expiresAt: new Date(Date.now() - 60_000) })
				.where(eq(approvalRequests.id, id));
			expect((await call(id)).reason).toBe("APPROVAL_EXPIRED");
		});

		it("lets exactly one of two concurrent calls through", async () => {
			const id = await approved();
			const results = await Promise.all([call(id), call(id), call(id), call(id)]);
			expect(results.filter((r) => r.allowed)).toHaveLength(1);
			for (const r of results.filter((x) => !x.allowed)) {
				expect(r.reason).toBe("APPROVAL_ALREADY_USED");
			}
		});

		it("records approver_id and the approval id on the audit row", async () => {
			const id = await approved();
			const r = await call(id);
			const rows = await theauth.db.select().from(auditLogs).where(eq(auditLogs.id, r.auditId));
			expect(rows[0]?.approverId).toBe("human-1");
			expect(rows[0]?.parameters).toMatchObject({ approvalId: id });
			expect(rows[0]?.result).toBe("allowed");
		});
	});

	describe("policy.evaluate", () => {
		const evalWith = (
			approvalId?: string,
			over?: { action?: string; resource?: string; agent?: string },
		) =>
			theauth.policy.evaluate({
				subject: { agentId: over?.agent ?? agentId, ownerId: "user-1" },
				action: over?.action ?? "execute",
				resource: over?.resource ?? RESOURCE,
				approvalId,
			});

		it("escalates without an approvalId", async () => {
			expect((await evalWith()).decision).toBe("escalate");
		});

		it("allows once and denies the replay", async () => {
			const id = await approved();
			const first = await evalWith(id);
			expect(first.decision).toBe("allow");
			const replay = await evalWith(id);
			expect(replay.decision).toBe("deny");
			expect(replay.reason).toBe("APPROVAL_ALREADY_USED");
		});

		it("denies a mismatched request", async () => {
			const id = await approved({ agent: otherAgentId });
			const d = await evalWith(id);
			expect(d.decision).toBe("deny");
			expect(d.reason).toBe("APPROVAL_MISMATCH");
		});

		it("records approver_id and the approval id on the audit row", async () => {
			const id = await approved();
			const d = await evalWith(id);
			await new Promise((r) => setTimeout(r, 50));
			const rows = await theauth.db
				.select()
				.from(auditLogs)
				.where(eq(auditLogs.id, d.auditId ?? ""));
			expect(rows[0]?.approverId).toBe("human-1");
			expect(rows[0]?.parameters).toMatchObject({ approvalId: id });
			expect(rows[0]?.result).toBe("allowed");
		});

		it("lets exactly one concurrent evaluate through", async () => {
			const id = await approved();
			const results = await Promise.all([evalWith(id), evalWith(id), evalWith(id)]);
			expect(results.filter((r) => r.decision === "allow")).toHaveLength(1);
		});
	});
});
