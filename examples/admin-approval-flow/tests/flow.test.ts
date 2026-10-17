import { describe, expect, it } from "vitest";
import { runAdminApprovalFlow } from "../src/flow.js";

describe("admin approval flow", () => {
	it("gates a delegation revoke behind a second admin, once", async () => {
		const out = await runAdminApprovalFlow({ step: () => undefined, note: () => undefined });

		// 2. pending, nothing changed yet
		expect(out.first.status).toBe("pending");
		expect(out.first.approvalId).not.toBe("");
		expect(out.delegationAfterFirst).toBe("active");

		// 3. four-eyes: the requester cannot approve
		expect(out.selfApproval).toEqual({ status: 403, code: "SELF_APPROVAL" });

		// 4. the other admin sees and approves it
		expect(out.pendingIds).toContain(out.first.approvalId);
		expect(out.approveStatus).toBe(200);

		// 5. executed with the approval, delegation revoked
		expect(out.second.status).toBe("executed");
		expect(out.delegationAfterSecond).toBe("revoked");

		// 6. single use
		expect(out.replay.isError).toBe(true);
		expect(out.replay.text).toContain("APPROVAL_ALREADY_USED");

		// 7. audit trail
		const mcp = out.audit.filter((e) => e.action === "admin_mcp.revoke_delegation");
		expect(mcp.map((e) => e.mcpResult)).toEqual(
			expect.arrayContaining(["requested", "pending", "executed", "denied"]),
		);
		const approve = out.audit.find((e) => e.action === "admin_api.approval.approve");
		expect(approve?.userId).toBe("user-bob");
		expect(out.audit.some((e) => e.action === "admin_api.delegation.revoke")).toBe(true);
	});
});
