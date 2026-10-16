/**
 * A policy decision whose audit row cannot be written is counted, not lost
 * silently. The decision itself is still returned to the caller.
 */

import { describe, expect, it } from "vitest";
import { getAuditWriteFailures, setAuditWriteErrorHandler } from "../src/audit/record.js";
import { createTheAuth } from "../src/theauth.js";

const settle = () => new Promise((r) => setTimeout(r, 30));

describe("policy.evaluate audit failures", () => {
	it("counts a failed decision record and reports it to the handler", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
			policy: { policyVersion: "v-test-1" },
		});
		const seen: number[] = [];
		setAuditWriteErrorHandler(auth.db, (info) => seen.push(info.totalFailures));
		expect(getAuditWriteFailures(auth.db)).toBe(0);

		// An agent id with no owner row cannot satisfy the audit foreign key.
		const decision = await auth.policy.evaluate({
			subject: { agentId: "agent-with-no-owner" },
			action: "execute",
			resource: "tool:pay",
		});
		await settle();

		expect(decision.allowed).toBe(false);
		expect(getAuditWriteFailures(auth.db)).toBe(1);
		expect(seen).toEqual([1]);
	});
});
