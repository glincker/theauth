/**
 * Guard OpenAI Agents SDK tools with theAuth.
 *
 * The script invokes the tools the way the SDK runner does when the model asks
 * for one, so it needs no model and no API key.
 */

import { createTheAuth, guardTool, replayAgent, ToolGuardError, users } from "@glinr/theauth";
import { RunContext, tool } from "@openai/agents";
import { z } from "zod";

const OWNER = "user-alice";
const HMAC_KEY = "demo-only-hmac-key";

const auth = await createTheAuth({
	database: { provider: "sqlite", url: ":memory:" },
	agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
	audit: { tamperEvident: true, hmacKey: HMAC_KEY },
	policy: {
		risk: { tiers: [{ tier: "large", when: { minAmount: 1000 }, require: "approval" }] },
	},
});

// Agents need an owner row. Human sign-in creates these for you in a real app.
auth.db
	.insert(users)
	.values({
		id: OWNER,
		email: "alice@example.com",
		name: "Alice",
		createdAt: new Date(),
		updatedAt: new Date(),
	})
	.run();

const agent = await auth.agent.create({
	ownerId: OWNER,
	name: "billing-agent",
	type: "autonomous",
	permissions: [{ resource: "tool:refund", actions: ["execute"] }],
});

// Set after a human approves. The guard hands it to policy.evaluate once.
let approvedId: string | undefined;
// Filled by onEscalate when the policy holds a call for approval.
let pendingId: string | undefined;

// Guard the plain definition first, then hand it to tool(). tool() returns an
// object that exposes invoke, not execute, so it cannot be wrapped afterwards.
const refund = tool({
	...guardTool(
		auth,
		{
			agentId: agent.id,
			risk: (args: { amount: number }) => ({ amount: args.amount, currency: "USD" }),
			approvalId: () => approvedId,
			onEscalate: (info) => {
				pendingId = info.approvalRequestId;
			},
		},
		{
			name: "refund",
			description: "Refund an invoice",
			parameters: z.object({ invoiceId: z.string(), amount: z.number() }),
			execute: async ({ invoiceId, amount }: { invoiceId: string; amount: number }) => ({
				refunded: amount,
				invoiceId,
			}),
		},
	),
	// Show a refusal to the model as text instead of rethrowing it.
	errorFunction: (_context, error) =>
		error instanceof ToolGuardError ? error.message : "The tool failed.",
});

// The SDK runner calls invoke(runContext, jsonString) when the model asks for the tool.
const call = (args: { invoiceId: string; amount: number }) =>
	refund.invoke(new RunContext(), JSON.stringify(args));

console.log("\n[1] Small refund is allowed");
console.log("   ", await call({ invoiceId: "inv_1", amount: 20 }));

console.log("\n[2] Large refund escalates, the model sees the refusal text");
console.log("   ", await call({ invoiceId: "inv_1", amount: 5000 }));
if (!pendingId) throw new Error("expected an approval request");
console.log(`    approval request ${pendingId}`);

console.log("\n[3] Human approves, the retry spends the approval once");
await auth.approval.approve(pendingId, OWNER);
approvedId = pendingId;
console.log("   ", await call({ invoiceId: "inv_1", amount: 5000 }));
console.log("   ", await call({ invoiceId: "inv_1", amount: 5000 }));

console.log("\n[4] Read the chained decision record");
// Audit rows are written in the background. Give the last two a moment to land.
await new Promise((resolve) => setTimeout(resolve, 300));
const replay = await replayAgent(auth.db, agent.id, {}, HMAC_KEY);
if (!replay.success) throw new Error("replay failed");
const seqOf = (detail: Record<string, unknown>): number =>
	typeof detail.chainSeq === "number" ? detail.chainSeq : 0;
const chained = replay.data.events
	.filter((event) => event.chained)
	.sort((a, b) => seqOf(a.detail) - seqOf(b.detail));
for (const event of chained) {
	const approver =
		typeof event.detail.approverId === "string" ? ` approver=${event.detail.approverId}` : "";
	console.log(`    #${seqOf(event.detail)} ${event.summary}${approver}`);
}
const { status, checked } = replay.data.verification;
console.log(`    chain ${status}, ${checked} rows checked`);
