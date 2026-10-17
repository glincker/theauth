/**
 * Guards Vercel AI SDK tools with theAuth. Calls the guarded tools directly, so no model or API key is needed.
 */
import {
	createTheAuth,
	guardTool,
	replayAgent,
	ToolApprovalRequiredError,
	ToolDeniedError,
	users,
} from "@glinr/theauth";
import { tool } from "ai";
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
	permissions: [
		{ resource: "tool:lookupInvoice", actions: ["execute"] },
		{ resource: "tool:refund", actions: ["execute"] },
	],
});

// Set after a human approves. The guard hands it to policy.evaluate once.
let approvedId: string | undefined;

// One guardTool per tool keeps each tool's argument types exact. guardTools
// (record form) also works, but the record's args type becomes a union.
const lookupInvoice = guardTool(
	auth,
	{ agentId: agent.id },
	{
		name: "lookupInvoice",
		...tool({
			description: "Look up an invoice by id",
			inputSchema: z.object({ invoiceId: z.string() }),
			execute: ({ invoiceId }) => Promise.resolve({ invoiceId, total: 480 }),
		}),
	},
);

const refund = guardTool(
	auth,
	{
		agentId: agent.id,
		risk: (args: { amount: number }) => ({ amount: args.amount, currency: "USD" }),
		approvalId: () => approvedId,
	},
	{
		name: "refund",
		...tool({
			description: "Refund an invoice",
			inputSchema: z.object({ invoiceId: z.string(), amount: z.number() }),
			execute: ({ invoiceId, amount }) => Promise.resolve({ refunded: amount, invoiceId }),
		}),
	},
);

// Pass { lookupInvoice, refund } as `tools` to generateText or streamText.

// The Vercel AI SDK passes (input, options) to execute.
const options = { toolCallId: "call_1", messages: [], context: {} };

console.log("\n[1] Small call is allowed");
console.log("   ", await lookupInvoice.execute?.({ invoiceId: "inv_1" }, options));

console.log("\n[2] Large refund escalates");
let requestId: string | undefined;
try {
	await refund.execute?.({ invoiceId: "inv_1", amount: 5000 }, options);
} catch (error) {
	if (error instanceof ToolApprovalRequiredError) {
		requestId = error.approvalRequestId;
		console.log(`    held, tier=${error.tier}, approval request=${requestId}`);
	} else {
		throw error;
	}
}
if (!requestId) throw new Error("expected an approval request");

console.log("\n[3] Human approves, the retry spends the approval once");
await auth.approval.approve(requestId, OWNER);
approvedId = requestId;
console.log("   ", await refund.execute?.({ invoiceId: "inv_1", amount: 5000 }, options));
try {
	await refund.execute?.({ invoiceId: "inv_1", amount: 5000 }, options);
} catch (error) {
	if (error instanceof ToolDeniedError) console.log(`    second use denied: ${error.code}`);
	else throw error;
}

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
