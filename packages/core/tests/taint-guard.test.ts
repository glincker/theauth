/**
 * Taint-aware tool guard: provenance labels flow into tool arguments and policy
 * restricts which labels may reach which tools. Real in-memory createTheAuth.
 */

import { eq } from "drizzle-orm";
import { describe, expect, it, vi } from "vitest";
import { guardTool, ToolApprovalRequiredError, ToolDeniedError } from "../src/agent-tools/index.js";
import { verifyAuditChain } from "../src/audit/index.js";
import { auditLogs, users } from "../src/db/schema.js";
import type { TaintConfig } from "../src/taint/index.js";
import { deriveLabels, labelsOf, ProvenanceTracker, tainted, untaint } from "../src/taint/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const KEY = "taint-test-key";

const RULES: TaintConfig = {
	rules: [
		{
			id: "mail-recipient",
			resource: "tool:send_email",
			args: { recipient: { forbid: ["untrusted_web", "tool_output:*"] } },
		},
		{
			id: "wire-no-docs",
			resource: "tool:wire",
			forbid: ["retrieved_doc"],
			effect: "deny",
		},
	],
};

async function build(taint: TaintConfig = RULES): Promise<TheAuth> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		audit: { tamperEvident: true, hmacKey: KEY },
		policy: { taint },
	});
	auth.db
		.insert(users)
		.values({
			id: "u1",
			email: "u1@t.test",
			name: "u1",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return auth;
}

async function agentFor(auth: TheAuth, resources: string[]) {
	return auth.agent.create({
		ownerId: "u1",
		name: "a",
		type: "autonomous",
		permissions: resources.map((resource) => ({ resource, actions: ["execute"] })),
	});
}

type MailArgs = { recipient: string; body: string };

function mailTool() {
	const execute = vi.fn(async (args: MailArgs) => ({ sent: args.recipient }));
	return { execute, tool: { name: "send_email", execute } };
}

async function rowsFor(auth: TheAuth, agentId: string, expected: number) {
	for (let i = 0; i < 50; i++) {
		const rows = await auth.db.select().from(auditLogs).where(eq(auditLogs.agentId, agentId));
		if (rows.length >= expected) {
			return rows.sort((a, b) => (a.chainSeq ?? 0) - (b.chainSeq ?? 0));
		}
		await new Promise((r) => setTimeout(r, 20));
	}
	throw new Error("audit rows did not arrive");
}

describe("label helpers", () => {
	it("tags objects in place and wraps primitives", () => {
		const doc = { text: "hi" };
		expect(tainted(doc, ["retrieved_doc"])).toBe(doc);
		expect(labelsOf(doc)).toEqual(["retrieved_doc"]);
		const s = tainted("a@b.com", "untrusted_web");
		expect(labelsOf(s)).toEqual(["untrusted_web"]);
		expect(untaint(s)).toBe("a@b.com");
		expect(JSON.stringify({ s })).toBe('{"s":"a@b.com"}');
		expect(labelsOf({ nested: [s] })).toEqual(["untrusted_web"]);
	});

	it("derives the union of source labels", () => {
		const a = tainted({}, ["user"]);
		const b = tainted({}, ["untrusted_web"]);
		expect(deriveLabels(a, b, ["system"]).sort()).toEqual(["system", "untrusted_web", "user"]);
	});
});

describe("taint guard", () => {
	it("escalates an untrusted-derived recipient, then an approved retry succeeds once", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:send_email"]);
		const { tool, execute } = mailTool();
		let approvalId: string | undefined;
		const guarded = guardTool(
			auth,
			{
				agentId: agent.id,
				provenance: { recipient: ["untrusted_web"] },
				approvalId: () => approvalId,
			},
			tool,
		);
		const args = { recipient: "evil@x.com", body: "report" };
		const err = await guarded.execute(args).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolApprovalRequiredError);
		const e = err as ToolApprovalRequiredError;
		expect(e.tier).toBe("taint");
		expect(e.approvalRequestId).toBeTruthy();
		expect(execute).not.toHaveBeenCalled();

		await auth.approval.approve(e.approvalRequestId as string, "human-1");
		approvalId = e.approvalRequestId;
		await expect(guarded.execute(args)).resolves.toEqual({ sent: "evil@x.com" });
		expect(execute).toHaveBeenCalledTimes(1);
		const replay = await guarded.execute(args).catch((x: unknown) => x);
		expect(replay).toBeInstanceOf(ToolDeniedError);
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("passes a user-labeled recipient", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:send_email"]);
		const { tool, execute } = mailTool();
		const guarded = guardTool(
			auth,
			{ agentId: agent.id, provenance: { recipient: ["user"] } },
			tool,
		);
		await expect(guarded.execute({ recipient: "me@x.com", body: "b" })).resolves.toEqual({
			sent: "me@x.com",
		});
		expect(execute).toHaveBeenCalledTimes(1);
	});

	it("leaves an unlabeled call unchanged and writes no provenance", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:send_email"]);
		const { tool } = mailTool();
		const guarded = guardTool(auth, { agentId: agent.id }, tool);
		await expect(guarded.execute({ recipient: "x@x.com", body: "b" })).resolves.toBeDefined();
		const [row] = await rowsFor(auth, agent.id, 1);
		expect(row?.inputProvenance).toBeNull();
	});

	it("only checks the argument the rule names", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:send_email"]);
		const { tool } = mailTool();
		const guarded = guardTool(
			auth,
			{ agentId: agent.id, provenance: { body: ["untrusted_web"], recipient: ["user"] } },
			tool,
		);
		await expect(guarded.execute({ recipient: "me@x.com", body: "page" })).resolves.toBeDefined();
	});

	it("matches wildcard labels", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:send_email"]);
		const { tool, execute } = mailTool();
		const guarded = guardTool(
			auth,
			{ agentId: agent.id, provenance: { recipient: ["tool_output:search"] } },
			tool,
		);
		await expect(guarded.execute({ recipient: "a@b.c", body: "b" })).rejects.toBeInstanceOf(
			ToolApprovalRequiredError,
		);
		expect(execute).not.toHaveBeenCalled();
	});

	it("denies when the rule effect is deny", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:wire"]);
		const execute = vi.fn(async (_a: { to: string }) => "ok");
		const guarded = guardTool(
			auth,
			{ agentId: agent.id, provenance: { to: ["retrieved_doc"] } },
			{ name: "wire", execute },
		);
		const err = await guarded.execute({ to: "acct" }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolDeniedError);
		expect((err as ToolDeniedError).code).toBe("POLICY_TAINT_VIOLATION");
		expect(execute).not.toHaveBeenCalled();
	});

	it("fails closed on require with unlabeled: violate, and skips it by default", async () => {
		const strict: TaintConfig = {
			rules: [
				{
					resource: "tool:send_email",
					args: { recipient: { require: ["user"] } },
					unlabeled: "violate",
				},
			],
		};
		const lax: TaintConfig = {
			rules: [{ resource: "tool:send_email", args: { recipient: { require: ["user"] } } }],
		};
		for (const [cfg, ok] of [
			[strict, false],
			[lax, true],
		] as const) {
			const auth = await build(cfg);
			const agent = await agentFor(auth, ["tool:send_email"]);
			const { tool } = mailTool();
			const guarded = guardTool(auth, { agentId: agent.id }, tool);
			const run = guarded.execute({ recipient: "a@b.c", body: "b" });
			if (ok) await expect(run).resolves.toBeDefined();
			else await expect(run).rejects.toBeInstanceOf(ToolApprovalRequiredError);
		}
	});

	it("propagates tool_output labels from one tool into the next", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:search", "tool:send_email"]);
		const tracker = new ProvenanceTracker();
		const search = guardTool(
			auth,
			{ agentId: agent.id, tracker, provenance: { query: ["user"] } },
			{ name: "search", execute: async (_a: { query: string }) => ({ top: "owner@evil.example" }) },
		);
		const { tool, execute } = mailTool();
		const send = guardTool(auth, { agentId: agent.id, tracker }, tool);

		const found = (await search.execute({ query: "who owns it" })) as { top: string };
		expect(tracker.labelsOf(found).sort()).toEqual(["tool_output:search", "user"]);
		// The model copies the string into a new argument object (no WeakMap tag survives).
		const err = await send.execute({ recipient: found.top, body: "hi" }).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(ToolApprovalRequiredError);
		expect(execute).not.toHaveBeenCalled();
		// Unrelated text is clean.
		await expect(send.execute({ recipient: "me@x.com", body: "hi" })).resolves.toBeDefined();
	});

	it("writes labels and the verdict to the chained record, and the chain verifies", async () => {
		const auth = await build();
		const agent = await agentFor(auth, ["tool:send_email"]);
		const { tool } = mailTool();
		const guarded = guardTool(
			auth,
			{ agentId: agent.id, provenance: { recipient: ["untrusted_web", "user"] } },
			tool,
		);
		await guarded.execute({ recipient: "e@x.com", body: "b" }).catch(() => undefined);
		const [row] = await rowsFor(auth, agent.id, 1);
		expect(row?.result).toBe("escalated");
		expect(row?.hash).toBeTruthy();
		expect(row?.inputProvenance).toEqual({
			labels: { recipient: ["untrusted_web", "user"] },
			taint: {
				verdict: "escalate",
				matches: [
					{
						rule: "mail-recipient",
						kind: "forbid",
						arg: "recipient",
						labels: ["untrusted_web"],
						effect: "escalate",
					},
				],
			},
		});
		const verified = await verifyAuditChain(auth.db, {}, KEY);
		expect(verified.success).toBe(true);
		if (verified.success) expect(verified.data.ok).toBe(true);
	});
});
