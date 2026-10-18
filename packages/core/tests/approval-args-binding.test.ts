/** An approval is bound to the action and arguments the human approved. */
import { describe, expect, it } from "vitest";
import { APPROVAL_CODES, consumeApproval } from "../src/approval/consume.js";
import { makeTheAuth, newAgent } from "./hook-test-utils.js";

const GATED = [
	{ resource: "bank:transfer", actions: ["execute"], constraints: { requireApproval: true } },
];

async function setup() {
	const theauth = await makeTheAuth({});
	const agent = await newAgent(theauth, "pay", GATED);
	return { theauth, agent };
}

async function approved(
	theauth: Awaited<ReturnType<typeof makeTheAuth>>,
	agentId: string,
	args?: Record<string, unknown>,
) {
	const req = await theauth.approval.request({
		agentId,
		userId: "user-1",
		action: "execute",
		resource: "bank:transfer",
		arguments: args,
	});
	await theauth.approval.approve(req.id, "user-1");
	return req.id;
}

describe("approval bound to arguments", () => {
	it("denies spending an approval on different arguments", async () => {
		const { theauth, agent } = await setup();
		const approvalId = await approved(theauth, agent.id, { amount: 10, to: "alice" });
		const r = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "bank:transfer",
			arguments: { amount: 1000000, to: "mallory" },
			approvalId,
		});
		expect(r.allowed).toBe(false);
		expect(r.reason).toBe(APPROVAL_CODES.ARGUMENTS_MISMATCH);
	});

	it("a mismatch does not burn the approval, the approved arguments still work", async () => {
		const { theauth, agent } = await setup();
		const approvalId = await approved(theauth, agent.id, { amount: 10, to: "alice" });
		const bad = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "bank:transfer",
			arguments: { amount: 11, to: "alice" },
			approvalId,
		});
		expect(bad.allowed).toBe(false);
		const good = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "bank:transfer",
			// Key order differs on purpose: the hash is canonical.
			arguments: { to: "alice", amount: 10 },
			approvalId,
		});
		expect(good.allowed).toBe(true);
	});

	it("an approval created without arguments covers only an argument-less call", async () => {
		const { theauth, agent } = await setup();
		const approvalId = await approved(theauth, agent.id);
		const withArgs = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "bank:transfer",
			arguments: { amount: 5 },
			approvalId,
		});
		expect(withArgs.allowed).toBe(false);
		expect(withArgs.reason).toBe(APPROVAL_CODES.ARGUMENTS_MISMATCH);
		const bare = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "bank:transfer",
			approvalId,
		});
		expect(bare.allowed).toBe(true);
	});

	it("an approval for arguments cannot be spent on an argument-less call", async () => {
		const { theauth, agent } = await setup();
		const approvalId = await approved(theauth, agent.id, { amount: 10 });
		const r = await theauth.authorize(agent.id, {
			action: "execute",
			resource: "bank:transfer",
			approvalId,
		});
		expect(r.allowed).toBe(false);
		expect(r.reason).toBe(APPROVAL_CODES.ARGUMENTS_MISMATCH);
	});

	it("consumeApproval returns the distinct code directly", async () => {
		const { theauth, agent } = await setup();
		const approvalId = await approved(theauth, agent.id, { amount: 10 });
		const base = { approvalId, agentId: agent.id, action: "execute", resource: "bank:transfer" };
		expect(await consumeApproval(theauth.db, { ...base, arguments: { amount: 99 } })).toEqual({
			ok: false,
			code: APPROVAL_CODES.ARGUMENTS_MISMATCH,
		});
		const ok = await consumeApproval(theauth.db, { ...base, arguments: { amount: 10 } });
		expect(ok.ok).toBe(true);
	});

	it("a cyclic argument bag never matches", async () => {
		const { theauth, agent } = await setup();
		const approvalId = await approved(theauth, agent.id, { amount: 10 });
		const cyclic: Record<string, unknown> = { amount: 10 };
		cyclic.self = cyclic;
		const r = await consumeApproval(theauth.db, {
			approvalId,
			agentId: agent.id,
			action: "execute",
			resource: "bank:transfer",
			arguments: cyclic,
		});
		expect(r).toEqual({ ok: false, code: APPROVAL_CODES.ARGUMENTS_MISMATCH });
	});
});
