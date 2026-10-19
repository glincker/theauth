/** Approvals as a first-class flow: request, decide, spend once, distinct codes, events, webhook. */
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { approvalRequests, auditLogs, users } from "../src/db/schema.js";
import type {
	ApprovalRequest,
	DecisionEvent,
	Permission,
	PolicyEngineConfig,
} from "../src/index.js";
import { createTheAuth } from "../src/index.js";

const GATED: Permission[] = [
	{ resource: "bank:transfer", actions: ["execute"], constraints: { requireApproval: true } },
];
const CALL = { action: "execute", resource: "bank:transfer" };

async function setup() {
	const events: DecisionEvent[] = [];
	const needed: ApprovalRequest[] = [];
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		observability: { onDecision: (e) => events.push(e) },
		approval: { onApprovalNeeded: async (r) => void needed.push(r) },
		webhooks: [
			{
				url: "https://hooks.example.test/approvals",
				secret: "s".repeat(32),
				events: ["approval.pending"],
				retries: 0,
			},
		],
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
		name: "payer",
		type: "autonomous",
		permissions: GATED,
	});
	const open = (args?: Record<string, unknown>) =>
		theauth.approval.request({
			agentId: agent.id,
			userId: "user-1",
			...CALL,
			arguments: args,
		});
	return { theauth, agent, events, needed, open };
}

afterEach(() => vi.unstubAllGlobals());

describe("approval lifecycle", () => {
	it("runs request, approve, spend once, replay", async () => {
		const { theauth, agent, open } = await setup();
		const req = await open({ amount: 10 });
		const input = { ...CALL, arguments: { amount: 10 }, approvalId: req.id };

		const pending = await theauth.authorize(agent.id, input);
		expect(pending).toMatchObject({ allowed: false, code: "approval_pending" });

		await theauth.approval.decide(req.id, { decision: "approve", decidedBy: "user-1" });
		const spent = await theauth.authorize(agent.id, input);
		expect(spent).toMatchObject({ allowed: true, code: "approval_consumed" });

		const replay = await theauth.authorize(agent.id, input);
		expect(replay).toMatchObject({ allowed: false, code: "approval_already_used" });
	});

	it("returns a distinct code for each failure", async () => {
		const { theauth, agent, open } = await setup();
		const code = async (approvalId: string, args?: Record<string, unknown>) =>
			(await theauth.authorize(agent.id, { ...CALL, arguments: args, approvalId })).code;

		expect(await code("apr_missing")).toBe("approval_not_found");

		const denied = await open();
		await theauth.approval.deny(denied.id, "user-1");
		expect(await code(denied.id)).toBe("approval_denied");

		const expired = await open();
		await theauth.approval.approve(expired.id, "user-1");
		await theauth.db
			.update(approvalRequests)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(approvalRequests.id, expired.id));
		expect(await code(expired.id)).toBe("approval_expired");

		const bound = await open({ amount: 10 });
		await theauth.approval.approve(bound.id, "user-1");
		expect(await code(bound.id, { amount: 99 })).toBe("approval_arguments_mismatch");
		expect(await code(bound.id, { amount: 10, __proto_note: "x" })).toBe(
			"approval_arguments_mismatch",
		);

		const other = await theauth.agent.create({
			ownerId: "user-1",
			name: "other",
			type: "autonomous",
			permissions: GATED,
		});
		const wrongAgent = await theauth.authorize(other.id, {
			...CALL,
			arguments: { amount: 10 },
			approvalId: bound.id,
		});
		expect(wrongAgent.code).toBe("approval_mismatch");
	});

	it("strips reserved keys before binding", async () => {
		const { theauth, agent, open } = await setup();
		const req = await open({ amount: 5 });
		await theauth.approval.approve(req.id, "user-1");
		const r = await theauth.authorize(agent.id, {
			...CALL,
			arguments: { amount: 5, approvalId: "apr_other" },
			approvalId: req.id,
		});
		expect(r.allowed).toBe(true);
	});

	it("lists pending requests for an owner and writes audit rows", async () => {
		const { theauth, agent, open } = await setup();
		const a = await open();
		const b = await open();
		await theauth.approval.approve(a.id, "user-1");
		const mine = await theauth.approval.listPending("user-1");
		expect(mine.map((r) => r.id)).toEqual([b.id]);
		expect(await theauth.approval.listPending("user-2")).toEqual([]);

		await theauth.db
			.update(approvalRequests)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(approvalRequests.id, b.id));
		expect(await theauth.approval.listPending("user-1")).toEqual([]);
		await expect(theauth.approval.approve(b.id, "user-1")).rejects.toThrow(/expired/);
		expect((await theauth.approval.get(b.id))?.status).toBe("expired");

		const rows = await theauth.db
			.select({ action: auditLogs.action })
			.from(auditLogs)
			.where(eq(auditLogs.agentId, agent.id));
		const actions = rows.map((r) => r.action);
		expect(actions).toEqual(
			expect.arrayContaining(["approval.request", "approval.approve", "approval.expire"]),
		);
	});

	it("emits decision events for each lifecycle step", async () => {
		const { theauth, events, open } = await setup();
		const a = await open();
		await theauth.approval.approve(a.id, "user-1");
		const b = await open();
		await theauth.approval.deny(b.id, "user-1");
		// Decision events fire off the request path, so wait until all four have arrived.
		await vi.waitFor(() => expect(events.filter((e) => e.source === "approval")).toHaveLength(4), {
			timeout: 3000,
		});
		const approval = events.filter((e) => e.source === "approval");
		expect(approval.map((e) => e.code)).toEqual([
			"approval_pending",
			"approval_granted",
			"approval_pending",
			"approval_denied",
		]);
		expect(approval[1]).toMatchObject({ decision: "allow", allowed: true, ownerId: "user-1" });
	});

	it("sends approval.pending to webhooks without raw arguments", async () => {
		const fetchMock = vi.fn(async () => new Response("ok", { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);
		const { needed, open } = await setup();
		const req = await open({ amount: 123456 });
		expect(needed.map((r) => r.id)).toEqual([req.id]);
		const sent = () =>
			(fetchMock.mock.calls as unknown as Array<[string, { body: string }]>)
				.map((c) => JSON.parse(c[1].body ?? "{}"))
				.filter((b) => b.event === "approval.pending" && b.data?.approvalId === req.id);
		// Delivery runs off the request path, so wait for it instead of guessing a delay.
		await vi.waitFor(() => expect(sent()).toHaveLength(1), { timeout: 3000 });
		const body = sent()[0];
		expect(body.event).toBe("approval.pending");
		expect(body.data).toMatchObject({ approvalId: req.id, userId: "user-1" });
		expect(body.data.argumentsHash).toMatch(/^[0-9a-f]{64}$/);
		expect(JSON.stringify(body)).not.toContain("123456");
	});

	it("exports the config types from the package root", () => {
		const cfg: PolicyEngineConfig = {};
		expect(cfg).toEqual({});
	});
});
