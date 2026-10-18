/**
 * Step-up on approvals (RFC 9470): a request can demand a fresh passkey or TOTP from the approver.
 * Covers the approval module, the admin API decision route, the risk tier that opens such a request,
 * and that an ordinary approval cannot stand in for a step-up one.
 */

import { describe, expect, it } from "vitest";
import { adminApi } from "../src/admin-api/index.js";
import { approverEvidence, createApprovalModule } from "../src/approval/approval.js";
import { consumeApproval } from "../src/approval/consume.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	approvalRequests,
	auditLogs,
	permissions as permissionsTable,
	users,
} from "../src/db/schema.js";
import type { EndpointContext, PluginEndpoint } from "../src/plugin/types.js";
import { createPolicyEngine } from "../src/policy/engine.js";
import type { AuthAssertion } from "../src/session/auth-context.js";
import { ACR, resolveAuthContext, StepUpRequiredError } from "../src/session/auth-context.js";

const NOW_S = () => Math.floor(Date.now() / 1000);
const passkeyNow: AuthAssertion = resolveAuthContext([{ method: "passkey", at: NOW_S() }], NOW_S());
const totpNow: AuthAssertion = resolveAuthContext(
	[
		{ method: "password", at: NOW_S() - 7200 },
		{ method: "totp", at: NOW_S() - 10 },
	],
	NOW_S(),
);
const passwordOnly: AuthAssertion = resolveAuthContext(
	[{ method: "password", at: NOW_S() - 5 }],
	NOW_S(),
);
const passkeyOld: AuthAssertion = resolveAuthContext(
	[
		{ method: "passkey", at: NOW_S() - 7200 },
		{ method: "password", at: NOW_S() - 5 },
	],
	NOW_S(),
);

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db.insert(users).values([
		{ id: "u1", email: "u1@test", createdAt: now, updatedAt: now },
		{ id: "admin1", email: "admin1@test", createdAt: now, updatedAt: now },
		{ id: "admin2", email: "admin2@test", createdAt: now, updatedAt: now },
	]);
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		tokenHash: "h",
		tokenPrefix: "pref0000",
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(permissionsTable).values({
		id: "p1",
		agentId: "a1",
		resource: "tool:pay",
		actions: ["execute"],
		constraints: null,
		relation: null,
		createdAt: now,
	});
	return db;
}

const base = { agentId: "a1", userId: "u1", action: "execute", resource: "tool:pay" };

describe("approval module step-up", () => {
	it("stores the rule on the request and exposes it", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request({
			...base,
			stepUp: { acr: ACR.phishingResistant, maxAge: 120 },
		});
		expect(req.requiredAcr).toBe(ACR.phishingResistant);
		expect(req.maxAuthAge).toBe(120);
		const stored = await approval.get(req.id);
		expect(stored?.requiredAcr).toBe(ACR.phishingResistant);
		expect(stored?.maxAuthAge).toBe(120);
	});

	it("does not change requests that carry no rule", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request(base);
		expect(req.requiredAcr).toBeUndefined();
		const decided = await approval.approve(req.id, "admin1");
		expect(decided.status).toBe("approved");
	});

	it("refuses to approve without an assertion, then with a weak one, then accepts a passkey", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request({
			...base,
			stepUp: { acr: ACR.phishingResistant, maxAge: 300 },
		});
		await expect(approval.approve(req.id, "admin1")).rejects.toBeInstanceOf(StepUpRequiredError);
		await expect(approval.approve(req.id, "admin1", passwordOnly)).rejects.toBeInstanceOf(
			StepUpRequiredError,
		);
		await expect(approval.approve(req.id, "admin1", totpNow)).rejects.toBeInstanceOf(
			StepUpRequiredError,
		);
		expect((await approval.get(req.id))?.status).toBe("pending");
		const decided = await approval.approve(req.id, "admin1", passkeyNow);
		expect(decided.status).toBe("approved");
	});

	it("accepts a fresh TOTP over an old password for a multi factor rule", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request({ ...base, stepUp: { acr: ACR.mfa, maxAge: 300 } });
		expect((await approval.approve(req.id, "admin1", totpNow)).status).toBe("approved");
	});

	it("refuses an old passkey even when a password was typed a moment ago", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request({
			...base,
			stepUp: { acr: ACR.phishingResistant, maxAge: 300 },
		});
		await expect(approval.approve(req.id, "admin1", passkeyOld)).rejects.toBeInstanceOf(
			StepUpRequiredError,
		);
	});

	it("never asks for step-up to deny", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request({ ...base, stepUp: { acr: ACR.phishingResistant } });
		const denied = await approval.decide(req.id, { decision: "deny", decidedBy: "admin1" });
		expect(denied.status).toBe("denied");
	});

	it("applies the module default and a per request callback in that order of precedence", async () => {
		const db = await setup();
		const approval = createApprovalModule(
			{
				requireAcr: ACR.mfa,
				maxAuthAge: 600,
				stepUp: (r) => (r.action === "delete" ? { acr: ACR.phishingResistant } : undefined),
			},
			db,
		);
		const plain = await approval.request(base);
		expect([plain.requiredAcr, plain.maxAuthAge]).toEqual([ACR.mfa, 600]);
		const risky = await approval.request({ ...base, action: "delete" });
		expect(risky.requiredAcr).toBe(ACR.phishingResistant);
		expect(risky.maxAuthAge).toBeUndefined();
		const explicit = await approval.request({ ...base, stepUp: { acr: ACR.singleFactor } });
		expect(explicit.requiredAcr).toBe(ACR.singleFactor);
	});

	it("rejects a rule naming an unknown acr or a negative age when the request opens", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		await expect(approval.request({ ...base, stepUp: { acr: "urn:nope" } })).rejects.toThrow(
			/Unknown acr/,
		);
		await expect(approval.request({ ...base, stepUp: { maxAge: -1 } })).rejects.toThrow(/maxAge/);
	});

	it("records how the approver proved themselves in the audit row", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request({ ...base, stepUp: { acr: ACR.mfa } });
		await approval.approve(req.id, "admin1", totpNow);
		const rows = await db.select().from(auditLogs);
		const row = rows.find((r) => r.action === "approval.approve");
		expect(row?.parameters).toMatchObject({ approverAcr: ACR.mfa });
		expect(approverEvidence(totpNow)).toMatchObject({ approverAmr: ["mfa", "otp", "pwd"] });
	});

	it("lets only one of two concurrent decisions win", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const req = await approval.request(base);
		const results = await Promise.allSettled([
			approval.approve(req.id, "admin1"),
			approval.deny(req.id, "admin2"),
		]);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
		expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
	});
});

describe("consumeApproval with a step-up floor", () => {
	it("refuses an ordinary approval where the policy demands step-up", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const ordinary = await approval.request(base);
		await approval.approve(ordinary.id, "admin1");
		const spent = await consumeApproval(db, {
			approvalId: ordinary.id,
			agentId: "a1",
			action: base.action,
			resource: base.resource,
			minStepUp: { acr: ACR.mfa, maxAge: 300 },
		});
		expect(spent).toEqual({ ok: false, code: "APPROVAL_STEP_UP_INSUFFICIENT" });
	});

	it("refuses a weaker rule and a longer allowed age, accepts an equal or stronger one", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const make = async (stepUp: { acr?: string; maxAge?: number }) => {
			const r = await approval.request({ ...base, stepUp });
			await approval.approve(r.id, "admin1", passkeyNow);
			return r.id;
		};
		const input = (approvalId: string) => ({
			approvalId,
			agentId: "a1",
			action: base.action,
			resource: base.resource,
			minStepUp: { acr: ACR.mfa, maxAge: 300 },
		});
		expect(
			(await consumeApproval(db, input(await make({ acr: ACR.singleFactor, maxAge: 300 })))).ok,
		).toBe(false);
		expect((await consumeApproval(db, input(await make({ acr: ACR.mfa, maxAge: 900 })))).ok).toBe(
			false,
		);
		expect((await consumeApproval(db, input(await make({ acr: ACR.mfa })))).ok).toBe(false);
		expect((await consumeApproval(db, input(await make({ acr: ACR.mfa, maxAge: 300 })))).ok).toBe(
			true,
		);
		expect(
			(await consumeApproval(db, input(await make({ acr: ACR.phishingResistant, maxAge: 60 })))).ok,
		).toBe(true);
	});
});

describe("risk tier step_up", () => {
	const risk = {
		tiers: [
			{ tier: "high", when: { minAmount: 10000 }, require: "step_up" as const },
			{
				tier: "wire",
				when: { minAmount: 500 },
				require: "approval" as const,
				stepUp: { acr: ACR.phishingResistant, maxAge: 120 },
			},
		],
	};
	const input = (amount: number, approvalId?: string) => ({
		subject: { agentId: "a1" },
		action: "execute",
		resource: "tool:pay",
		context: { risk: { amount } },
		...(approvalId && { approvalId }),
	});

	it("opens the approval with the default multi factor rule for a step_up tier", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const engine = createPolicyEngine({ db, approval, config: { risk } });
		const d = await engine.evaluate(input(20000), { openApproval: true });
		expect(d.escalation?.requirement).toBe("step_up");
		expect(d.escalation?.stepUp).toEqual({ acr: ACR.mfa, maxAge: 300 });
		const req = await approval.get(d.escalation?.approvalRequestId as string);
		expect(req?.requiredAcr).toBe(ACR.mfa);
		expect(req?.maxAuthAge).toBe(300);
	});

	it("carries an explicit rule from the tier onto the request", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const engine = createPolicyEngine({ db, approval, config: { risk } });
		const d = await engine.evaluate(input(900), { openApproval: true });
		const req = await approval.get(d.escalation?.approvalRequestId as string);
		expect(req?.requiredAcr).toBe(ACR.phishingResistant);
		expect(req?.maxAuthAge).toBe(120);
	});

	it("lets a step_up tier through once the right approval is spent", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const engine = createPolicyEngine({ db, approval, config: { risk } });
		const d = await engine.evaluate(input(20000), { openApproval: true });
		const id = d.escalation?.approvalRequestId as string;
		const args = { amount: 20000 };
		expect((await engine.evaluate(input(20000, id))).code).toBe("approval_pending");
		await approval.approve(id, "admin1", totpNow);
		const spent = await engine.evaluate({
			...input(20000, id),
			context: { risk: { amount: 20000 }, arguments: undefined },
		});
		expect(args.amount).toBe(20000);
		expect(spent.allowed).toBe(true);
	});

	it("refuses an ordinary approval for a step_up tier", async () => {
		const db = await setup();
		const approval = createApprovalModule({}, db);
		const engine = createPolicyEngine({ db, approval, config: { risk } });
		const ordinary = await approval.request(base);
		await approval.approve(ordinary.id, "admin1");
		const d = await engine.evaluate(input(20000, ordinary.id));
		expect(d.allowed).toBe(false);
		expect(d.code).toBe("approval_step_up_insufficient");
	});
});

describe("admin API approval decision", () => {
	async function harness(resolveApproverAuth?: (r: Request) => Promise<AuthAssertion | null>) {
		const db = await setup();
		await db.insert(agents).values({
			id: "sys",
			ownerId: "admin1",
			name: "system",
			type: "autonomous",
			status: "active",
			tokenHash: "h2",
			tokenPrefix: "p2",
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const endpoints: PluginEndpoint[] = [];
		await adminApi({
			enabled: true,
			adminUserIds: ["admin1", "admin2"],
			systemAgentId: "sys",
			resolveApproverAuth,
		}).init?.({
			db,
			config: {} as never,
			addEndpoint: (ep) => endpoints.push(ep),
			addMigration: () => undefined,
			sessionManager: null,
		});
		const ctx: EndpointContext = {
			db,
			getSession: async () => null,
			getUser: async (req) => {
				const t = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
				return t === "admin2-token"
					? { id: "admin2" }
					: t === "admin1-token"
						? { id: "admin1" }
						: null;
			},
		};
		const approve = (id: string) => {
			const route = endpoints.find((e) => e.path === "/approvals/:id/approve");
			return route?.handler(
				new Request(`http://localhost/api/approvals/${id}/approve`, {
					method: "POST",
					headers: { authorization: "Bearer admin2-token" },
				}),
				ctx,
			) as Promise<Response>;
		};
		return { db, approve };
	}

	async function openRequest(db: Database, stepUp?: { acr?: string; maxAge?: number }) {
		const approval = createApprovalModule({}, db);
		return approval.request({ ...base, userId: "admin1", ...(stepUp && { stepUp }) });
	}

	it("answers 401 with the step-up challenge when the approver has no assertion", async () => {
		const { db, approve } = await harness();
		const req = await openRequest(db, { acr: ACR.phishingResistant, maxAge: 300 });
		const res = await approve(req.id);
		expect(res.status).toBe(401);
		const challenge = res.headers.get("www-authenticate") ?? "";
		expect(challenge).toContain('error="insufficient_user_authentication"');
		expect(challenge).toContain(`acr_values="${ACR.phishingResistant}"`);
		expect(challenge).toContain('max_age="300"');
		const body = (await res.json()) as { error: { code: string } };
		expect(body.error.code).toBe("STEP_UP_REQUIRED");
		const [row] = await db.select().from(approvalRequests);
		expect(row?.status).toBe("pending");
	});

	it("approves when the resolver reports a sufficient sign-in and audits the evidence", async () => {
		const { db, approve } = await harness(async () => passkeyNow);
		const req = await openRequest(db, { acr: ACR.phishingResistant, maxAge: 300 });
		const res = await approve(req.id);
		expect(res.status).toBe(200);
		const rows = await db.select().from(auditLogs);
		const row = rows.find((r) => r.action === "admin_api.approval.approve");
		expect(row?.parameters).toMatchObject({ approverAcr: ACR.phishingResistant });
	});

	it("still answers 401 for a resolver that reports a weaker sign-in or throws", async () => {
		const weak = await harness(async () => passwordOnly);
		const r1 = await openRequest(weak.db, { acr: ACR.mfa });
		expect((await weak.approve(r1.id)).status).toBe(401);
		const broken = await harness(async () => {
			throw new Error("resolver down");
		});
		const r2 = await openRequest(broken.db, { acr: ACR.mfa });
		expect((await broken.approve(r2.id)).status).toBe(401);
	});

	it("leaves approvals without a rule alone", async () => {
		const { db, approve } = await harness();
		const req = await openRequest(db);
		expect((await approve(req.id)).status).toBe(200);
	});
});
