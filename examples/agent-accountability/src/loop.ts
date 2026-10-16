/**
 * Agent accountability loop: identity, scoped delegation, policy gate,
 * human approval, tamper-evident audit, revocation.
 */
import { createTheAuth, insertAuditRow, users, verifyAuditChain } from "@glinr/theauth";

export interface Narrator {
	step(n: number, text: string): void;
	note(text: string): void;
}

export interface LoopOutcome {
	unauthorizedDenied: boolean;
	approvalRequired: boolean;
	approvalUnlocked: boolean;
	chainOk: boolean;
	chainChecked: number;
	revokedRejected: boolean;
}

const OWNER = "user-alice";
const REFUND = "mcp:payments:refund";

export async function runAccountabilityLoop(say: Narrator): Promise<LoopOutcome> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
		audit: { tamperEvident: true, hmacKey: "demo-only-hmac-key" },
	});
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

	// Approvals the human has granted; each is single use.
	const approved = new Set<string>();

	interface Attempt {
		ran: boolean;
		held: boolean;
		reason: string;
		approvalRequestId?: string;
	}

	/**
	 * Policy gate: runs before every action. policy.evaluate answers allow, deny
	 * or escalate; an escalate runs only once a human approval is on file.
	 */
	async function attempt(
		agentId: string,
		action: string,
		resource: string,
		args?: Record<string, unknown>,
		openApproval = false,
	): Promise<Attempt> {
		const decision = await auth.policy.evaluate(
			{ subject: { agentId, ownerId: OWNER }, action, resource, context: { arguments: args } },
			{ openApproval },
		);
		const approvalRequestId = decision.escalation?.approvalRequestId;
		if (decision.decision === "allow") return { ran: true, held: false, reason: decision.reason };
		if (decision.decision === "escalate") {
			const ran = approved.delete(`${agentId}:${action}:${resource}`);
			return { ran, held: !ran, reason: decision.reason, approvalRequestId };
		}
		return { ran: false, held: false, reason: decision.reason };
	}

	// 1. Identity bound to an owner
	say.step(1, "Create an agent identity owned by alice");
	const orchestrator = await auth.agent.create({
		ownerId: OWNER,
		name: "support-orchestrator",
		type: "autonomous",
		permissions: [
			{ resource: "mcp:crm:notes", actions: ["read", "write"] },
			{ resource: REFUND, actions: ["execute"] },
		],
	});
	const worker = await auth.agent.create({
		ownerId: OWNER,
		name: "refund-worker",
		type: "delegated",
		permissions: [],
	});
	say.note(`agent ${worker.name} (${worker.id.slice(0, 12)}) owner=${OWNER}`);

	// 2. Scoped, short-lived delegation
	say.step(2, "Delegate narrow authority for 15 minutes");
	const chain = await auth.delegate({
		fromAgent: orchestrator.id,
		toAgent: worker.id,
		permissions: [
			{ resource: "mcp:crm:notes", actions: ["read"] },
			// The approval constraint travels with the grant.
			{ resource: REFUND, actions: ["execute"], constraints: { requireApproval: true } },
		],
		expiresAt: new Date(Date.now() + 15 * 60 * 1000),
		maxDepth: 1,
	});
	say.note(
		`chain ${chain.id.slice(0, 12)} grants crm:notes read and refund (approval required), root owner ${chain.rootOwnerId}, expires ${chain.expiresAt.toISOString()}`,
	);

	// 3. Policy check before each action
	say.step(3, "Agent attempts actions; policy runs first");
	const read = await attempt(worker.id, "read", "mcp:crm:notes");
	say.note(`read  mcp:crm:notes      -> ${read.ran ? "ALLOWED" : `DENIED (${read.reason})`}`);
	const write = await attempt(worker.id, "write", "mcp:crm:notes");
	say.note(`write mcp:crm:notes      -> ${write.ran ? "ALLOWED" : `DENIED (${write.reason})`}`);
	const refundArgs = { amountUsd: 480, orderId: "ord_1042" };
	const refund = await attempt(worker.id, "execute", REFUND, refundArgs, true);
	say.note(`exec  ${REFUND} -> ${refund.ran ? "ALLOWED" : `HELD (${refund.reason})`}`);

	// 4. Human approves
	say.step(4, "High-value action waits for a human");
	const requestId = refund.approvalRequestId;
	if (!requestId) throw new Error("policy.evaluate did not open an approval request");
	say.note(`approval ${requestId.slice(0, 12)} pending for ${OWNER}`);
	const decided = await auth.approval.approve(requestId, OWNER);
	approved.add(`${worker.id}:execute:${REFUND}`);
	say.note(`alice -> ${decided.status.toUpperCase()}`);
	const unlocked = await attempt(worker.id, "execute", REFUND);
	say.note(`exec  ${REFUND} -> ${unlocked.ran ? "ALLOWED with approval" : "STILL DENIED"}`);

	// 5. Decision into the audit log, chain verifies
	say.step(5, "Record the human decision and verify the audit chain");
	await insertAuditRow(auth.db, {
		id: `dec_${requestId}`,
		agentId: worker.id,
		userId: OWNER,
		action: "approve",
		resource: REFUND,
		parameters: { requestId, decidedBy: OWNER, outcome: decided.status },
		result: "allowed",
		reason: `human_${decided.status}`,
		durationMs: 0,
		timestamp: new Date(),
		cacheHit: false,
	});
	const entries = await auth.audit.query({ agentId: worker.id });
	say.note(`${entries.length} audit entries for ${worker.name}`);
	const verdict = await verifyAuditChain(auth.db, {}, "demo-only-hmac-key");
	const verified = verdict.success ? verdict.data : { ok: false, checked: 0 };
	say.note(`chain ok=${verified.ok} rows checked=${verified.checked}`);

	// 6. Revoke, then the next attempt fails
	say.step(6, "Owner revokes the agent");
	await auth.agent.revoke(worker.id);
	const after = await attempt(worker.id, "read", "mcp:crm:notes");
	say.note(`read  mcp:crm:notes      -> ${after.ran ? "ALLOWED" : `DENIED (${after.reason})`}`);

	return {
		unauthorizedDenied: !write.ran,
		approvalRequired: refund.held,
		approvalUnlocked: unlocked.ran,
		chainOk: verified.ok,
		chainChecked: verified.checked,
		revokedRejected: !after.ran,
	};
}
