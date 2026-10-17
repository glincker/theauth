// Scenario logic running the real theAuth code: createTheAuth on in-memory sql.js, guardTool, tainted(), policy, and signed audit checkpoints and receipts.

import type {
	Checkpoint,
	CheckpointPublicKey,
	Receipt,
	TaintConfig,
	TaintVerdict,
	TheAuth,
} from "@glinr/theauth/browser";
import {
	createCheckpoint,
	createReceipt,
	createTheAuth,
	generateCheckpointKeyPair,
	guardTool,
	ToolApprovalRequiredError,
	ToolDeniedError,
	tainted,
	users,
	verifyReceipt,
} from "@glinr/theauth/browser";
import { loadSqlJs } from "./edge/sql-js.js";
import type { PlaygroundPolicy, ToolCall } from "./presets.js";

export type Outcome = "allow" | "deny" | "escalate";

export interface KeyMaterial {
	signer: Awaited<ReturnType<typeof generateCheckpointKeyPair>>["signer"];
	publicKey: CheckpointPublicKey;
}

export interface ScenarioResult {
	outcome: Outcome;
	reason: string;
	code?: string;
	tier?: string;
	approvalRequestId?: string;
	/** Labels the policy engine saw, by argument name. */
	labels: Record<string, string[]>;
	taint?: TaintVerdict;
	toolRan: boolean;
	receipt?: Receipt;
	receiptError?: string;
	verified?: boolean;
	verifyReason?: string;
	publicKey: CheckpointPublicKey;
}

export function newKey(keyId = "playground-key"): Promise<KeyMaterial> {
	return generateCheckpointKeyPair(keyId).then(({ signer, publicKey }) => ({ signer, publicKey }));
}

export function parsePolicy(text: string): { policy: PlaygroundPolicy } | { error: string } {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch (e) {
		return { error: `Not valid JSON: ${e instanceof Error ? e.message : "parse error"}` };
	}
	if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
		return { error: "The policy must be a JSON object." };
	}
	const obj = raw as Record<string, unknown>;
	const taint = obj.taint as { rules?: unknown } | undefined;
	const risk = obj.risk as { tiers?: unknown } | undefined;
	if (taint !== undefined && !Array.isArray(taint?.rules)) {
		return { error: '"taint.rules" must be an array.' };
	}
	if (risk !== undefined && !Array.isArray(risk?.tiers)) {
		return { error: '"risk.tiers" must be an array.' };
	}
	return {
		policy: {
			taint: { rules: (taint?.rules as Array<Record<string, unknown>>) ?? [] },
			risk: { tiers: (risk?.tiers as Array<Record<string, unknown>>) ?? [] },
		},
	};
}

const HMAC_KEY = "playground-audit-key";

async function buildAuth(policy: PlaygroundPolicy): Promise<TheAuth> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		sqlJs: loadSqlJs,
		agents: { enabled: true, maxPerUser: 5, defaultPermissions: [], auditAll: true },
		audit: { tamperEvident: true, hmacKey: HMAC_KEY },
		policy: {
			taint: policy.taint as unknown as TaintConfig,
			risk: policy.risk as unknown as NonNullable<
				Parameters<typeof createTheAuth>[0]["policy"]
			>["risk"],
		},
	});
	const now = new Date();
	await auth.db.insert(users).values({
		id: "visitor",
		email: "visitor@playground.invalid",
		name: "Visitor",
		createdAt: now,
		updatedAt: now,
	});
	return auth;
}

function stringLabels(map: Record<string, string[]>): Record<string, string[]> {
	return Object.fromEntries(Object.entries(map).filter(([, v]) => v.length > 0));
}

async function waitForRow(auth: TheAuth, agentId: string): Promise<string | undefined> {
	for (let i = 0; i < 60; i++) {
		const rows = await auth.audit.query({ agentId, limit: 20 });
		const row = rows.find((r) => r.action === "execute");
		if (row) return row.id;
		await new Promise((r) => setTimeout(r, 25));
	}
	return undefined;
}

/** Arguments with the labelled ones wrapped by tainted(), as an agent runtime would. */
export function labelledArgs(call: ToolCall): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [name, value] of Object.entries(call.args)) {
		const labels = call.labels[name];
		out[name] = labels && labels.length > 0 ? tainted(value, labels) : value;
	}
	return out;
}

export async function runScenario(
	call: ToolCall,
	policy: PlaygroundPolicy,
	key: KeyMaterial,
): Promise<ScenarioResult> {
	const auth = await buildAuth(policy);
	const agent = await auth.agent.create({
		ownerId: "visitor",
		name: "playground-agent",
		type: "autonomous",
		permissions: ["send_email", "read_web", "pay"].map((t) => ({
			resource: `tool:${t}`,
			actions: ["execute"],
		})),
	});

	let ran = false;
	let seenLabels: Record<string, string[]> = {};
	let verdict: TaintVerdict | undefined;
	const tool = {
		name: call.tool,
		execute: async (_args: Record<string, unknown>) => {
			ran = true;
			return { ok: true };
		},
	};
	const guarded = guardTool(
		auth,
		{
			agentId: agent.id,
			risk: (a) =>
				call.tool === "pay"
					? { amount: Number(a.amount), currency: String(a.currency) }
					: undefined,
			onDecision: ({ decision }) => {
				verdict = decision.taint;
				seenLabels = stringLabels(decision.taint?.labels ?? {});
			},
		},
		tool,
	);

	const result: ScenarioResult = {
		outcome: "allow",
		reason: "",
		labels: {},
		toolRan: false,
		publicKey: key.publicKey,
	};
	try {
		await guarded.execute(labelledArgs(call));
		result.reason = "Policy allowed the call and the tool ran.";
	} catch (error) {
		if (error instanceof ToolDeniedError) {
			result.outcome = "deny";
			result.reason = error.reason;
			result.code = error.code;
		} else if (error instanceof ToolApprovalRequiredError) {
			result.outcome = "escalate";
			result.reason = error.reason;
			result.tier = error.tier;
			result.approvalRequestId = error.approvalRequestId;
		} else {
			throw error;
		}
	}
	result.toolRan = ran;
	result.labels = Object.keys(seenLabels).length > 0 ? seenLabels : mirrorLabels(call);
	result.taint = verdict;

	const rowId = await waitForRow(auth, agent.id);
	if (!rowId) {
		result.receiptError = "The audit row did not arrive in time.";
		return result;
	}
	const cp = await createCheckpoint(auth.db, { signer: key.signer });
	if (!cp.success) {
		result.receiptError = cp.error.message;
		return result;
	}
	const rec = await createReceipt(auth.db, rowId, cp.data as Checkpoint, {
		reveal: ["action", "resource", "result", "reason", "inputProvenance"],
		hmacKey: HMAC_KEY,
	});
	if (!rec.success) {
		result.receiptError = rec.error.message;
		return result;
	}
	result.receipt = rec.data;
	const check = await verifyReceipt(rec.data, key.publicKey);
	result.verified = check.valid;
	if (!check.valid) result.verifyReason = check.reason;
	return result;
}

function mirrorLabels(call: ToolCall): Record<string, string[]> {
	return stringLabels(call.labels);
}

/** Verify a receipt (possibly edited by the visitor) with the public key. */
export async function verifyReceiptJson(
	text: string,
	publicKey: CheckpointPublicKey,
): Promise<{ valid: boolean; reason?: string }> {
	let parsed: Receipt;
	try {
		parsed = JSON.parse(text) as Receipt;
	} catch {
		return { valid: false, reason: "not valid JSON" };
	}
	const out = await verifyReceipt(parsed, publicKey);
	return out.valid ? { valid: true } : { valid: false, reason: out.reason };
}
