import { describe, expect, it } from "vitest";
import { uniqueEmail } from "./claim-races.js";
import type { ContractAuth, StoreContractTarget } from "./types.js";

type Make = () => Promise<StoreContractTarget>;

async function agentFor(auth: ContractAuth, tag: string): Promise<{ agentId: string }> {
	const owner = await auth.user.create({ email: uniqueEmail(tag) });
	const agent = await auth.agent.create({
		ownerId: owner.id,
		name: `contract-${tag}`,
		type: "autonomous",
		permissions: [{ resource: "mcp:*", actions: ["execute"] }],
	});
	return { agentId: agent.id };
}

async function expectGaplessChain(auth: ContractAuth, agentId: string, minRows: number) {
	const verified = await auth.audit.verifyAuditChain({ agentId });
	if (!verified.success) throw new Error(`verify failed: ${verified.error.message}`);
	expect(verified.data.ok).toBe(true);
	expect(verified.data.unchained).toBe(0);
	expect(verified.data.checked).toBeGreaterThanOrEqual(minRows);
	// A gapless chain from seq 1 has a head equal to the number of rows checked.
	expect(verified.data.heads.find((h) => h.agentId === agentId)?.seq).toBe(verified.data.checked);
}

/** Concurrent appends for one agent must form one gapless chain that verifies, from one process or two. */
export function defineAuditOrder(make: Make, parallel: number): void {
	describe("audit chain order", () => {
		it("appends concurrent rows for one agent into a verifiable gapless chain", async () => {
			const t = await make();
			try {
				const { agentId } = await agentFor(t.auth, "chain");
				const results = await Promise.all(
					Array.from({ length: parallel }, (_, i) =>
						t.auth.authorize(agentId, { action: "execute", resource: `mcp:x:t${i}` }),
					),
				);
				expect(results.every((r) => r.allowed)).toBe(true);
				expect(await t.auth.audit.query({ agentId, limit: parallel + 10 })).toHaveLength(parallel);
				await expectGaplessChain(t.auth, agentId, parallel);
			} finally {
				await t.close();
			}
		});

		it("keeps one chain when two processes append for the same agent", async () => {
			const t = await make();
			const other = t.peer ? await t.peer() : null;
			try {
				if (!other) return; // the backend cannot be shared between two instances
				const { agentId } = await agentFor(t.auth, "chain2");
				const half = Math.ceil(parallel / 2);
				await Promise.all(
					Array.from({ length: half * 2 }, (_, i) =>
						(i % 2 === 0 ? t.auth : other.auth).authorize(agentId, {
							action: "execute",
							resource: `mcp:y:t${i}`,
						}),
					),
				);
				expect(await t.auth.audit.query({ agentId, limit: parallel + 10 })).toHaveLength(half * 2);
				await expectGaplessChain(t.auth, agentId, half * 2);
			} finally {
				await other?.close();
				await t.close();
			}
		});
	});
}
