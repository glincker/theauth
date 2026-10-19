import { describe, expect, it } from "vitest";
import type { AuditInsert, AuditRow } from "../../../src/audit/chain.js";
import { computeRowHash, linkAndAppend } from "../../../src/audit/chain.js";
import { computePseudonyms } from "../../../src/audit/pseudonym.js";
import type { Stores } from "../../../src/db/store/index.js";
import { StoreConflictError } from "../../../src/db/store-conflict.js";
import { seedAgent } from "./seed.js";
import type { MakeTarget, SuiteOptions } from "./target.js";
import { uid } from "./target.js";

const HMAC_KEY = "audit-contract-hmac-key";
const SECOND_MS = 1_700_000_000_000;

interface Seed {
	agentId: string;
	userId: string;
}

/** A fully stamped row, as `appendChained` builds it before linking. */
async function stamped(seed: Seed, over: Partial<AuditInsert> = {}): Promise<AuditInsert> {
	const row: AuditInsert = {
		id: uid("au"),
		agentId: seed.agentId,
		userId: seed.userId,
		action: "execute",
		resource: "mcp:contract:tool",
		result: "allowed",
		durationMs: 3,
		timestamp: new Date(SECOND_MS),
		hashVersion: 2,
		...over,
	};
	row.idPseudonyms = over.idPseudonyms ?? (await computePseudonyms(row, HMAC_KEY));
	return row;
}

async function append(stores: Stores, row: AuditInsert): Promise<void> {
	await stores.audit.exclusive(row.agentId, () => linkAndAppend(stores.audit, row, HMAC_KEY));
}

async function chainOf(stores: Stores, agentId: string): Promise<AuditRow[]> {
	return (await stores.kernel.findMany("auditLogs", {
		where: [{ field: "agentId", op: "eq", value: agentId }],
		orderBy: [{ field: "chainSeq", dir: "asc" }],
	})) as unknown as AuditRow[];
}

/** Recomputes every hash from what the backend returns. */
async function expectVerifiableChain(
	stores: Stores,
	agentId: string,
	rows: number,
): Promise<AuditRow[]> {
	const chain = await chainOf(stores, agentId);
	expect(chain).toHaveLength(rows);
	let prev: string | null = null;
	for (const [i, row] of chain.entries()) {
		expect(row.chainSeq).toBe(i + 1);
		expect(row.prevHash).toBe(prev);
		expect(await computeRowHash(row, i + 1, prev, HMAC_KEY)).toBe(row.hash);
		prev = row.hash;
	}
	return chain;
}

const LONG_TEXT = 'line one\nline two "quoted" \\ back slash café 中文 \u{1f600} '.repeat(40);

/** One case per hashed field of version 2 (`hashedFieldsV2` and `commonFields` in audit/chain.ts). */
const FIELD_CASES: Array<[string, Partial<AuditInsert>]> = [
	["id", { id: `${uid("au")}-é中` }],
	["action", { action: "exécute/%_![x]" }],
	["resource", { resource: "mcp:srv:tool/%_!['\"\\" }],
	[
		"parameters",
		{
			parameters: {
				z: 1,
				a: { deep: [1, 2.5, -0.1, "s", null, true, false, [], {}], text: "café \u{1f600}" },
				big: 9_007_199_254_740_991,
				neg: -42,
				empty: "",
				multi: 'a\nb\tc"d\\e',
			},
		},
	],
	["parameters empty object", { parameters: {} }],
	["parameters null", { parameters: null }],
	["result allowed", { result: "allowed" }],
	["result denied", { result: "denied" }],
	["result rate_limited", { result: "rate_limited" }],
	["result escalated", { result: "escalated" }],
	["reason text", { reason: LONG_TEXT }],
	["reason empty string", { reason: "" }],
	["reason null", { reason: null }],
	["durationMs zero", { durationMs: 0 }],
	["durationMs large", { durationMs: 2_000_000_000 }],
	["tokensCost zero", { tokensCost: 0 }],
	["tokensCost large", { tokensCost: 1_999_999_999 }],
	["tokensCost null", { tokensCost: null }],
	["ip", { ip: "2001:db8::8a2e:370:7334" }],
	["ip empty string", { ip: "" }],
	["userAgent", { userAgent: `${"Mozilla/5.0 é ".repeat(80)}end` }],
	["cacheHit true", { cacheHit: true }],
	["cacheHit false", { cacheHit: false }],
	["timestamp past 2^31 seconds", { timestamp: new Date(4_102_444_800_000) }],
	["timestamp epoch second one", { timestamp: new Date(1000) }],
	["policyVersion", { policyVersion: "v1.2.3-é" }],
	["delegationChain", { delegationChain: ["agent-a", "agent-b", "agent-中"] }],
	["delegationChain empty", { delegationChain: [] }],
	[
		"inputProvenance",
		{
			inputProvenance: {
				sources: [{ kind: "tool", id: "t1", score: 0.5 }],
				trusted: false,
				note: "",
			},
		},
	],
	["idPseudonyms", { idPseudonyms: { userId: "p1", agentId: "p2", extra: "pé" } }],
];

function sameValue(written: unknown, read: unknown): void {
	if (written instanceof Date) expect((read as Date).getTime()).toBe(written.getTime());
	else expect(read ?? null).toEqual(written ?? null);
}

/** The audit repository and the chain writer on it: round trips, order, forks, the write queue. */
export function defineAudit(make: MakeTarget, options: SuiteOptions): void {
	const parallel = options.parallel ?? 24;

	describe("audit repository", () => {
		it("has no head for an agent without chained rows", async () => {
			const t = await make();
			try {
				const seed = await seedAgent(t.stores.kernel);
				expect(await t.stores.audit.readHead(seed.agentId)).toBeNull();
				await t.stores.audit.insertUnchained({ ...(await stamped(seed)), recordedAtMs: 5 });
				expect(await t.stores.audit.readHead(seed.agentId)).toBeNull();
			} finally {
				await t.close();
			}
		});

		it("reads the highest chained row as the head and refuses a taken seq", async () => {
			const t = await make();
			try {
				const seed = await seedAgent(t.stores.kernel);
				const base = await stamped(seed);
				// Rows without a chain position must not be taken for the head, whichever way the engine sorts NULLs.
				await t.stores.audit.insertUnchained({ ...base, id: uid("au"), recordedAtMs: SECOND_MS });
				await t.stores.audit.appendAt({
					...base,
					id: uid("au"),
					chainSeq: 1,
					hash: "h1",
					prevHash: null,
					recordedAtMs: SECOND_MS + 1,
				});
				await t.stores.audit.appendAt({
					...base,
					id: uid("au"),
					chainSeq: 3,
					hash: "h3",
					prevHash: "h1",
					recordedAtMs: SECOND_MS + 3,
				});
				expect(await t.stores.audit.readHead(seed.agentId)).toEqual({
					seq: 3,
					hash: "h3",
					recordedAtMs: SECOND_MS + 3,
				});
				await expect(
					t.stores.audit.appendAt({
						...base,
						id: uid("au"),
						chainSeq: 3,
						hash: "x",
						prevHash: "h1",
					}),
				).rejects.toBeInstanceOf(StoreConflictError);
				// The same seq under another agent is fine.
				const other = await seedAgent(t.stores.kernel);
				await t.stores.audit.appendAt({
					...(await stamped(other)),
					chainSeq: 3,
					hash: "y",
					prevHash: null,
				});
				await expect(t.stores.audit.appendAt({ ...base, id: uid("au") })).rejects.toThrow(
					/chainSeq and hash/,
				);
			} finally {
				await t.close();
			}
		});

		it("lets rows without a chain position share an agent", async () => {
			const t = await make();
			try {
				const seed = await seedAgent(t.stores.kernel);
				for (let i = 0; i < 3; i++) {
					await t.stores.audit.insertUnchained({
						...(await stamped(seed)),
						recordedAtMs: SECOND_MS + i,
					});
				}
				expect(
					await t.stores.kernel.count("auditLogs", [
						{ field: "agentId", op: "eq", value: seed.agentId },
					]),
				).toBe(3);
			} finally {
				await t.close();
			}
		});

		it.each(FIELD_CASES)("round trips the hashed field: %s", async (_name, over) => {
			const t = await make();
			try {
				const seed = await seedAgent(t.stores.kernel);
				const first = await stamped(seed);
				const row = await stamped(seed, over);
				await append(t.stores, first);
				await append(t.stores, row);
				const chain = await expectVerifiableChain(t.stores, seed.agentId, 2);
				const back = chain[1] as AuditRow;
				for (const key of Object.keys(over) as Array<keyof AuditInsert>) {
					sameValue(row[key], back[key as keyof AuditRow]);
				}
				// cacheHit defaults to false when the row leaves it out.
				if (!("cacheHit" in over)) expect(back.cacheHit).toBe(false);
			} finally {
				await t.close();
			}
		});

		it("serializes writers of one agent in call order and lets agents interleave", async () => {
			const t = await make();
			try {
				const { audit } = t.stores;
				const order: string[] = [];
				let release: () => void = () => undefined;
				const gate = new Promise<void>((resolve) => {
					release = resolve;
				});
				const first = audit.exclusive("a", async () => {
					await gate;
					order.push("a1");
				});
				const second = audit.exclusive("a", async () => {
					order.push("a2");
				});
				const failing = audit.exclusive("a", async () => {
					throw new Error("boom");
				});
				const third = audit.exclusive("a", async () => {
					order.push("a3");
				});
				await audit.exclusive("b", async () => {
					order.push("b1");
				});
				expect(order).toEqual(["b1"]);
				release();
				await Promise.all([first, second, third]);
				await expect(failing).rejects.toThrow("boom");
				expect(order).toEqual(["b1", "a1", "a2", "a3"]);
			} finally {
				await t.close();
			}
		});

		it("builds one gapless verifiable chain from parallel writers in one process", async () => {
			const t = await make();
			try {
				const seed = await seedAgent(t.stores.kernel);
				const rows = await Promise.all(
					Array.from({ length: parallel }, (_, i) => stamped(seed, { resource: `mcp:p:${i}` })),
				);
				await Promise.all(rows.map((r) => append(t.stores, r)));
				await expectVerifiableChain(t.stores, seed.agentId, parallel);
			} finally {
				await t.close();
			}
		});

		it("keeps one chain when two processes append for the same agent", async () => {
			const t = await make();
			const other = t.peer ? await t.peer() : null;
			try {
				if (!other) return;
				const seed = await seedAgent(t.stores.kernel);
				const total = parallel;
				const rows = await Promise.all(
					Array.from({ length: total }, (_, i) => stamped(seed, { resource: `mcp:q:${i}` })),
				);
				await Promise.all(rows.map((r, i) => append(i % 2 === 0 ? t.stores : other.stores, r)));
				await expectVerifiableChain(t.stores, seed.agentId, total);
			} finally {
				await other?.close();
				await t.close();
			}
		});
	});
}
