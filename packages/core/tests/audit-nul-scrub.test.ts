import { describe, expect, it } from "vitest";
import { enableAuditChain, insertAuditRow } from "../src/audit/chain.js";
import { scrubNul } from "../src/audit/scrub.js";
import { verifyAuditChain } from "../src/audit/verify.js";
import { createDatabase } from "../src/db/database.js";
import { runMigrations } from "../src/db/migrate/index.js";
import { storesFor } from "../src/db/store/index.js";
import { seedAgent } from "./store-contract/kernel/seed.js";

describe("audit NUL scrub", () => {
	it("replaces NUL in strings, array items and object keys, and leaves clean rows alone", () => {
		const clean = { a: "x", b: [1, "y"], c: { d: null } };
		expect(scrubNul(clean)).toBe(clean);
		expect(
			scrubNul({ reason: "a\u0000b", list: ["\u0000"], deep: { "k\u0000": "v\u0000" } }),
		).toEqual({
			reason: "a�b",
			list: ["�"],
			deep: { "k�": "v�" },
		});
		const when = new Date(1000);
		expect(scrubNul({ when, text: "\u0000" }).when).toBe(when);
	});

	it("keeps the chain verifiable when a field carries NUL, even where the engine would cut it", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await runMigrations(db, "sqlite");
		enableAuditChain(db, { hmacKey: "nul-scrub-key" });
		const { agentId, userId } = await seedAgent(storesFor(db).kernel);
		await insertAuditRow(db, {
			id: "nul-1",
			agentId,
			userId,
			action: "execute",
			resource: "mcp:srv:tool\u0000x",
			parameters: { "k\u0000": "v\u0000w" },
			result: "denied",
			reason: "before\u0000after",
			durationMs: 1,
			timestamp: new Date(1_700_000_000_000),
		});
		const verified = await verifyAuditChain(db, { agentId }, "nul-scrub-key");
		expect(verified.success && verified.data.ok).toBe(true);
		const row = await storesFor(db).kernel.findOne("auditLogs", [
			{ field: "id", op: "eq", value: "nul-1" },
		]);
		expect(row?.reason).toBe("before�after");
		expect(row?.resource).toBe("mcp:srv:tool�x");
	});
});
