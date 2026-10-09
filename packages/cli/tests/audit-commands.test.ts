import type { createAuditModule } from "@glinr/theauth";
import { describe, expect, it } from "vitest";
import { parseAuditArgs, runAudit } from "../src/audit-commands.js";

type AuditModule = ReturnType<typeof createAuditModule>;

function fakeAudit(overrides: Partial<AuditModule>): AuditModule {
	const unused = async () => {
		throw new Error("not used");
	};
	return {
		query: unused,
		export: unused,
		cleanup: unused,
		verifyAuditChain: unused,
		replayAgent: unused,
		exportAudit: unused,
		...overrides,
	} as AuditModule;
}

describe("parseAuditArgs", () => {
	it("parses verify and replay flags", () => {
		const v = parseAuditArgs(["verify", "--from", "2026-10-01T00:00:00Z", "--json"]);
		expect(v).toMatchObject({ subcommand: "verify", json: true, error: null });
		expect(v.from?.toISOString()).toBe("2026-10-01T00:00:00.000Z");
		const r = parseAuditArgs(["replay", "--agent=a1", "--user", "u1"]);
		expect(r).toMatchObject({ subcommand: "replay", agent: "a1", user: "u1", error: null });
	});

	it("rejects bad input", () => {
		expect(parseAuditArgs(["replay"]).error).toMatch(/--agent/);
		expect(parseAuditArgs(["verify", "--from", "nope"]).error).toMatch(/not a valid date/);
		expect(parseAuditArgs(["verify", "--wat"]).error).toMatch(/Unknown option/);
		expect(parseAuditArgs(["frob"]).error).toMatch(/Unknown audit command/);
		expect(parseAuditArgs([]).help).toBe(true);
	});
});

describe("runAudit", () => {
	it("exits 0 on a clean chain and 1 with row ids on a break", async () => {
		const ok = await runAudit(
			parseAuditArgs(["verify"]),
			fakeAudit({
				verifyAuditChain: async () => ({
					success: true,
					data: { ok: true, checked: 4, unchained: 1, heads: [] },
				}),
			}),
		);
		expect(ok.code).toBe(0);
		expect(ok.output).toContain("4 chained rows verified");

		const bad = await runAudit(
			parseAuditArgs(["verify", "--json"]),
			fakeAudit({
				verifyAuditChain: async () => ({
					success: true,
					data: {
						ok: false,
						checked: 2,
						unchained: 0,
						heads: [],
						firstBreak: {
							agentId: "a1",
							rowId: "r2",
							seq: 2,
							reason: "hash_mismatch",
							rowIds: ["r2"],
						},
					},
				}),
			}),
		);
		expect(bad.code).toBe(1);
		expect(JSON.parse(bad.output).firstBreak.rowIds).toEqual(["r2"]);
	});

	it("prints a replay timeline and fails when the chain is broken", async () => {
		const out = await runAudit(
			parseAuditArgs(["replay", "--agent", "a1"]),
			fakeAudit({
				replayAgent: async () => ({
					success: true,
					data: {
						agentId: "a1",
						events: [
							{
								kind: "action",
								at: new Date("2026-10-01T00:00:10Z"),
								id: "r1",
								summary: "allowed execute mcp:x",
								chained: true,
								detail: {},
							},
						],
						verification: { status: "broken", checked: 1, unchained: 0, heads: [] },
					},
				}),
			}),
		);
		expect(out.code).toBe(1);
		expect(out.output).toContain("2026-10-01T00:00:10.000Z  action     allowed execute mcp:x");
		expect(out.output).toContain("Chain: broken");
	});
});
