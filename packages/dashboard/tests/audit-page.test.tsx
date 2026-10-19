import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { AuditLogEntry, ExplainResponse } from "../src/api/types.js";
import { ExplainView } from "../src/components/explain-drawer.js";
import { AuditTable } from "../src/pages/audit-table.js";

function entry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
	return {
		id: "a1",
		timestamp: "2026-10-17T10:00:00.000Z",
		agentId: "agent-1",
		agentName: "Billing agent",
		action: "read",
		resource: "mcp:github:issues",
		result: "denied",
		durationMs: 4,
		metadata: {},
		code: "no_permission",
		...overrides,
	};
}

describe("AuditTable", () => {
	it("renders a Code column with the decision code of each row", () => {
		const html = renderToStaticMarkup(
			<AuditTable
				entries={[entry(), entry({ id: "a2", result: "allowed", code: "allowed" })]}
				onExplain={() => {}}
			/>,
		);
		expect(html).toContain("Code");
		expect(html).toContain("no_permission");
		expect(html).toContain(">allowed<");
		expect(html.match(/data-testid="decision-code"/g)).toHaveLength(2);
	});

	it("shows a dash for rows written before codes existed, and an explain action per row", () => {
		const html = renderToStaticMarkup(
			<AuditTable entries={[entry({ code: undefined })]} onExplain={() => {}} />,
		);
		expect(html).not.toContain('data-testid="decision-code"');
		expect(html).toContain("Explain decision for read on mcp:github:issues");
	});

	it("shows provenance chips with the id or a short hash, and a dash when none", () => {
		const hash = "ab12cd34".padEnd(64, "0");
		const html = renderToStaticMarkup(
			<AuditTable
				entries={[
					entry({
						inputs: [
							{ kind: "retrieved_document", hash },
							{ kind: "user_message", id: "msg_1", hash: "f".repeat(64) },
						],
					}),
					entry({ id: "a2" }),
				]}
				onExplain={() => {}}
			/>,
		);
		expect(html).toContain("Inputs");
		expect(html.match(/data-testid="input-chips"/g)).toHaveLength(1);
		expect(html).toContain("ab12cd34");
		expect(html).toContain("msg_1");
	});

	it("renders the empty state without rows", () => {
		expect(renderToStaticMarkup(<AuditTable entries={[]} onExplain={() => {}} />)).toContain(
			"No audit events yet",
		);
	});
});

describe("ExplainView", () => {
	const result: ExplainResponse = {
		decision: "deny",
		allowed: false,
		code: "rate_limited",
		reason: "Rate limit of 10 per hour reached",
		agent: { id: "agent-1", name: "Billing agent", ownerId: "u1", status: "active" },
		matchedGrant: {
			source: "own",
			permission: { resource: "mcp:github:*", actions: ["read"] },
			resourceMatch: "wildcard:prefix",
			actionMatch: "exact",
		},
		constraints: [{ constraint: "maxCallsPerHour", outcome: "fail", detail: "10 of 10 used" }],
		attempts: [],
		hook: { configured: true, evaluated: true, outcome: "timeout", guard: "pii", elapsedMs: 2000 },
		nearMisses: [],
	};

	it("shows the code, the failed constraint and the hook outcome", () => {
		const html = renderToStaticMarkup(<ExplainView result={result} />);
		expect(html).toContain("rate_limited");
		expect(html).toContain("maxCallsPerHour");
		expect(html).toContain("10 of 10 used");
		expect(html).toContain("timeout (pii) in 2000ms");
	});
});
