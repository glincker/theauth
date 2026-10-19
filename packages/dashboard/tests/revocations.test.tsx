import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/api/client.js";
import type { DelegationImpact, RevocationRow } from "../src/api/types.js";
import {
	BusStats,
	DenylistTable,
	describeKind,
	ImpactTable,
} from "../src/components/revocation-tables.js";
import { approvalsUnavailable } from "../src/pages/approvals.js";
import { buildExplainRequest } from "../src/pages/explain.js";
import { buildRevocationInput, revocationsUnavailable } from "../src/pages/revocations.js";

afterEach(() => vi.unstubAllGlobals());

function stubFetch(body: unknown, status = 200) {
	const fn = vi.fn(async () => new Response(JSON.stringify(body), { status }));
	vi.stubGlobal("fetch", fn);
	return fn;
}

const link: DelegationImpact = {
	id: "d1",
	fromAgentId: "agent_a",
	toAgentId: "agent_b",
	expiresAt: "2026-10-19T00:00:00.000Z",
	cascade: ["d1", "d2"],
	agents: ["agent_b", "agent_c"],
	denied: false,
	tokenRule: "rule",
};

describe("api client: revocations", () => {
	it("reads the snapshot, with an optional kind filter", async () => {
		const fn = stubFetch({ rows: [], stats: null });
		const client = createApiClient("http://x/");
		const res = await client.getRevocations("dlg");
		expect(res.success).toBe(true);
		expect(fn).toHaveBeenCalledWith("http://x/api/revocations?kind=dlg", expect.anything());
		await client.getRevocations();
		expect(fn).toHaveBeenLastCalledWith("http://x/api/revocations", expect.anything());
	});

	it("posts a revoke and reads the impact list", async () => {
		const fn = stubFetch({ revoked: ["d1"] }, 201);
		const client = createApiClient("http://x");
		await client.createRevocation({ kind: "dlg", id: "d1", reason: "leaked" });
		const [url, init] = fn.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("http://x/api/revocations");
		expect(init.method).toBe("POST");
		expect(JSON.parse(String(init.body))).toEqual({ kind: "dlg", id: "d1", reason: "leaked" });
		await client.getDelegationImpact();
		expect(fn.mock.calls[1]?.[0]).toBe("http://x/api/revocations/delegations");
	});

	it("reports a missing route as HTTP_404 so pages can guard", async () => {
		stubFetch({}, 404);
		const res = await createApiClient("http://x").getRevocations();
		expect(res.success).toBe(false);
		if (!res.success) {
			expect(revocationsUnavailable(res.error)).toBe(true);
			expect(approvalsUnavailable(res.error)).toBe(true);
		}
	});
});

describe("form helpers", () => {
	it("validates explain input and trims it", () => {
		expect(buildExplainRequest({ agentId: " ", action: "read", resource: "r" })).toBe(
			"Agent id is required",
		);
		expect(buildExplainRequest({ agentId: " a ", action: "read", resource: " r " })).toEqual({
			agentId: "a",
			action: "read",
			resource: "r",
		});
	});

	it("validates revoke input", () => {
		expect(buildRevocationInput("agent", " ", "")).toBe("An id is required");
		expect(buildRevocationInput("agent", " a1 ", " ")).toEqual({ kind: "agent", id: "a1" });
		expect(buildRevocationInput("sub", "u1", "left")).toEqual({
			kind: "sub",
			id: "u1",
			reason: "left",
		});
		expect(describeKind("dlg")).toContain("delegation");
	});
});

describe("revocation components", () => {
	it("renders bus counters and flags push failures", () => {
		const html = renderToStaticMarkup(
			<BusStats
				stats={{
					published: 3,
					rowsPushed: 5,
					retries: 1,
					pushFailures: 2,
					attemptFailures: 3,
					pruned: 0,
				}}
			/>,
		);
		expect(html).toContain("Push failures");
		expect(html).toContain("text-red-500");
		expect(renderToStaticMarkup(<BusStats stats={null} />)).toContain("no revocation bus");
	});

	it("renders denylist rows and the empty state", () => {
		const row: RevocationRow = {
			kind: "dlg",
			id: "d1",
			revokedAt: "2026-10-18T10:00:00.000Z",
			expiresAt: "2026-10-19T10:00:00.000Z",
			reason: "delegation.revoke",
			sourceId: "d1",
		};
		const html = renderToStaticMarkup(<DenylistTable rows={[row]} />);
		expect(html).toContain("delegation.revoke");
		expect(html).toContain(">d1<");
		expect(renderToStaticMarkup(<DenylistTable rows={[]} />)).toContain("No denylist rows");
	});

	it("shows the cascade per link and hides revoke for denied links", () => {
		const html = renderToStaticMarkup(
			<ImpactTable links={[link, { ...link, id: "d9", denied: true }]} onRevoke={() => {}} />,
		);
		expect(html).toContain("2 links, tokens bound to d1, d2");
		expect(html).toContain("Revoke delegation d1");
		expect(html).not.toContain("Revoke delegation d9");
		expect(html).toContain(">denied<");
	});
});
