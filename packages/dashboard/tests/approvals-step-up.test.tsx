import { afterEach, describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/api/client.js";
import { quorumHint, stepUpHint } from "../src/pages/approvals.js";

afterEach(() => vi.unstubAllGlobals());

describe("stepUpHint", () => {
	it("is null for a request without a rule", () => {
		expect(stepUpHint({})).toBeNull();
	});

	it("names the factor and how fresh it must be", () => {
		expect(stepUpHint({ requiredAcr: "urn:theauth:acr:phishing-resistant", maxAuthAge: 120 })).toBe(
			"Needs a passkey within 2m",
		);
		expect(stepUpHint({ requiredAcr: "urn:theauth:acr:mfa", maxAuthAge: 45 })).toBe(
			"Needs a second factor within 45s",
		);
		expect(stepUpHint({ requiredAcr: "urn:theauth:acr:mfa" })).toBe("Needs a second factor");
		expect(stepUpHint({ maxAuthAge: 300 })).toBe("Needs a sign-in within 5m");
	});

	it("shows an unknown class as is", () => {
		expect(stepUpHint({ requiredAcr: "urn:example:gold" })).toBe("Needs urn:example:gold");
	});
});

describe("api client step-up errors", () => {
	it("keeps the STEP_UP_REQUIRED code from the admin API error body", async () => {
		const body = { error: { code: "STEP_UP_REQUIRED", message: "needs a stronger sign-in" } };
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response(JSON.stringify(body), { status: 401 })),
		);
		const res = await createApiClient("http://x").decideApproval("apr_1", "approve");
		expect(res).toEqual({
			success: false,
			error: { code: "STEP_UP_REQUIRED", message: "needs a stronger sign-in" },
		});
	});

	it("leaves other errors in their old shape", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response("{}", { status: 404, statusText: "Not Found" })),
		);
		const res = await createApiClient("http://x").getPendingApprovals();
		expect(res).toEqual({ success: false, error: { code: "HTTP_404", message: "Not Found" } });
	});
});

describe("quorumHint", () => {
	it("is null for a single approver", () => {
		expect(quorumHint({})).toBeNull();
		expect(quorumHint({ requiredApprovals: 1, approvalsReceived: 0 })).toBeNull();
	});

	it("shows progress toward the quorum", () => {
		expect(quorumHint({ requiredApprovals: 2, approvalsReceived: 1 })).toBe("1 of 2 approvals");
		expect(quorumHint({ requiredApprovals: 3 })).toBe("0 of 3 approvals");
	});
});
