import { describe, expect, it } from "vitest";
import { runAccountabilityLoop } from "../src/loop.js";

describe("agent accountability loop", () => {
	it("denies, escalates, approves, audits and revokes", async () => {
		const out = await runAccountabilityLoop({ step: () => undefined, note: () => undefined });
		expect(out.unauthorizedDenied).toBe(true);
		expect(out.approvalRequired).toBe(true);
		expect(out.approvalUnlocked).toBe(true);
		expect(out.replayDenied).toBe(true);
		expect(out.chainOk).toBe(true);
		expect(out.chainChecked).toBeGreaterThan(0);
		expect(out.revokedRejected).toBe(true);
	});
});
