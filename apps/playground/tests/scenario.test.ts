import { beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_POLICY, PRESETS } from "../src/presets.js";
import type { KeyMaterial } from "../src/scenario.js";
import { newKey, parsePolicy, runScenario } from "../src/scenario.js";
import { buildSnippet } from "../src/snippet.js";

let key: KeyMaterial;
beforeAll(async () => {
	key = await newKey();
});

describe("playground scenarios", () => {
	for (const preset of PRESETS) {
		it(`${preset.id} -> ${preset.expected}, with a verifiable receipt`, async () => {
			const r = await runScenario(preset.call, DEFAULT_POLICY, key);
			expect(r.outcome).toBe(preset.expected);
			expect(r.toolRan).toBe(preset.expected === "allow");
			expect(r.receiptError).toBeUndefined();
			expect(r.verified).toBe(true);
			expect(r.receipt?.proof.treeSize).toBe(r.receipt?.checkpoint.size);
		}, 30_000);
	}

	it("labels the poisoned recipient and blocks on the taint rule", async () => {
		const preset = PRESETS[0];
		if (!preset) throw new Error("missing preset");
		const r = await runScenario(preset.call, DEFAULT_POLICY, key);
		expect(r.labels.recipient).toEqual(["untrusted_web"]);
		expect(r.code).toBe("POLICY_TAINT_VIOLATION");
	}, 30_000);

	it("rejects a receipt whose root hash was changed", async () => {
		const { verifyReceipt } = await import("@glinr/theauth/browser");
		const preset = PRESETS[1];
		if (!preset) throw new Error("missing preset");
		const r = await runScenario(preset.call, DEFAULT_POLICY, key);
		if (!r.receipt) throw new Error("no receipt");
		const bad = structuredClone(r.receipt);
		bad.checkpoint.rootHash = `${bad.checkpoint.rootHash[0] === "0" ? "1" : "0"}${bad.checkpoint.rootHash.slice(1)}`;
		expect((await verifyReceipt(bad, key.publicKey)).valid).toBe(false);
	}, 30_000);

	it("parses policy JSON and emits a snippet with real API names", () => {
		expect("error" in parsePolicy("{")).toBe(true);
		const preset = PRESETS[0];
		if (!preset) throw new Error("missing preset");
		const code = buildSnippet(preset.call, DEFAULT_POLICY);
		for (const name of ["guardTool", "tainted", "createTheAuth", "ToolDeniedError"]) {
			expect(code).toContain(name);
		}
	});
});
