/** The Python and Go clients list every decision code core can return. */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { applyRegion, CODES, goName, regions } from "../scripts/sdk-decision-codes.js";
import { DECISION_CODES } from "../src/permission/codes.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (file: string) => readFileSync(resolve(root, file), "utf8");

describe("client decision codes", () => {
	it("generator input is core's DECISION_CODES", () => {
		expect([...CODES]).toEqual(Object.values(DECISION_CODES));
	});

	it("names Go constants predictably", () => {
		expect(goName("ip_not_allowed")).toBe("IPNotAllowed");
		expect(goName("approval_step_up_insufficient")).toBe("ApprovalStepUpInsufficient");
	});

	it("every generated region in the clients is current", () => {
		for (const region of regions()) {
			const source = read(region.file);
			expect(applyRegion(source, region), `${region.file} is stale, run generate-openapi.ts`).toBe(
				source,
			);
		}
	});

	it("the Go constants hold exactly the core codes", () => {
		const go = read("sdks/go/decision.go");
		const found = [...go.matchAll(/^\tDecision\w+\s+DecisionCode = "([a-z_]+)"$/gm)].map(
			(m) => m[1],
		);
		expect(found).toEqual(Object.values(DECISION_CODES));
	});

	it("the Python literal and tuple hold exactly the core codes", () => {
		const py = read("sdks/python/theauth/codes.py");
		const lists = [
			...py.matchAll(/BEGIN GENERATED decision-codes (?:literal|tuple)\n([\s\S]*?)\s*# END/g),
		];
		expect(lists).toHaveLength(2);
		for (const m of lists) {
			const found = [...(m[1] ?? "").matchAll(/"([a-z_]+)"/g)].map((x) => x[1]);
			expect(found).toEqual(Object.values(DECISION_CODES));
		}
	});

	it("openapi.json lists the same codes", () => {
		const doc = JSON.parse(read("sdks/openapi.json")) as {
			components: { schemas: { DecisionCode: { enum: string[] } } };
		};
		expect(doc.components.schemas.DecisionCode.enum).toEqual(Object.values(DECISION_CODES));
	});
});
