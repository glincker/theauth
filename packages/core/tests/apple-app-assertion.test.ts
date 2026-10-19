/** Apple App Attest assertions over real device recordings (see tests/fixtures/apple-app-assertion.json for sources and licenses). */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyAppleAssertion } from "../src/device/attestation/apple-assertion.js";

interface Fx {
	assertion: string;
	clientData: string;
	appId: string;
	publicKey: string;
	previousCounter: number;
	counter: number;
}
const file = JSON.parse(
	readFileSync(new URL("./fixtures/apple-app-assertion.json", import.meta.url), "utf8"),
) as { assertions: Record<string, Fx> };
const FIXTURES = Object.entries(file.assertions);

describe("verifyAppleAssertion on real recordings", () => {
	for (const [name, fx] of FIXTURES) {
		it(`${name}: accepts and reads the counter`, async () => {
			const res = await verifyAppleAssertion(fx);
			expect(res).toMatchObject({ ok: true, counter: fx.counter });
		});

		it(`${name}: refuses a replay of the same counter`, async () => {
			const res = await verifyAppleAssertion({ ...fx, previousCounter: fx.counter });
			expect(res).toEqual({ ok: false, reason: "Assertion counter did not increase" });
		});

		it(`${name}: refuses other client data, app id and key`, async () => {
			expect(await verifyAppleAssertion({ ...fx, clientData: `${fx.clientData}x` })).toEqual({
				ok: false,
				reason: "Assertion signature is not valid",
			});
			expect(await verifyAppleAssertion({ ...fx, appId: "TEAM.other" })).toEqual({
				ok: false,
				reason: "Assertion is not for this App ID",
			});
			const other = FIXTURES.find(([n]) => n !== name)?.[1];
			if (!other) throw new Error("need two fixtures");
			expect(await verifyAppleAssertion({ ...fx, publicKey: other.publicKey })).toEqual({
				ok: false,
				reason: "Assertion signature is not valid",
			});
		});

		it(`${name}: refuses a flipped signature or authenticatorData byte`, async () => {
			const raw = Uint8Array.from(atob(fx.assertion), (c) => c.charCodeAt(0));
			// Last byte of the CBOR map is inside authenticatorData, a byte near the start is inside the signature.
			for (const at of [raw.length - 1, 20]) {
				const bad = raw.slice();
				bad[at] = (bad[at] as number) ^ 1;
				const res = await verifyAppleAssertion({
					...fx,
					assertion: btoa(String.fromCharCode(...bad)),
				});
				expect(res.ok).toBe(false);
			}
		});
	}

	it("accepts base64url input and raw bytes", async () => {
		const fx = FIXTURES[0]?.[1] as Fx;
		const url = fx.assertion.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		expect((await verifyAppleAssertion({ ...fx, assertion: url })).ok).toBe(true);
		const bytes = Uint8Array.from(atob(fx.assertion), (c) => c.charCodeAt(0));
		expect(
			(
				await verifyAppleAssertion({
					...fx,
					assertion: bytes,
					clientData: new TextEncoder().encode(fx.clientData),
				})
			).ok,
		).toBe(true);
	});

	it("refuses malformed input without throwing", async () => {
		const fx = FIXTURES[0]?.[1] as Fx;
		for (const bad of ["", "AAAA", "!!!!", btoa("not cbor at all")]) {
			expect((await verifyAppleAssertion({ ...fx, assertion: bad })).ok).toBe(false);
		}
		expect((await verifyAppleAssertion({ ...fx, publicKey: "AAAA" })).ok).toBe(false);
		expect((await verifyAppleAssertion({ ...fx, previousCounter: -1 })).ok).toBe(false);
		expect((await verifyAppleAssertion({ ...fx, previousCounter: 2 ** 32 })).ok).toBe(false);
	});
});
