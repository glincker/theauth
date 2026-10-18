/** Invalid expiry dates and tolerances are rejected instead of silently disabling a check. */
import { describe, expect, it } from "vitest";
import {
	GUARD_MAX_RESPONSE_BYTES,
	httpGuard,
	signGuardResponse,
	verifyGuardRequest,
	verifyGuardResponse,
} from "../src/hooks/http-guard.js";
import { ValidationError } from "../src/validation.js";
import { future, makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

const BAD_DATES: [string, unknown][] = [
	["Invalid Date", new Date("not a date")],
	["NaN", Number.NaN],
	["Infinity", Number.POSITIVE_INFINITY],
	["a string", "2030-01-01"],
	["null", null],
];

describe("expiresAt validation", () => {
	for (const [label, value] of BAD_DATES) {
		it(`agent.create rejects ${label}`, async () => {
			const theauth = await makeTheAuth({});
			await expect(
				theauth.agent.create({
					ownerId: "user-1",
					name: "x",
					type: "autonomous",
					permissions: READ_GITHUB,
					expiresAt: value as Date,
				}),
			).rejects.toBeInstanceOf(ValidationError);
		});

		it(`agent.update rejects ${label} and keeps the old expiry`, async () => {
			const theauth = await makeTheAuth({});
			const agent = await newAgent(theauth, "a", READ_GITHUB);
			await expect(
				theauth.agent.update(agent.id, { expiresAt: value as Date }),
			).rejects.toBeInstanceOf(ValidationError);
		});

		it(`delegate rejects ${label}`, async () => {
			const theauth = await makeTheAuth({});
			const parent = await newAgent(theauth, "p", READ_GITHUB);
			const kid = await newAgent(theauth, "c", []);
			await expect(
				theauth.delegate({
					fromAgent: parent.id,
					toAgent: kid.id,
					permissions: READ_GITHUB,
					expiresAt: value as Date,
				}),
			).rejects.toMatchObject({ code: "INVALID_EXPIRES_AT" });
		});
	}

	it("a valid date still works", async () => {
		const theauth = await makeTheAuth({});
		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "x",
			type: "autonomous",
			permissions: READ_GITHUB,
			expiresAt: future(),
		});
		expect(agent.expiresAt).toBeInstanceOf(Date);
	});
});

describe("guard toleranceSec validation", () => {
	for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY, 1e9]) {
		it(`httpGuard rejects ${bad} at config time`, () => {
			expect(() =>
				httpGuard({
					name: "v",
					url: "https://vendor.example/check",
					secret: "s",
					toleranceSec: bad,
				}),
			).toThrow(/toleranceSec/);
		});
	}

	it("verifyGuardResponse fails closed on NaN tolerance", async () => {
		const body = '{"decision":"allow"}';
		const headers = await signGuardResponse("s", { requestId: "rid", body, timestamp: 1 });
		const r = await verifyGuardResponse("s", {
			requestId: "rid",
			headers,
			body,
			toleranceSec: Number.NaN,
		});
		expect(r.ok).toBe(false);
	});

	it("verifyGuardRequest fails closed on NaN tolerance", async () => {
		const r = await verifyGuardRequest("s", { "x-theauth-timestamp": "1" }, "{}", {
			toleranceSec: Number.NaN,
		});
		expect(r.ok).toBe(false);
	});
});

describe("guard response size cap", () => {
	function streamOf(chunks: number, size: number, state: { pulled: number; cancelled: boolean }) {
		return new ReadableStream<Uint8Array>({
			pull(controller) {
				if (state.pulled >= chunks) {
					controller.close();
					return;
				}
				state.pulled += 1;
				controller.enqueue(new Uint8Array(size).fill(97));
			},
			cancel() {
				state.cancelled = true;
			},
		});
	}

	it("aborts the stream once the cap is exceeded", async () => {
		const state = { pulled: 0, cancelled: false };
		const guard = httpGuard({
			name: "v",
			url: "https://vendor.example/check",
			secret: "s",
			requireSignedResponse: false,
			fetch: async () => new Response(streamOf(10000, 16384, state), { status: 200 }),
		});
		await expect(
			guard.check({ agentId: "a", action: "r", resource: "x" } as never, undefined),
		).rejects.toThrow(/too large/);
		expect(state.cancelled).toBe(true);
		// Cap is 64 KiB, so at most a handful of 16 KiB chunks are ever pulled (with stream prefetch).
		expect(state.pulled * 16384).toBeLessThan(GUARD_MAX_RESPONSE_BYTES * 4);
	});
});
