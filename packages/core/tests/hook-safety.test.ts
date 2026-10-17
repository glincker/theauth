import { afterEach, describe, expect, it, vi } from "vitest";
import { runWithTimeout } from "../src/hooks/run.js";
import type { EnvReader } from "../src/hooks/safety.js";
import { resolveHookSafety } from "../src/hooks/safety.js";

const envOf =
	(vars: Record<string, string>): EnvReader =>
	(name) =>
		vars[name];

describe("resolveHookSafety", () => {
	it("applies built-in defaults", () => {
		const r = resolveHookSafety(undefined, envOf({}));
		expect(r.beforeAuthorize).toEqual({ timeoutMs: 2000, onTimeout: "deny", onError: "deny" });
		expect(r.beforeAgentCreate).toEqual({ timeoutMs: 2000, onTimeout: "throw", onError: "throw" });
	});

	it("per-hook beats top-level beats env beats default", () => {
		const env = envOf({
			THEAUTH_HOOK_TIMEOUT_MS: "100",
			THEAUTH_HOOK_ON_TIMEOUT: "allow",
			THEAUTH_HOOK_ON_ERROR: "allow",
		});
		const envOnly = resolveHookSafety(undefined, env);
		expect(envOnly.beforeAuthorize).toEqual({
			timeoutMs: 100,
			onTimeout: "allow",
			onError: "allow",
		});

		const top = resolveHookSafety({ timeoutMs: 200, onTimeout: "throw" }, env);
		expect(top.beforeAuthorize).toEqual({ timeoutMs: 200, onTimeout: "throw", onError: "allow" });

		const per = resolveHookSafety(
			{
				timeoutMs: 200,
				onTimeout: "throw",
				beforeAuthorize: { timeoutMs: 300, onTimeout: "deny" },
			},
			env,
		);
		expect(per.beforeAuthorize).toEqual({ timeoutMs: 300, onTimeout: "deny", onError: "allow" });
		expect(per.beforeAgentCreate.timeoutMs).toBe(200);
	});

	it("ignores bad env values, honors 0, clamps range", () => {
		const bad = resolveHookSafety(
			undefined,
			envOf({ THEAUTH_HOOK_TIMEOUT_MS: "abc", THEAUTH_HOOK_ON_TIMEOUT: "maybe" }),
		);
		expect(bad.beforeAuthorize.timeoutMs).toBe(2000);
		expect(bad.beforeAuthorize.onTimeout).toBe("deny");

		expect(resolveHookSafety({ timeoutMs: 0 }, envOf({})).beforeAuthorize.timeoutMs).toBe(0);
		expect(resolveHookSafety({ timeoutMs: 999999 }, envOf({})).beforeAuthorize.timeoutMs).toBe(
			60000,
		);
		expect(resolveHookSafety({ timeoutMs: -5 }, envOf({})).beforeAuthorize.timeoutMs).toBe(0);
	});
});

describe("runWithTimeout", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("resolves and clears the timer", async () => {
		vi.useFakeTimers();
		const res = await runWithTimeout(async () => 42, 1000);
		expect(res).toEqual({ ok: true, value: 42 });
		expect(vi.getTimerCount()).toBe(0);
	});

	it("reports a rejection and clears the timer", async () => {
		vi.useFakeTimers();
		const boom = new Error("boom");
		const res = await runWithTimeout(async () => {
			throw boom;
		}, 1000);
		expect(res).toEqual({ ok: false, timedOut: false, error: boom });
		expect(vi.getTimerCount()).toBe(0);
	});

	it("times out and aborts the signal", async () => {
		vi.useFakeTimers();
		let captured: AbortSignal | undefined;
		const pending = runWithTimeout((signal) => {
			captured = signal;
			return new Promise<never>(() => undefined);
		}, 500);
		await vi.advanceTimersByTimeAsync(500);
		const res = await pending;
		expect(res).toMatchObject({ ok: false, timedOut: true });
		expect(captured?.aborted).toBe(true);
		expect(vi.getTimerCount()).toBe(0);
	});

	it("ignores a late rejection after timeout", async () => {
		vi.useFakeTimers();
		let rejectLate: (e: Error) => void = () => undefined;
		const pending = runWithTimeout(
			() =>
				new Promise<never>((_, reject) => {
					rejectLate = reject;
				}),
			100,
		);
		await vi.advanceTimersByTimeAsync(100);
		await pending;
		rejectLate(new Error("late"));
		await vi.advanceTimersByTimeAsync(0);
	});

	it("timeoutMs 0 disables the timer", async () => {
		vi.useFakeTimers();
		const res = await runWithTimeout(async () => "ok", 0);
		expect(res).toEqual({ ok: true, value: "ok" });
		expect(vi.getTimerCount()).toBe(0);
	});
});
