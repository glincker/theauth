import { afterEach, describe, expect, it, vi } from "vitest";
import type { TheAuthHooks } from "../src/hooks/lifecycle.js";
import { runWithTimeout } from "../src/hooks/run.js";
import type { EnvReader } from "../src/hooks/safety.js";
import { HookBlockedError, HookTimeoutError, resolveHookSafety } from "../src/hooks/safety.js";
import { auditRows, makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

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
		expect(await pending).toEqual({ ok: false, timedOut: true, error: undefined });
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

type BeforeAuthorizeHook = NonNullable<TheAuthHooks["beforeAuthorize"]>;
const REQ = { action: "read", resource: "mcp:github:issues" };
const never = () => new Promise<never>(() => {});

describe("hook safety wiring: beforeAuthorize", () => {
	it("a hook that never resolves is denied hook_timeout, audited, and reported", async () => {
		const onHookError = vi.fn();
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { beforeAuthorize: { timeoutMs: 30 }, onHookError },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);

		const startedAt = Date.now();
		const result = await theauth.authorize(agent.id, REQ);

		expect(Date.now() - startedAt).toBeLessThan(1000);
		expect(result).toMatchObject({ allowed: false, code: "hook_timeout" });
		expect(result.reason).toBe("beforeAuthorize hook timed out after 30ms");
		expect(onHookError).toHaveBeenCalledWith(
			expect.objectContaining({ hook: "beforeAuthorize", kind: "timeout", agentId: agent.id }),
		);
		const rows = await auditRows(theauth, agent.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.decisionCode).toBe("hook_timeout");
	});

	it("the signal is aborted when the timeout fires", async () => {
		let signal: AbortSignal | undefined;
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: (ctx) => {
					signal = ctx.signal;
					return never();
				},
			},
			hookSafety: { timeoutMs: 20 },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		expect(signal?.aborted).toBe(true);
	});

	it("a throwing hook is denied hook_error and the message is not leaked", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => {
					throw new Error("secret-db-password");
				},
			},
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_error" });
		expect(result.reason).not.toContain("secret-db-password");
		const rows = await auditRows(theauth, agent.id);
		expect(JSON.stringify(rows[0])).not.toContain("secret-db-password");
	});

	it("onError throw rejects with the original error", async () => {
		const boom = new Error("boom");
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => {
					throw boom;
				},
			},
			hookSafety: { onError: "throw" },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		await expect(theauth.authorize(agent.id, REQ)).rejects.toBe(boom);
	});

	it("onTimeout throw rejects with HookTimeoutError", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 20, onTimeout: "throw" },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		await expect(theauth.authorize(agent.id, REQ)).rejects.toBeInstanceOf(HookTimeoutError);
	});

	it("onTimeout allow proceeds and marks the audit row fail_open", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 20, onTimeout: "allow" },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: true, code: "allowed" });
		const rows = await auditRows(theauth, agent.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.parameters).toMatchObject({
			theauthHook: { outcome: "fail_open", failure: "hook_timeout" },
		});
	});

	it("fail open still denies when permissions deny, and the denial row carries fail_open", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 20, onTimeout: "allow" },
		});
		const agent = await newAgent(theauth, "t", []);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "no_permission" });
		const rows = await auditRows(theauth, agent.id);
		expect(rows[0]?.parameters).toMatchObject({ theauthHook: { outcome: "fail_open" } });
	});

	it.each([
		[{}],
		["yes"],
		[42],
		[{ decision: "maybe" }],
	])("malformed verdict %j is denied hook_error", async (verdict) => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: (async () => verdict) as unknown as BeforeAuthorizeHook },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_error" });
	});

	it("an onHookError that throws does not change the result", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: {
				timeoutMs: 20,
				onHookError: () => {
					throw new Error("reporter down");
				},
			},
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_timeout" });
	});

	it("authorizeByToken fails closed the same way", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 20 },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		const result = await theauth.authorizeByToken(agent.token, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_timeout" });
	});

	it("policy.evaluate fails closed: timeout is effect deny, code hook_timeout", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 20 },
		});
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		const d = await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...REQ });
		expect(d).toMatchObject({ effect: "deny", code: "hook_timeout" });
		const second = await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...REQ });
		expect(second.cacheHit).toBe(false);
	});

	it("a fast hook is unaffected and leaves no pending timer", async () => {
		vi.useFakeTimers();
		try {
			const res = await runWithTimeout(async () => "ok", 1000);
			expect(res).toEqual({ ok: true, value: "ok" });
			expect(vi.getTimerCount()).toBe(0);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("hook safety wiring: beforeAgentCreate", () => {
	const input = { ownerId: "user-1", name: "n", type: "autonomous" as const, permissions: [] };

	it("a timeout throws HookTimeoutError and creates no agent", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAgentCreate: never },
			hookSafety: { timeoutMs: 20 },
		});
		await expect(theauth.agent.create(input)).rejects.toBeInstanceOf(HookTimeoutError);
		expect(await theauth.agent.list({ userId: "user-1" })).toHaveLength(0);
	});

	it("a throw re-throws the original error by default", async () => {
		const boom = new Error("boom");
		const theauth = await makeTheAuth({
			hooks: {
				beforeAgentCreate: async () => {
					throw boom;
				},
			},
		});
		await expect(theauth.agent.create(input)).rejects.toBe(boom);
	});

	it("onError deny throws HookBlockedError without the original message", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAgentCreate: async () => {
					throw new Error("secret");
				},
			},
			hookSafety: { beforeAgentCreate: { onError: "deny" } },
		});
		const err = await theauth.agent.create(input).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(HookBlockedError);
		expect((err as HookBlockedError).code).toBe("hook_error");
		expect((err as Error).message).not.toContain("secret");
	});

	it("onTimeout allow lets creation proceed", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAgentCreate: never },
			hookSafety: { timeoutMs: 20, onTimeout: "allow" },
		});
		const agent = await theauth.agent.create(input);
		expect(agent.id).toBeTruthy();
	});

	it("a block verdict still throws with its reason", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAgentCreate: async () => ({ allow: false, reason: "sandbox" }) },
		});
		await expect(theauth.agent.create(input)).rejects.toThrow("sandbox");
	});
});

describe("runWithTimeout synchronous throw", () => {
	it("fails closed with the thrown error and does not leave the timer running", async () => {
		vi.useFakeTimers();
		try {
			const boom = new Error("sync boom");
			const res = await runWithTimeout(() => {
				throw boom;
			}, 1000);
			expect(res).toEqual({ ok: false, timedOut: false, error: boom });
			expect(vi.getTimerCount()).toBe(0);
		} finally {
			vi.useRealTimers();
		}
	});
});
