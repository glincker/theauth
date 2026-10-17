/** External guard adapter: guardHook and composeBeforeAuthorize. */
import { describe, expect, it } from "vitest";
import type { ExternalGuard, GuardCheckInput } from "../src/hooks/guard.js";
import { composeBeforeAuthorize, guardHook } from "../src/hooks/guard.js";
import type { BeforeAuthorizeContext, TheAuthHooks } from "../src/hooks/lifecycle.js";
import { auditRows, delegateTo, makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

type Hook = NonNullable<TheAuthHooks["beforeAuthorize"]>;

const REQ = { action: "read", resource: "mcp:github:issues" };

function guard(check: ExternalGuard["check"], name = "test-guard"): ExternalGuard {
	return { name, check };
}

describe("guardHook", () => {
	it("allow passes through to permission evaluation", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: guardHook(guard(async () => ({ decision: "allow" }))) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		expect((await theauth.authorize(agent.id, REQ)).allowed).toBe(true);
		const denied = await theauth.authorize(agent.id, { action: "read", resource: "mcp:other:x" });
		expect(denied.allowed).toBe(false);
		expect(denied.code).not.toBe("hook_denied");
	});

	it("deny writes guard name and ruleId to the audit row", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: guardHook(
					guard(async () => ({ decision: "deny", reason: "nope", ruleId: "r-7" }), "hol"),
				),
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_denied", reason: "nope" });
		const row = (await auditRows(theauth, agent.id))[0];
		expect(row?.parameters).toMatchObject({
			theauthHook: { outcome: "deny", guard: "hol", ruleId: "r-7" },
		});
	});

	it("keeps a guard name the guard set itself", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: guardHook(
					guard(async () => ({ decision: "deny", guard: "inner-rules" }), "outer"),
				),
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		const row = (await auditRows(theauth, agent.id))[0];
		expect(row?.parameters).toMatchObject({ theauthHook: { guard: "inner-rules" } });
	});

	it("escalate requires approval", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: guardHook(guard(async () => ({ decision: "escalate" }))) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "approval_required" });
	});

	it("a throwing guard denies with hook_error and hides the message", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: guardHook(
					guard(async () => {
						throw new Error("secret upstream detail");
					}),
				),
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_error" });
		expect(result.reason).not.toContain("secret");
	});

	it("a guard that never answers is aborted and denied with hook_timeout", async () => {
		let aborted = false;
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: guardHook(
					guard(
						(_input, signal) =>
							new Promise<never>(() => {
								signal.addEventListener("abort", () => {
									aborted = true;
								});
							}),
					),
				),
			},
			hookSafety: { beforeAuthorize: { timeoutMs: 40 } },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "hook_timeout" });
		expect(aborted).toBe(true);
	});

	it("a malformed verdict denies", async () => {
		const bad = guard(async () => ({ verdict: "yes" }) as never);
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: guardHook(bad) } });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		expect(await theauth.authorize(agent.id, REQ)).toMatchObject({
			allowed: false,
			code: "hook_error",
		});
	});

	it("receives the chain, request and arguments, and no token", async () => {
		const seen: GuardCheckInput[] = [];
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: guardHook(
					guard(async (input) => {
						seen.push(input);
						return { decision: "allow" };
					}),
				),
			},
		});
		const root = await newAgent(theauth, "root", READ_GITHUB);
		const child = await newAgent(theauth, "child", []);
		await delegateTo(theauth, root.id, child.id);

		const result = await theauth.authorize(child.id, { ...REQ, arguments: { n: 2 } });
		expect(result.allowed).toBe(true);
		const input = seen[0];
		expect(input).toMatchObject({
			agentId: child.id,
			action: "read",
			resource: "mcp:github:issues",
			arguments: { n: 2 },
			source: "authorize",
			dryRun: false,
		});
		expect(input?.agent).toMatchObject({ id: child.id, ownerId: "user-1", name: "child" });
		expect(input?.agent).not.toHaveProperty("token");
		expect(input?.delegation.path).toEqual([root.id, child.id]);
		expect(input?.delegation.rootOwnerId).toBe("user-1");
		expect(JSON.stringify(input)).not.toContain("token");
	});

	it("can deny based on the delegation chain", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: guardHook(
					guard(async (input) =>
						input.delegation.path.length > 1
							? { decision: "deny", reason: "delegated calls blocked", ruleId: "no-delegation" }
							: { decision: "allow" },
					),
				),
			},
		});
		const root = await newAgent(theauth, "root", READ_GITHUB);
		const child = await newAgent(theauth, "child", []);
		await delegateTo(theauth, root.id, child.id);

		expect((await theauth.authorize(root.id, REQ)).allowed).toBe(true);
		const result = await theauth.authorize(child.id, REQ);
		expect(result).toMatchObject({
			allowed: false,
			code: "hook_denied",
			reason: "delegated calls blocked",
		});
	});

	it("passes dryRun and the aborting signal through the context", async () => {
		const ctx = {
			agentId: "a",
			action: "read",
			resource: "r",
			agent: { id: "a", ownerId: "u", name: "n", type: "autonomous" },
			delegation: { path: ["a"], links: [], inbound: [] },
			source: "explain",
			dryRun: true,
			context: { ip: "10.0.0.1" },
			signal: new AbortController().signal,
		} as unknown as BeforeAuthorizeContext;
		let got: GuardCheckInput | undefined;
		await guardHook(
			guard(async (input) => {
				got = input;
				return { decision: "allow" };
			}),
		)(ctx);
		expect(got).toMatchObject({ dryRun: true, source: "explain", ip: "10.0.0.1" });
	});
});

describe("composeBeforeAuthorize", () => {
	const ctx = { signal: new AbortController().signal } as BeforeAuthorizeContext;

	function tracked(log: string[], name: string, result: Awaited<ReturnType<Hook>>): Hook {
		return async () => {
			log.push(name);
			return result;
		};
	}

	it("runs in order and short-circuits on the first deny", async () => {
		const log: string[] = [];
		const hook = composeBeforeAuthorize(
			tracked(log, "a", { decision: "allow" }),
			tracked(log, "b", { decision: "deny", reason: "b says no", guard: "b" }),
			tracked(log, "c", { decision: "allow" }),
		);
		expect(await hook(ctx)).toMatchObject({ decision: "deny", reason: "b says no", guard: "b" });
		expect(log).toEqual(["a", "b"]);
	});

	it("escalate beats allow, deny beats escalate", async () => {
		const log: string[] = [];
		const esc = await composeBeforeAuthorize(
			tracked(log, "a", { decision: "escalate", reason: "ask" }),
			tracked(log, "b", { decision: "allow" }),
		)(ctx);
		expect(esc).toMatchObject({ decision: "escalate", reason: "ask" });
		expect(log).toEqual(["a", "b"]);

		const deny = await composeBeforeAuthorize(
			tracked([], "a", { decision: "escalate" }),
			tracked([], "b", { allow: false, reason: "legacy no" }),
		)(ctx);
		expect(deny).toMatchObject({ decision: "deny", reason: "legacy no" });
	});

	it("allows when every hook allows or returns undefined", async () => {
		const hook = composeBeforeAuthorize(
			tracked([], "a", undefined),
			tracked([], "b", { allow: true }),
		);
		expect(await hook(ctx)).toEqual({ decision: "allow" });
		expect(await composeBeforeAuthorize()(ctx)).toEqual({ decision: "allow" });
	});

	it("propagates a throw and rejects a malformed verdict", async () => {
		const boom: Hook = async () => {
			throw new Error("boom");
		};
		await expect(composeBeforeAuthorize(boom)(ctx)).rejects.toThrow("boom");
		const bad: Hook = async () => ({ nope: 1 }) as never;
		await expect(composeBeforeAuthorize(bad)(ctx)).rejects.toThrow("malformed");
	});

	it("denies end to end when one composed guard throws", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: composeBeforeAuthorize(
					guardHook(guard(async () => ({ decision: "allow" }))),
					async () => {
						throw new Error("down");
					},
				),
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		expect(await theauth.authorize(agent.id, REQ)).toMatchObject({
			allowed: false,
			code: "hook_error",
		});
	});
});
