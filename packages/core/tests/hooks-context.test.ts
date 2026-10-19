/** beforeAuthorize context: resolved agent, delegation chain, source, and coverage of every entry point. */
import { describe, expect, it, vi } from "vitest";
import type { BeforeAuthorizeContext, TheAuthHooks } from "../src/hooks/lifecycle.js";
import {
	auditRows,
	delegateTo,
	expireChain,
	makeTheAuth,
	newAgent,
	READ_GITHUB,
} from "./hook-test-utils.js";

const lineage = vi.hoisted(() => ({ calls: 0 }));
vi.mock("../src/delegation/lineage.js", async (importOriginal) => {
	const original = await importOriginal<typeof import("../src/delegation/lineage.js")>();
	return {
		...original,
		resolveHookChain: (...args: Parameters<typeof original.resolveHookChain>) => {
			lineage.calls++;
			return original.resolveHookChain(...args);
		},
	};
});

type Hook = NonNullable<TheAuthHooks["beforeAuthorize"]>;

function recorder(verdict?: Awaited<ReturnType<Hook>>) {
	const seen: BeforeAuthorizeContext[] = [];
	const hook: Hook = async (ctx) => {
		seen.push(ctx);
		return verdict;
	};
	return { seen, hook };
}

const REQ = { action: "read", resource: "mcp:github:issues" };

describe("beforeAuthorize context", () => {
	it("gives an undelegated agent a single-element path and no links", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const agent = await newAgent(theauth, "solo", READ_GITHUB);

		const result = await theauth.authorize(agent.id, { ...REQ, arguments: { n: 1 } });

		expect(result.allowed).toBe(true);
		const ctx = seen[0];
		expect(ctx?.agent.ownerId).toBe("user-1");
		expect(ctx?.agent.name).toBe("solo");
		expect(ctx?.agent).not.toHaveProperty("token");
		expect(ctx?.source).toBe("authorize");
		expect(ctx?.dryRun).toBe(false);
		expect(ctx?.arguments).toEqual({ n: 1 });
		expect(ctx?.signal).toBeInstanceOf(AbortSignal);
		expect(ctx?.delegation.path).toEqual([agent.id]);
		expect(ctx?.delegation.links).toEqual([]);
		expect(ctx?.delegation.rootOwnerId).toBe("user-1");
	});

	it("passes request context (ip, userAgent)", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ, { ip: "10.0.0.1", userAgent: "ua" });
		expect(seen[0]?.context).toEqual({ ip: "10.0.0.1", userAgent: "ua" });
	});

	it("A -> B -> C: path root first, links carry permissions and constraints", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const a = await newAgent(theauth, "a", [
			{ resource: "mcp:github:*", actions: ["read", "write"] },
		]);
		const b = await newAgent(theauth, "b", [], "user-2");
		const c = await newAgent(theauth, "c", [], "user-2");
		const ab = await delegateTo(theauth, a.id, b.id, [
			{ resource: "mcp:github:*", actions: ["read"], constraints: { maxCallsPerHour: 50 } },
		]);
		const bc = await delegateTo(theauth, b.id, c.id, [
			{ resource: "mcp:github:issues", actions: ["read"] },
		]);

		const result = await theauth.authorize(c.id, REQ);

		expect(result.allowed).toBe(true);
		const chain = seen[0]?.delegation;
		expect(chain?.path).toEqual([a.id, b.id, c.id]);
		expect(chain?.rootOwnerId).toBe("user-1");
		expect(chain?.links.map((l) => l.delegationId)).toEqual([ab.id, bc.id]);
		expect(chain?.links[0]?.fromAgent).toBe(a.id);
		expect(chain?.links[0]?.toAgent).toBe(b.id);
		expect(chain?.links[0]?.permissions[0]?.constraints?.maxCallsPerHour).toBe(50);
		expect(chain?.links[1]?.permissions[0]?.resource).toBe("mcp:github:issues");
		expect(chain?.links[1]?.depth).toBeGreaterThan(chain?.links[0]?.depth ?? 99);
		expect(chain?.links[0]?.expiresAt).toBeInstanceOf(Date);
		expect(chain?.inbound.map((l) => l.delegationId)).toEqual([bc.id]);
	});

	it("two inbound grants: links follows the oldest, inbound has both", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const a = await newAgent(theauth, "a", READ_GITHUB);
		const d = await newAgent(theauth, "d", READ_GITHUB, "user-2");
		const b = await newAgent(theauth, "b", []);
		const c = await newAgent(theauth, "c", []);
		await delegateTo(theauth, a.id, b.id);
		const bc = await delegateTo(theauth, b.id, c.id);
		const dc = await delegateTo(theauth, d.id, c.id);

		await theauth.authorize(c.id, REQ);

		const chain = seen[0]?.delegation;
		expect(chain?.path).toEqual([a.id, b.id, c.id]);
		expect(chain?.links).toHaveLength(2);
		expect(chain?.inbound.map((l) => l.delegationId)).toEqual([bc.id, dc.id]);
		expect(chain?.rootOwnerId).toBe("user-1");
	});

	it("revoked and expired links are absent from links and inbound", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const a = await newAgent(theauth, "a", READ_GITHUB);
		const b = await newAgent(theauth, "b", []);
		const c = await newAgent(theauth, "c", []);
		const ab = await delegateTo(theauth, a.id, b.id);
		const bc = await delegateTo(theauth, b.id, c.id);

		await theauth.delegation.revoke(ab.id);
		await theauth.authorize(b.id, REQ);
		expect(seen.at(-1)?.delegation.links).toEqual([]);
		expect(seen.at(-1)?.delegation.inbound).toEqual([]);

		await expireChain(theauth, bc.id);
		await theauth.authorize(c.id, REQ);
		expect(seen.at(-1)?.delegation.path).toEqual([c.id]);
		expect(seen.at(-1)?.delegation.inbound).toEqual([]);
	});
});

describe("when the hook is not called", () => {
	it("unknown agent id, revoked agent and invalid token never reach the hook", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const agent = await newAgent(theauth, "gone", READ_GITHUB);

		const unknown = await theauth.authorize("no-such-agent", REQ);
		expect(unknown.code).toBe("agent_not_found");
		const badToken = await theauth.authorizeByToken("not-a-token", REQ);
		expect(badToken.code).toBe("invalid_token");
		await theauth.agent.revoke(agent.id);
		const revoked = await theauth.authorize(agent.id, REQ);
		expect(revoked.code).toBe("agent_revoked");
		const revokedToken = await theauth.authorizeByToken(agent.token, REQ);
		expect(revokedToken.allowed).toBe(false);

		expect(seen).toHaveLength(0);
	});

	it("loads no lineage when no hook is configured", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "plain", READ_GITHUB);
		const before = lineage.calls;
		await theauth.authorize(agent.id, REQ);
		await theauth.authorizeByToken(agent.token, REQ);
		await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...REQ });
		expect(lineage.calls).toBe(before);
	});
});

describe("authorizeByToken", () => {
	it("calls the hook with source authorizeByToken; a block is hook_denied", async () => {
		const { seen, hook } = recorder({ allow: false, reason: "nope" });
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const agent = await newAgent(theauth, "tok", READ_GITHUB);

		const result = await theauth.authorizeByToken(agent.token, REQ);

		expect(seen[0]?.source).toBe("authorizeByToken");
		expect(result).toMatchObject({ allowed: false, code: "hook_denied", reason: "nope" });
		expect(result.auditId).not.toBe("");
	});

	it("honors delegated permissions like authorize does", async () => {
		const theauth = await makeTheAuth({});
		const a = await newAgent(theauth, "a", READ_GITHUB);
		const b = await newAgent(theauth, "b", []);
		expect((await theauth.authorizeByToken(b.token, REQ)).allowed).toBe(false);
		await delegateTo(theauth, a.id, b.id);
		expect((await theauth.authorizeByToken(b.token, REQ)).allowed).toBe(true);
		expect((await theauth.authorize(b.id, REQ)).allowed).toBe(true);
	});

	it("fires afterAuthorize and onViolation with the source", async () => {
		const afterAuthorize = vi.fn().mockResolvedValue(undefined);
		const onViolation = vi.fn().mockResolvedValue(undefined);
		const theauth = await makeTheAuth({ hooks: { afterAuthorize, onViolation } });
		const agent = await newAgent(theauth, "t", READ_GITHUB);
		await theauth.authorizeByToken(agent.token, { action: "delete", resource: "mcp:github:x" });
		await new Promise((r) => setTimeout(r, 10));
		expect(afterAuthorize).toHaveBeenCalledWith(
			expect.objectContaining({ source: "authorizeByToken" }),
		);
		expect(onViolation).toHaveBeenCalledWith(
			expect.objectContaining({ source: "authorizeByToken", code: "no_permission" }),
		);
	});
});

describe("policy.evaluate", () => {
	it("calls the hook for an agent subject, not for a user-only subject", async () => {
		const { seen, hook } = recorder();
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: hook } });
		const agent = await newAgent(theauth, "p", READ_GITHUB);

		await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...REQ });
		expect(seen).toHaveLength(1);
		expect(seen[0]?.source).toBe("policy.evaluate");
		expect(seen[0]?.agent.id).toBe(agent.id);

		await theauth.policy.evaluate({ subject: { userId: "user-1" }, ...REQ });
		expect(seen).toHaveLength(1);
	});

	it("a deny is hook_denied, never cached; the hook is asked again", async () => {
		let deny = true;
		const calls: string[] = [];
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => {
					calls.push("x");
					return deny ? { allow: false, reason: "blocked" } : undefined;
				},
			},
		});
		const agent = await newAgent(theauth, "p", READ_GITHUB);
		const input = { subject: { agentId: agent.id }, ...REQ };

		const first = await theauth.policy.evaluate(input);
		expect(first).toMatchObject({ effect: "deny", code: "hook_denied", reason: "blocked" });
		const second = await theauth.policy.evaluate(input);
		expect(second.code).toBe("hook_denied");
		expect(calls).toHaveLength(2);

		deny = false;
		const third = await theauth.policy.evaluate(input);
		expect(third.allowed).toBe(true);
		expect(third.cacheHit).toBe(false);
	});

	it("a cached permit still asks the hook, and a later deny wins over the cache", async () => {
		let deny = false;
		let calls = 0;
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => {
					calls++;
					return deny ? { decision: "deny", reason: "late" } : undefined;
				},
			},
		});
		const agent = await newAgent(theauth, "p", READ_GITHUB);
		const input = { subject: { agentId: agent.id }, ...REQ };

		expect((await theauth.policy.evaluate(input)).allowed).toBe(true);
		const hit = await theauth.policy.evaluate(input);
		expect(hit.cacheHit).toBe(true);
		expect(calls).toBe(2);

		deny = true;
		const blocked = await theauth.policy.evaluate(input);
		expect(blocked).toMatchObject({ allowed: false, code: "hook_denied", cacheHit: false });
	});

	it("principal of a hook block carries the delegation chain", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ allow: false }) },
		});
		const a = await newAgent(theauth, "a", READ_GITHUB);
		const b = await newAgent(theauth, "b", [], "user-2");
		await delegateTo(theauth, a.id, b.id);
		const d = await theauth.policy.evaluate({ subject: { agentId: b.id }, ...REQ });
		expect(d.principal).toEqual({
			actorId: b.id,
			subjectId: "user-1",
			delegationChain: [a.id, b.id],
		});
	});
});

describe("escalate verdict", () => {
	const escalate = async () => ({ decision: "escalate" as const, reason: "needs a human" });

	it("authorize is denied with approval_required and an escalated audit row", async () => {
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: escalate } });
		const agent = await newAgent(theauth, "e", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({
			allowed: false,
			code: "approval_required",
			reason: "needs a human",
		});
		const rows = await auditRows(theauth, agent.id);
		expect(rows.map((r) => r.result)).toEqual(["escalated"]);
	});

	it("policy.evaluate escalates with tier hook", async () => {
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: escalate } });
		const agent = await newAgent(theauth, "e", READ_GITHUB);
		const d = await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...REQ });
		expect(d.decision).toBe("escalate");
		expect(d.escalation).toMatchObject({ tier: "hook", requirement: "approval" });
	});

	it("a valid approvalId is spent once, then normal permission checks decide", async () => {
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: escalate } });
		const agent = await newAgent(theauth, "e", READ_GITHUB);
		const req = await theauth.approval.request({
			agentId: agent.id,
			userId: "user-1",
			...REQ,
		});
		await theauth.approval.approve(req.id, "human-1");
		const input = { subject: { agentId: agent.id }, ...REQ, approvalId: req.id };

		const allowed = await theauth.policy.evaluate(input);
		expect(allowed.allowed).toBe(true);
		const replay = await theauth.policy.evaluate(input);
		expect(replay).toMatchObject({ allowed: false, code: "approval_already_used" });
	});

	it("an approval never grants more than the agent's own permissions", async () => {
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: escalate } });
		const agent = await newAgent(theauth, "e", []);
		const req = await theauth.approval.request({
			agentId: agent.id,
			userId: "user-1",
			...REQ,
		});
		await theauth.approval.approve(req.id, "human-1");
		const d = await theauth.policy.evaluate({
			subject: { agentId: agent.id },
			...REQ,
			approvalId: req.id,
		});
		expect(d.allowed).toBe(false);
	});
});

describe("verdict shapes", () => {
	it("legacy { allow: false, reason } keeps its reason", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ allow: false, reason: "x" }) },
		});
		const agent = await newAgent(theauth, "l", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, reason: "x", code: "hook_denied" });
	});

	it("a deny without a reason uses the default text", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ decision: "deny" }) },
		});
		const agent = await newAgent(theauth, "l", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result.reason).toBe("Blocked by beforeAuthorize hook");
	});

	it("a hook cannot widen access: allow still runs permission evaluation", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ decision: "allow" }) },
		});
		const agent = await newAgent(theauth, "l", []);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result).toMatchObject({ allowed: false, code: "no_permission" });
	});
});
