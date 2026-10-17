/** A revoked or expired delegator stops lending authority down the chain, on every path. Direct permissions of the delegate are unaffected. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { agents } from "../src/db/schema.js";
import { createDelegatorLiveness } from "../src/delegation/liveness.js";
import type { HookDelegationChain } from "../src/hooks/lifecycle.js";
import { checkLiveDelegation, createDbDelegationStore } from "../src/mcp/delegation-check.js";
import { createSimulator } from "../src/simulator/index.js";
import type { TheAuth } from "../src/theauth.js";
import { delegateTo, makeTheAuth, newAgent } from "./hook-test-utils.js";

const GH = { action: "read", resource: "mcp:github:issues" };
const DIRECT = { action: "run", resource: "tool:direct" };
const READ = [{ resource: "mcp:github:*", actions: ["read"] }];

type Break = "revoked" | "expired";

async function breakAgent(theauth: TheAuth, id: string, how: Break): Promise<void> {
	await theauth.db
		.update(agents)
		.set(how === "revoked" ? { status: "revoked" } : { expiresAt: new Date(Date.now() - 1000) })
		.where(eq(agents.id, id));
}

async function build() {
	let chain: HookDelegationChain | undefined;
	const theauth = await makeTheAuth({
		policy: { policyVersion: "v-live-1" },
		hooks: {
			beforeAuthorize: async (ctx) => {
				chain = await ctx.delegation;
				return undefined;
			},
		},
	});
	const a = await newAgent(theauth, "a", READ);
	const b = await newAgent(theauth, "b", []);
	const c = await newAgent(theauth, "c", [{ resource: "tool:direct", actions: ["run"] }]);
	const ab = await delegateTo(theauth, a.id, b.id, READ);
	const bc = await delegateTo(theauth, b.id, c.id, READ);
	return { theauth, a, b, c, ab, bc, lastChain: () => chain };
}

for (const how of ["revoked", "expired"] as const) {
	describe(`delegator ${how} two hops up`, () => {
		it("lends permissions while live, then stops on every path", async () => {
			const { theauth, a, c, lastChain } = await build();
			expect((await theauth.authorize(c.id, GH)).allowed).toBe(true);
			expect(lastChain()?.path).toHaveLength(3);

			await breakAgent(theauth, a.id, how);

			const viaId = await theauth.authorize(c.id, GH);
			expect(viaId.allowed).toBe(false);
			expect(lastChain()?.path).toEqual([c.id]);
			expect(lastChain()?.links).toEqual([]);
			expect(lastChain()?.inbound).toEqual([]);

			const viaToken = await theauth.authorizeByToken(c.token, GH);
			expect(viaToken.allowed).toBe(false);

			const evaluated = await theauth.policy.evaluate({
				subject: { agentId: c.id },
				action: GH.action,
				resource: GH.resource,
			});
			expect(evaluated.decision).toBe("deny");

			const explained = await theauth.explain(c.id, GH.action, GH.resource);
			expect(explained.success && explained.data.allowed).toBe(false);

			const sim = await createSimulator({ db: theauth.db }).simulate({
				agentId: c.id,
				...GH,
			});
			expect(sim.success && sim.data.allowed).toBe(false);
		});

		it("leaves permissions the delegate holds directly unaffected", async () => {
			const { theauth, a, c } = await build();
			await breakAgent(theauth, a.id, how);
			expect((await theauth.authorize(c.id, DIRECT)).allowed).toBe(true);
			expect((await theauth.authorizeByToken(c.token, DIRECT)).allowed).toBe(true);
		});

		it("fails the live MCP delegation check at the delegator's link", async () => {
			const { theauth, a, b, c } = await build();
			const store = createDbDelegationStore(theauth.db);
			const hops = [{ sub: b.id }, { sub: a.id }];
			expect(await checkLiveDelegation(store, a.id, [{ sub: b.id }])).toBeNull();
			await breakAgent(theauth, a.id, how);
			const failed = await checkLiveDelegation(store, a.id, [{ sub: b.id }]);
			expect(failed).toMatchObject({ from: a.id, to: b.id, reason: how });
			const deeper = await checkLiveDelegation(store, a.id, [{ sub: c.id }, { sub: b.id }]);
			expect(deeper?.reason).toBe(how);
			expect(hops).toHaveLength(2);
		});
	});
}

describe("delegator liveness edge cases", () => {
	it("a root user as delegator has no agent status to check", async () => {
		const theauth = await makeTheAuth({});
		const liveness = createDelegatorLiveness(theauth.db, new Date());
		expect(await liveness.delegatorState("user-1")).toBe("live");
	});

	it("a live middle agent with its own broken delegator also stops lending", async () => {
		const { theauth, b, c } = await build();
		await breakAgent(theauth, b.id, "revoked");
		expect((await theauth.authorize(c.id, GH)).allowed).toBe(false);
	});
});
