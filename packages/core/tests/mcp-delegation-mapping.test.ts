/**
 * Actor to agent id mapping for the live delegation check: token exchange sets
 * `act.sub` to a user or client id, so `resolveActorAgentId` maps each actor to
 * the agent id used in delegation records before the link lookup.
 */
import { describe, expect, it } from "vitest";
import { checkLiveDelegation } from "../src/mcp/delegation-check.js";
import type { McpActorRef, McpDelegationLink, McpDelegationStore } from "../src/mcp/types.js";
import { addClient, basicAuth, codeFlow, makeHarness, tokenRequest } from "./mcp-test-harness.js";

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";
const FUTURE = new Date(Date.now() + 3_600_000);

function mapStore(links: Map<string, McpDelegationLink>): McpDelegationStore {
	return { findLink: async (from, to) => links.get(`${from}>${to}`) ?? null };
}

/** Links keyed by agent ids, not by the ids carried in the token. */
function agentLinks(): Map<string, McpDelegationLink> {
	return new Map<string, McpDelegationLink>([
		["agent_root>agent_a", { status: "active", expiresAt: FUTURE }],
		["agent_a>agent_b", { status: "active", expiresAt: FUTURE }],
	]);
}

const TABLE: Record<string, string> = {
	user_1: "agent_root",
	xch1: "agent_a",
	xch2: "agent_b",
};
const lookup = (actor: McpActorRef) => TABLE[actor.sub];

async function mintChain(config: Parameters<typeof makeHarness>[0]) {
	const h = makeHarness({ tokenExchange: { enabled: true }, ...config });
	await addClient(h, { clientId: "app", grantTypes: ["authorization_code", "refresh_token"] });
	await addClient(h, { clientId: "xch1", secret: "s1", grantTypes: [TE] });
	await addClient(h, { clientId: "xch2", secret: "s2", grantTypes: [TE] });
	const subject = await codeFlow(h, "app");
	const exchange = async (token: string, id: string, secret: string) => {
		const res = await h.mcp.token(
			tokenRequest(
				{ grant_type: TE, subject_token_type: AT, subject_token: token },
				basicAuth(id, secret),
			),
		);
		if (!res.success) throw new Error(`${res.error.code}: ${res.error.message}`);
		return res.data.access_token;
	};
	const first = await exchange(subject.access_token, "xch1", "s1");
	const second = await exchange(first, "xch2", "s2");
	return { h, second };
}

describe("checkLiveDelegation actor mapping", () => {
	const hops = [{ sub: "xch2" }, { sub: "xch1" }];

	it("maps every path entry to an agent id before findLink", async () => {
		const seen: McpActorRef[] = [];
		const out = await checkLiveDelegation(mapStore(agentLinks()), "user_1", hops, {
			resolveActorAgentId: (a) => {
				seen.push(a);
				return lookup(a);
			},
		});
		expect(out).toBeNull();
		expect(seen.map((a) => a.sub)).toEqual(["user_1", "xch1", "xch2"]);
	});

	it("passes the hop client id to the mapper", async () => {
		const seen: McpActorRef[] = [];
		await checkLiveDelegation(mapStore(agentLinks()), "user_1", [{ sub: "xch1", clientId: "c1" }], {
			resolveActorAgentId: (a) => {
				seen.push(a);
				return lookup(a);
			},
		});
		expect(seen[1]).toEqual({ sub: "xch1", clientId: "c1" });
	});

	it("fails closed on an unmapped actor with a distinct reason", async () => {
		const out = await checkLiveDelegation(mapStore(agentLinks()), "user_1", hops, {
			resolveActorAgentId: (a) => (a.sub === "xch2" ? undefined : lookup(a)),
		});
		expect(out?.reason).toBe("unmapped actor");
		expect(out?.to).toBe("xch2");
	});

	it("falls back to the raw id when allowUnmappedActors is true", async () => {
		const links = new Map<string, McpDelegationLink>([
			["agent_root>agent_a", { status: "active", expiresAt: FUTURE }],
			["agent_a>xch2", { status: "active", expiresAt: FUTURE }],
		]);
		const out = await checkLiveDelegation(mapStore(links), "user_1", hops, {
			resolveActorAgentId: (a) => (a.sub === "xch2" ? undefined : lookup(a)),
			allowUnmappedActors: true,
		});
		expect(out).toBeNull();
	});

	it("supports an async mapper", async () => {
		const out = await checkLiveDelegation(mapStore(agentLinks()), "user_1", hops, {
			resolveActorAgentId: async (a) => lookup(a),
		});
		expect(out).toBeNull();
	});

	it("fails closed when the mapper throws, even with allowUnmappedActors", async () => {
		const out = await checkLiveDelegation(mapStore(agentLinks()), "user_1", hops, {
			resolveActorAgentId: async () => {
				throw new Error("db down");
			},
			allowUnmappedActors: true,
		});
		expect(out?.reason).toBe("mapper failed");
	});

	it("keeps raw ids when no mapper is set", async () => {
		const links = new Map<string, McpDelegationLink>([
			["user_1>xch1", { status: "active", expiresAt: FUTURE }],
			["xch1>xch2", { status: "active", expiresAt: FUTURE }],
		]);
		expect(await checkLiveDelegation(mapStore(links), "user_1", hops)).toBeNull();
		expect((await checkLiveDelegation(mapStore(agentLinks()), "user_1", hops))?.reason).toBe(
			"missing",
		);
	});
});

describe("mcp config actor mapping", () => {
	it("accepts a chain whose links are keyed by mapped agent ids", async () => {
		const { h, second } = await mintChain({
			delegationStore: mapStore(agentLinks()),
			resolveActorAgentId: lookup,
		});
		expect((await h.mcp.validateToken(second, ["mcp:read"])).success).toBe(true);
	});

	it("rejects an unmapped actor as INVALID_TOKEN with the reason in the message", async () => {
		// Exchange validates the subject token too, so break the mapper after minting.
		let broken = false;
		const { h, second } = await mintChain({
			delegationStore: mapStore(agentLinks()),
			resolveActorAgentId: (a) => (broken && a.sub === "xch1" ? undefined : lookup(a)),
		});
		broken = true;
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(false);
		if (!res.success) {
			expect(res.error.code).toBe("INVALID_TOKEN");
			expect(res.error.message).toContain("unmapped actor");
		}
	});

	it("rejects when the mapper throws", async () => {
		let broken = false;
		const { h, second } = await mintChain({
			delegationStore: mapStore(agentLinks()),
			resolveActorAgentId: async (a) => {
				if (broken) throw new Error("boom");
				return lookup(a);
			},
		});
		broken = true;
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_TOKEN");
	});

	it("allows unmapped actors when explicitly configured", async () => {
		const links = new Map<string, McpDelegationLink>([
			["agent_root>xch1", { status: "active", expiresAt: FUTURE }],
			["xch1>xch2", { status: "active", expiresAt: FUTURE }],
		]);
		const { h, second } = await mintChain({
			delegationStore: mapStore(links),
			resolveActorAgentId: (a) => (a.sub === "user_1" ? "agent_root" : undefined),
			allowUnmappedActors: true,
		});
		expect((await h.mcp.validateToken(second, ["mcp:read"])).success).toBe(true);
	});

	it("leaves the default unchanged without a mapper", async () => {
		const links = new Map<string, McpDelegationLink>([
			["user_1>xch1", { status: "active", expiresAt: FUTURE }],
			["xch1>xch2", { status: "active", expiresAt: FUTURE }],
		]);
		const { h, second } = await mintChain({ delegationStore: mapStore(links) });
		expect((await h.mcp.validateToken(second, ["mcp:read"])).success).toBe(true);
	});
});
