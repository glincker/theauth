/**
 * Opt-in live delegation check: the `act` chain of an access token is walked
 * against live link records, so revoking a parent grant stops tokens minted
 * down the chain before they expire.
 */
import { describe, expect, it } from "vitest";
import type { McpDelegationLink, McpDelegationStore } from "../src/mcp/types.js";
import { addClient, basicAuth, codeFlow, makeHarness, tokenRequest } from "./mcp-test-harness.js";

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";

function mapStore(links: Map<string, McpDelegationLink>): McpDelegationStore {
	return { findLink: async (from, to) => links.get(`${from}>${to}`) ?? null };
}

const FUTURE = new Date(Date.now() + 3_600_000);
const PAST = new Date(Date.now() - 1000);

/** Mint a token whose act chain is [xch2 (current), xch1]. */
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

function healthy(): Map<string, McpDelegationLink> {
	return new Map<string, McpDelegationLink>([
		["user_1>xch1", { status: "active", expiresAt: FUTURE }],
		["xch1>xch2", { status: "active", expiresAt: FUTURE }],
	]);
}

describe("live delegation check on act chains", () => {
	it("accepts a healthy chain", async () => {
		const { h, second } = await mintChain({ delegationStore: mapStore(healthy()) });
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(true);
		if (res.success) expect(res.data.delegationChain?.map((x) => x.sub)).toEqual(["xch2", "xch1"]);
	});

	it("rejects when a parent link is revoked after minting", async () => {
		const links = healthy();
		const { h, second } = await mintChain({ delegationStore: mapStore(links) });
		expect((await h.mcp.validateToken(second, ["mcp:read"])).success).toBe(true);
		links.set("user_1>xch1", { status: "revoked", expiresAt: FUTURE });
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_TOKEN");
	});

	it("rejects when the child link is expired", async () => {
		const links = healthy();
		links.set("xch1>xch2", { status: "active", expiresAt: PAST });
		const { h, second } = await mintChain({ delegationStore: mapStore(links) });
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_TOKEN");
	});

	it("rejects when a link is missing", async () => {
		const links = healthy();
		links.delete("xch1>xch2");
		const { h, second } = await mintChain({ delegationStore: mapStore(links) });
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.code).toBe("INVALID_TOKEN");
	});

	it("leaves behaviour unchanged when no store is configured", async () => {
		const { h, second } = await mintChain({});
		const res = await h.mcp.validateToken(second, ["mcp:read"]);
		expect(res.success).toBe(true);
	});

	it("does not consult the store for tokens without an act chain", async () => {
		const h = makeHarness({ delegationStore: mapStore(new Map()) });
		await addClient(h, { clientId: "app", grantTypes: ["authorization_code", "refresh_token"] });
		const out = await codeFlow(h, "app");
		expect((await h.mcp.validateToken(out.access_token, ["mcp:read"])).success).toBe(true);
	});
});
