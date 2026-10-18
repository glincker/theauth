import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import {
	createTheAuthHandler,
	peerAddressOf,
	requireAgent,
	toWebRequest,
} from "../../src/http/index.js";
import type { Permission } from "../../src/types.js";
import { makeAuth, seedUser } from "./helpers.js";

/** A GET `IncomingMessage` stand-in with a chosen socket address. */
function nodeRequest(
	path: string,
	remoteAddress: string | undefined,
	headers: Record<string, string> = {},
): IncomingMessage {
	return {
		method: "GET",
		url: path,
		headers: { host: "localhost", ...headers },
		socket: { remoteAddress },
	} as unknown as IncomingMessage;
}

const PEER = "203.0.113.5";
const OTHER = "198.51.100.9";

async function agentWith(permission: Permission) {
	const auth = await makeAuth();
	await seedUser(auth, "owner");
	const agent = await auth.agent.create({
		ownerId: "owner",
		name: "ip-bound",
		type: "autonomous",
		permissions: [permission],
	});
	return { auth, agent };
}

const allowlist = (ips: string[]): Permission => ({
	resource: "docs",
	actions: ["read"],
	constraints: { ipAllowlist: ips },
});

describe("peer address handling", () => {
	it("records the socket address out of band", async () => {
		const web = await toWebRequest(nodeRequest("/x", PEER));
		expect(peerAddressOf(web)).toBe(PEER);
		expect(web.headers.get("x-forwarded-for")).toBeNull();
		expect(peerAddressOf(new Request("http://localhost/x"))).toBeUndefined();
	});

	it("normalises an IPv4-mapped IPv6 address", async () => {
		const web = await toWebRequest(nodeRequest("/x", "::ffff:10.0.0.7"));
		expect(peerAddressOf(web)).toBe("10.0.0.7");
	});

	it("a header cannot set the peer address", async () => {
		const web = await toWebRequest(
			nodeRequest("/x", undefined, { "x-peer-address": PEER, "x-forwarded-for": PEER }),
		);
		expect(peerAddressOf(web)).toBeUndefined();
	});
});

describe("ipAllowlist through the handler", () => {
	async function authorize(
		allowedIps: string[],
		peer: string,
		headers: Record<string, string> = {},
		trustedProxy?: { trustedProxyCount: number },
	): Promise<number> {
		const { auth, agent } = await agentWith(allowlist(allowedIps));
		const handler = createTheAuthHandler(auth, { allowUnauthenticated: true, trustedProxy });
		const body = JSON.stringify({ agentId: agent.id, action: "read", resource: "docs" });
		const web = await toWebRequest({
			...nodeRequest("/api/theauth/authorize", peer, headers),
			method: "POST",
			headers: { host: "localhost", "content-type": "application/json", ...headers },
			body,
			complete: true,
			readableEnded: true,
		} as unknown as IncomingMessage);
		return (await handler(web)).status;
	}

	it("allows the real peer and denies another", async () => {
		expect(await authorize([PEER], PEER)).toBe(200);
		expect(await authorize([PEER], OTHER)).toBe(403);
	});

	it("ignores a forged X-Forwarded-For without trustedProxy", async () => {
		expect(await authorize([PEER], OTHER, { "x-forwarded-for": PEER })).toBe(403);
		expect(await authorize([PEER], PEER, { "x-forwarded-for": OTHER })).toBe(200);
	});

	it("uses the forwarded value, not the peer, when trustedProxy is set", async () => {
		const proxy = { trustedProxyCount: 1 };
		expect(await authorize([PEER], OTHER, { "x-forwarded-for": PEER }, proxy)).toBe(200);
		expect(await authorize([PEER], PEER, { "x-forwarded-for": OTHER }, proxy)).toBe(403);
	});
});

describe("rate limit buckets per peer", () => {
	it("limits each peer separately and ignores forged forwarded headers", async () => {
		const auth = await makeAuth();
		const handler = createTheAuthHandler(auth, {
			allowUnauthenticated: true,
			rateLimit: { read: { max: 1, window: 60 } },
		});
		const call = async (peer: string, headers: Record<string, string> = {}) =>
			(await handler(await toWebRequest(nodeRequest("/api/theauth/agents", peer, headers)))).status;
		expect(await call(PEER)).toBe(200);
		expect(await call(PEER, { "x-forwarded-for": "1.1.1.1" })).toBe(429);
		expect(await call(OTHER, { "x-forwarded-for": PEER })).toBe(200);
		expect(await call(OTHER)).toBe(429);
	});
});

describe("requireAgent default client ip", () => {
	it("uses the recorded peer address when clientIp is not given", async () => {
		const { auth, agent } = await agentWith(allowlist([PEER]));
		const withPeer = async (peer: string) =>
			(
				await requireAgent(
					auth,
					await toWebRequest(nodeRequest("/x", peer, { authorization: `Bearer ${agent.token}` })),
					{ action: "read", resource: "docs" },
				)
			).ok;
		expect(await withPeer(PEER)).toBe(true);
		expect(await withPeer(OTHER)).toBe(false);
	});
});
