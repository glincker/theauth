/** DNS over HTTPS resolver with an injected fetch. */
import { describe, expect, it } from "vitest";
import { createDohResolver } from "../src/mcp/doh-resolver.js";

interface Rec {
	name: string;
	type: number;
	data: string;
}

type Answers = Record<string, { Status?: number; Answer?: Rec[] }>;

const json = (body: unknown, status = 200): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/dns-json" },
	});

/** Builds a fetch that answers per type ("A" or "AAAA") and records every request URL. */
function dnsFetch(byType: Answers, urls: string[] = []): typeof fetch {
	return (async (input: RequestInfo | URL) => {
		const u = new URL(String(input));
		urls.push(u.toString());
		const answer = byType[u.searchParams.get("type") ?? ""] ?? { Status: 0 };
		return json({ Status: 0, ...answer });
	}) as typeof fetch;
}

const A = (name: string, data: string): Rec => ({ name, type: 1, data });
const AAAA = (name: string, data: string): Rec => ({ name, type: 28, data });
const CNAME = (name: string, data: string): Rec => ({ name, type: 5, data });

const mk = (fetchImpl: typeof fetch, extra: Parameters<typeof createDohResolver>[0] = {}) =>
	createDohResolver({ fetchImpl, endpoint: "https://doh.test/dns-query", ...extra });

describe("createDohResolver", () => {
	it("returns A and AAAA answers", async () => {
		const resolve = mk(
			dnsFetch({
				A: { Answer: [A("client.example.", "93.184.216.34")] },
				AAAA: { Answer: [AAAA("client.example.", "2606:4700::1111")] },
			}),
		);
		expect((await resolve("client.example")).sort()).toEqual(["2606:4700::1111", "93.184.216.34"]);
	});

	it("sends dns-json queries for both types without credentials", async () => {
		const urls: string[] = [];
		const inits: RequestInit[] = [];
		const base = dnsFetch({ A: { Answer: [A("client.example", "8.8.8.8")] } }, urls);
		const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
			inits.push(init ?? {});
			return base(input, init);
		}) as typeof fetch;
		await mk(fetchImpl)("Client.Example.");
		expect(urls.some((u) => u.includes("name=client.example") && u.includes("type=A"))).toBe(true);
		expect(urls.some((u) => u.includes("type=AAAA"))).toBe(true);
		expect(inits[0]?.credentials).toBe("omit");
		expect(inits[0]?.cache).toBe("no-store");
		expect(new Headers(inits[0]?.headers).get("accept")).toBe("application/dns-json");
	});

	it("follows a CNAME chain to public addresses", async () => {
		const resolve = mk(
			dnsFetch({
				A: {
					Answer: [CNAME("client.example", "edge.cdn.example."), A("edge.cdn.example", "8.8.4.4")],
				},
			}),
		);
		expect(await resolve("client.example")).toEqual(["8.8.4.4"]);
	});

	it("ignores address records that are not on the CNAME chain", async () => {
		const resolve = mk(
			dnsFetch({
				A: { Answer: [A("client.example", "8.8.8.8"), A("other.example", "10.0.0.1")] },
			}),
		);
		expect(await resolve("client.example")).toEqual(["8.8.8.8"]);
	});

	it("refuses a private answer", async () => {
		const resolve = mk(dnsFetch({ A: { Answer: [A("client.example", "10.0.0.5")] } }));
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "private_address" });
	});

	it("refuses when only one of several answers is private", async () => {
		const resolve = mk(
			dnsFetch({
				A: { Answer: [A("client.example", "93.184.216.34"), A("client.example", "10.0.0.5")] },
			}),
		);
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "private_address" });
	});

	it("refuses a private AAAA answer and a mapped private address", async () => {
		await expect(
			mk(dnsFetch({ AAAA: { Answer: [AAAA("client.example", "fd00:ec2::254")] } }))(
				"client.example",
			),
		).rejects.toMatchObject({ code: "private_address" });
		await expect(
			mk(dnsFetch({ AAAA: { Answer: [AAAA("client.example", "::ffff:10.0.0.1")] } }))(
				"client.example",
			),
		).rejects.toMatchObject({ code: "private_address" });
	});

	it("refuses a CNAME that lands on a private address", async () => {
		const resolve = mk(
			dnsFetch({
				A: {
					Answer: [
						CNAME("client.example", "inner.evil.example"),
						A("inner.evil.example", "127.0.0.1"),
					],
				},
			}),
		);
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "private_address" });
	});

	it("refuses a CNAME to an internal name", async () => {
		const resolve = mk(
			dnsFetch({
				A: {
					Answer: [
						CNAME("client.example", "metadata.google.internal"),
						A("metadata.google.internal", "8.8.8.8"),
					],
				},
			}),
		);
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "blocked_cname" });
	});

	it("can be told to return private answers (for callers that screen themselves)", async () => {
		const resolve = mk(dnsFetch({ A: { Answer: [A("client.example", "10.0.0.5")] } }), {
			rejectPrivateAnswers: false,
		});
		expect(await resolve("client.example")).toEqual(["10.0.0.5"]);
	});

	it("still refuses malformed addresses when private answers are allowed", async () => {
		const resolve = mk(dnsFetch({ A: { Answer: [A("client.example", "not-an-ip")] } }), {
			rejectPrivateAnswers: false,
		});
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "bad_response" });
	});

	it("returns an empty list for NXDOMAIN", async () => {
		const resolve = mk(dnsFetch({ A: { Status: 3 }, AAAA: { Status: 3 } }));
		expect(await resolve("nothere.example")).toEqual([]);
	});

	it("returns an empty list for a name with no A or AAAA data", async () => {
		const resolve = mk(dnsFetch({}));
		expect(await resolve("client.example")).toEqual([]);
	});

	it("throws on SERVFAIL", async () => {
		const resolve = mk(dnsFetch({ A: { Status: 2 } }));
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "servfail" });
	});

	it("throws on REFUSED", async () => {
		const resolve = mk(dnsFetch({ A: { Status: 5 }, AAAA: { Status: 5 } }));
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "servfail" });
	});

	it("fails closed when AAAA fails but A succeeds", async () => {
		const resolve = mk(
			dnsFetch({ A: { Answer: [A("client.example", "8.8.8.8")] }, AAAA: { Status: 2 } }),
		);
		await expect(resolve("client.example")).rejects.toThrow();
	});

	it("throws on non 200", async () => {
		const fetchImpl = (async () => new Response("oops", { status: 503 })) as typeof fetch;
		await expect(mk(fetchImpl)("client.example")).rejects.toMatchObject({ code: "bad_status" });
	});

	it("throws on a 3xx without following it", async () => {
		const fetchImpl = (async () =>
			new Response(null, {
				status: 302,
				headers: { location: "https://evil.example/" },
			})) as typeof fetch;
		await expect(mk(fetchImpl)("client.example")).rejects.toMatchObject({ code: "bad_status" });
	});

	it("throws on malformed JSON", async () => {
		const fetchImpl = (async () => new Response("{not json", { status: 200 })) as typeof fetch;
		await expect(mk(fetchImpl)("client.example")).rejects.toMatchObject({ code: "bad_response" });
	});

	it.each([
		["null", "null"],
		["array", "[]"],
		["missing status", "{}"],
		["status string", '{"Status":"0"}'],
		["answer not array", '{"Status":0,"Answer":{}}'],
		["record without data", '{"Status":0,"Answer":[{"name":"a.example","type":1}]}'],
	])("throws on a bad shape: %s", async (_label, body) => {
		const fetchImpl = (async () => new Response(body, { status: 200 })) as typeof fetch;
		await expect(mk(fetchImpl)("client.example")).rejects.toThrow();
	});

	it("throws on an oversized body", async () => {
		const fetchImpl = (async () =>
			new Response(`{"Status":0,"pad":"${"x".repeat(70_000)}"}`, { status: 200 })) as typeof fetch;
		await expect(mk(fetchImpl)("client.example")).rejects.toMatchObject({ code: "bad_response" });
	});

	it("throws on a CNAME loop", async () => {
		const resolve = mk(
			dnsFetch({
				A: { Answer: [CNAME("a.example", "b.example"), CNAME("b.example", "a.example")] },
			}),
		);
		await expect(resolve("a.example")).rejects.toMatchObject({ code: "cname_loop" });
	});

	it("throws on a self referencing CNAME", async () => {
		const resolve = mk(dnsFetch({ A: { Answer: [CNAME("a.example", "a.example")] } }));
		await expect(resolve("a.example")).rejects.toMatchObject({ code: "cname_loop" });
	});

	it("throws when the CNAME chain is longer than the limit", async () => {
		const chain: Rec[] = [];
		for (let i = 0; i < 12; i++) chain.push(CNAME(`h${i}.example`, `h${i + 1}.example`));
		chain.push(A("h12.example", "8.8.8.8"));
		const fetchImpl = dnsFetch({ A: { Answer: chain } });
		await expect(mk(fetchImpl, { maxCnameDepth: 4 })("h0.example")).rejects.toMatchObject({
			code: "cname_depth",
		});
		expect(await mk(fetchImpl, { maxCnameDepth: 16 })("h0.example")).toEqual(["8.8.8.8"]);
	});

	it("times out when the endpoint never answers", async () => {
		const fetchImpl = ((_: RequestInfo | URL, init?: RequestInit) =>
			new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
			})) as typeof fetch;
		const started = Date.now();
		await expect(mk(fetchImpl, { timeoutMs: 200 })("client.example")).rejects.toMatchObject({
			code: "timeout",
		});
		expect(Date.now() - started).toBeLessThan(1500);
	});

	it("times out even when the abort signal is ignored", async () => {
		const fetchImpl = (() => new Promise<Response>(() => undefined)) as typeof fetch;
		await expect(mk(fetchImpl, { timeoutMs: 200 })("client.example")).rejects.toMatchObject({
			code: "timeout",
		});
	});

	it("throws when fetch rejects", async () => {
		const fetchImpl = (async () => {
			throw new TypeError("network down");
		}) as typeof fetch;
		await expect(mk(fetchImpl)("client.example")).rejects.toMatchObject({ code: "transport" });
	});

	it("falls back to the next endpoint on transport failure", async () => {
		const seen: string[] = [];
		const fetchImpl = (async (input: RequestInfo | URL) => {
			const u = new URL(String(input));
			seen.push(u.host);
			if (u.host === "one.test") return new Response("down", { status: 500 });
			return json({
				Status: 0,
				Answer: u.searchParams.get("type") === "A" ? [A("client.example", "8.8.8.8")] : [],
			});
		}) as typeof fetch;
		const resolve = createDohResolver({
			fetchImpl,
			endpoint: ["https://one.test/q", "https://two.test/q"],
		});
		expect(await resolve("client.example")).toEqual(["8.8.8.8"]);
		expect(seen).toContain("two.test");
	});

	it("does not fall back after a private verdict", async () => {
		const seen: string[] = [];
		const fetchImpl = (async (input: RequestInfo | URL) => {
			const u = new URL(String(input));
			seen.push(u.host);
			const answer = u.host === "one.test" ? "10.0.0.1" : "8.8.8.8";
			return json({
				Status: 0,
				Answer: u.searchParams.get("type") === "A" ? [A("client.example", answer)] : [],
			});
		}) as typeof fetch;
		const resolve = createDohResolver({
			fetchImpl,
			endpoint: ["https://one.test/q", "https://two.test/q"],
		});
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "private_address" });
		expect(seen).not.toContain("two.test");
	});

	it("throws after every endpoint failed", async () => {
		const fetchImpl = (async () => new Response("down", { status: 500 })) as typeof fetch;
		const resolve = createDohResolver({
			fetchImpl,
			endpoint: ["https://one.test/q", "https://two.test/q"],
		});
		await expect(resolve("client.example")).rejects.toMatchObject({ code: "bad_status" });
	});

	it("uses the default endpoints when none are given", async () => {
		const urls: string[] = [];
		const resolve = createDohResolver({
			fetchImpl: dnsFetch({ A: { Answer: [A("client.example", "8.8.8.8")] } }, urls),
		});
		await resolve("client.example");
		expect(urls[0]).toContain("https://cloudflare-dns.com/dns-query?");
	});

	it.each([
		"127.0.0.1",
		"localhost",
		"[::1]",
		"a.internal",
		"intranet",
		"10.0.0.1.nip.io",
		"",
		"a b.example",
	])("refuses to query for %j", async (host) => {
		let called = false;
		const fetchImpl = (async () => {
			called = true;
			return json({ Status: 0 });
		}) as typeof fetch;
		await expect(mk(fetchImpl)(host)).rejects.toMatchObject({ code: "invalid_host" });
		expect(called).toBe(false);
	});

	it("rejects non https endpoints and empty endpoint lists at creation", () => {
		expect(() => createDohResolver({ endpoint: "http://doh.test/q" })).toThrow(TypeError);
		expect(() => createDohResolver({ endpoint: [] })).toThrow(TypeError);
	});

	it("does not de-duplicate into a different answer order issue (dedupes addresses)", async () => {
		const resolve = mk(
			dnsFetch({
				A: { Answer: [A("client.example", "8.8.8.8"), A("client.example", "8.8.8.8")] },
			}),
		);
		expect(await resolve("client.example")).toEqual(["8.8.8.8"]);
	});
});
