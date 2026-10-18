import { readFileSync } from "node:fs";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { SafeFetchEvent } from "../src/mcp/safe-fetch.js";
import { safeFetchJson } from "../src/mcp/safe-fetch.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

let server: Server;
let base = "";
let handler: Handler = (_req, res) => res.end();
const seen: string[] = [];

beforeAll(async () => {
	server = createServer((req, res) => {
		seen.push(req.url ?? "");
		handler(req, res);
	});
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
	base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
	server.closeAllConnections();
	await new Promise<void>((r) => server.close(() => r()));
});

const json = (res: ServerResponse, body: string, type = "application/json") => {
	res.writeHead(200, { "content-type": type });
	res.end(body);
};

const opts = { allowLoopbackForTests: true, timeoutMs: 1000 } as const;
const publicResolver = async () => ["93.184.216.34"];

describe("safeFetchJson against a local server", () => {
	it("returns a 200 JSON document and sends minimal headers", async () => {
		let headers: IncomingMessage["headers"] = {};
		handler = (req, res) => {
			headers = req.headers;
			res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=120" });
			res.end('{"a":1}');
		};
		const r = await safeFetchJson(`${base}/doc`, opts);
		expect(r).toEqual({ ok: true, json: { a: 1 }, cacheControl: "max-age=120" });
		expect(headers.cookie).toBeUndefined();
		expect(headers.authorization).toBeUndefined();
		expect(headers.referer).toBeUndefined();
		expect(headers.accept).toBe("application/json");
	});

	it("accepts +json media types", async () => {
		handler = (_q, res) => json(res, "{}", "application/vnd.x+json; charset=utf-8");
		expect((await safeFetchJson(`${base}/d`, opts)).ok).toBe(true);
	});

	it("refuses loopback without the test option", async () => {
		seen.length = 0;
		const r = await safeFetchJson(`${base}/d`);
		expect(r).toMatchObject({ ok: false, reason: "invalid_url" });
		const https = await safeFetchJson(base.replace("http:", "https:"), { resolver: "none" });
		expect(https.ok).toBe(false);
		expect(seen).toEqual([]);
	});

	it("refuses 3xx and never requests the target", async () => {
		seen.length = 0;
		handler = (_q, res) => {
			res.writeHead(302, { location: `${base}/target` });
			res.end();
		};
		const r = await safeFetchJson(`${base}/start`, opts);
		expect(r).toMatchObject({ ok: false, reason: "redirect" });
		expect(seen).toEqual(["/start"]);
	});

	it("refuses 204, 201 and 404", async () => {
		for (const status of [204, 201, 404]) {
			handler = (_q, res) => {
				res.writeHead(status, { "content-type": "application/json" });
				res.end();
			};
			expect(await safeFetchJson(`${base}/d`, opts)).toMatchObject({
				ok: false,
				reason: "http_error",
			});
		}
	});

	it("refuses a wrong content type", async () => {
		handler = (_q, res) => json(res, "{}", "text/html");
		expect(await safeFetchJson(`${base}/d`, opts)).toMatchObject({
			ok: false,
			reason: "bad_content_type",
		});
	});

	it("refuses an oversized declared and chunked body", async () => {
		handler = (_q, res) => json(res, JSON.stringify({ pad: "x".repeat(6000) }));
		expect(await safeFetchJson(`${base}/d`, opts)).toMatchObject({
			ok: false,
			reason: "too_large",
		});
		handler = (_q, res) => {
			res.writeHead(200, { "content-type": "application/json" });
			res.write('{"pad":"');
			res.write("x".repeat(3000));
			res.write("x".repeat(3000));
			res.end('"}');
		};
		expect(await safeFetchJson(`${base}/d`, { ...opts, maxBytes: 5120 })).toMatchObject({
			ok: false,
			reason: "too_large",
		});
	});

	it("refuses invalid JSON", async () => {
		handler = (_q, res) => json(res, "{nope");
		expect(await safeFetchJson(`${base}/d`, opts)).toMatchObject({
			ok: false,
			reason: "invalid_json",
		});
	});

	it("aborts a slow-drip body at the deadline", async () => {
		let timer: NodeJS.Timeout | undefined;
		handler = (_q, res) => {
			res.writeHead(200, { "content-type": "application/json" });
			res.write("{");
			timer = setInterval(() => res.write(" "), 40);
			res.on("close", () => clearInterval(timer));
		};
		const started = Date.now();
		const r = await safeFetchJson(`${base}/d`, { ...opts, timeoutMs: 300 });
		clearInterval(timer);
		expect(r).toMatchObject({ ok: false, reason: "timeout" });
		expect(Date.now() - started).toBeLessThan(300 + 250);
	});

	it("times out when headers are slow", async () => {
		handler = (_q, res) => {
			setTimeout(() => json(res, "{}"), 600);
		};
		const started = Date.now();
		const r = await safeFetchJson(`${base}/d`, { ...opts, timeoutMs: 150 });
		expect(r).toMatchObject({ ok: false, reason: "timeout" });
		expect(Date.now() - started).toBeLessThan(150 + 250);
	});
});

describe("resolver handling", () => {
	const fetchOk = async () =>
		new Response("{}", { headers: { "content-type": "application/json" } });
	const url = "https://client.example/doc";

	it("accepts a public resolver answer", async () => {
		expect((await safeFetchJson(url, { resolver: publicResolver, fetchImpl: fetchOk })).ok).toBe(
			true,
		);
	});

	it("refuses a private address", async () => {
		let called = false;
		const r = await safeFetchJson(url, {
			resolver: async () => ["10.0.0.5"],
			fetchImpl: async () => {
				called = true;
				return fetchOk();
			},
		});
		expect(r).toMatchObject({ ok: false, reason: "blocked_host" });
		expect(called).toBe(false);
	});

	it("refuses mixed public and private answers", async () => {
		const r = await safeFetchJson(url, {
			resolver: async () => ["93.184.216.34", "10.0.0.5"],
			fetchImpl: fetchOk,
		});
		expect(r).toMatchObject({ ok: false, reason: "blocked_host" });
	});

	it("fails closed when the resolver throws or returns nothing", async () => {
		const events: SafeFetchEvent[] = [];
		const thrown = await safeFetchJson(url, {
			resolver: async () => {
				throw new Error("secret-internal-detail");
			},
			fetchImpl: fetchOk,
			onEvent: (e) => events.push(e),
		});
		expect(thrown).toMatchObject({ ok: false, reason: "dns_failure" });
		expect(
			await safeFetchJson(url, { resolver: async () => [], fetchImpl: fetchOk }),
		).toMatchObject({
			reason: "dns_failure",
		});
	});

	it("resolver none skips resolution", async () => {
		expect((await safeFetchJson(url, { resolver: "none", fetchImpl: fetchOk })).ok).toBe(true);
	});

	it("auto resolver never makes the fetch throw", async () => {
		const events: SafeFetchEvent[] = [];
		const r = await safeFetchJson(url, {
			resolver: "auto",
			fetchImpl: fetchOk,
			onEvent: (e) => events.push(e),
		});
		expect(typeof r.ok).toBe("boolean");
	});
});

describe("error hygiene", () => {
	it("gives detail to onEvent and a generic error to the caller", async () => {
		const events: SafeFetchEvent[] = [];
		handler = (_q, res) => {
			res.writeHead(500, { "content-type": "application/json" });
			res.end('{"secret":"db password"}');
		};
		const r = await safeFetchJson(`${base}/d?token=abc`, {
			...opts,
			onEvent: (e) => events.push(e),
		});
		expect(r.ok).toBe(false);
		const returned = JSON.stringify(r);
		expect(returned).not.toContain("500");
		expect(returned).not.toContain("secret");
		const ev = events.find((e) => e.type === "safe_fetch.failed");
		expect(ev?.detail).toContain("500");
		expect(ev?.url).not.toContain("token");
	});

	it("never throws when onEvent throws or fetchImpl throws synchronously", async () => {
		const r = await safeFetchJson("https://client.example/d", {
			resolver: publicResolver,
			fetchImpl: () => {
				throw new Error("sync boom");
			},
			onEvent: () => {
				throw new Error("observer boom");
			},
		});
		expect(r).toMatchObject({ ok: false, reason: "network_error" });
	});
});

describe("runtime portability", () => {
	it("has no static node: import and only the guarded dynamic one", () => {
		const fetcher = readFileSync(new URL("../src/mcp/safe-fetch.ts", import.meta.url), "utf8");
		const src = readFileSync(new URL("../src/mcp/safe-fetch-dns.ts", import.meta.url), "utf8");
		expect(fetcher).not.toMatch(/from\s+["']node:/);
		expect(src).not.toMatch(/from\s+["']node:/);
		expect(src).not.toMatch(/require\(\s*["']node:/);
		expect(src).not.toMatch(/import\(\s*["']node:/);
		// The dynamic import takes a runtime-built specifier and sits inside try/catch.
		const idx = src.indexOf("await import(");
		expect(idx).toBeGreaterThan(-1);
		expect(src.slice(Math.max(0, idx - 300), idx)).toContain("try {");
	});
});
