import { readFileSync } from "node:fs";
import type { Server } from "node:https";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { SafeFetchEvent } from "../src/mcp/safe-fetch.js";
import { safeFetchJson, setNodeHttpsForTests } from "../src/mcp/safe-fetch.js";
import type { NodeHttpsModule } from "../src/mcp/safe-fetch-node.js";
import {
	createPinnedLookup,
	PinnedConnectRefused,
	pinnedHttpsGet,
	publicVetter,
} from "../src/mcp/safe-fetch-node.js";

// Self signed test certificate for CN=localhost, SAN DNS:localhost. Test only.
const KEY = [
	"-----BEGIN PRIVATE KEY-----",
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYMHdyWGsCsxWT6gF",
	"TK/dc/L7HmI4MibpV0v2YO94dGehRANCAAT3xEbSk8SrjeMMDMt5pa5Rv28nKOlQ",
	"FwXT3CUniY3amSRwsLZvTqgbmva8bstWWS/L1CcFy6m2oWMEBOWxGZA/",
	"-----END PRIVATE KEY-----",
].join("\n");
const CERT = [
	"-----BEGIN CERTIFICATE-----",
	"MIIBczCCARqgAwIBAgIUJv5HgBai2h24BMALFtYvSmB8SM0wCgYIKoZIzj0EAwIw",
	"FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAxODAzNTI0M1oYDzIxMjYwOTI0",
	"MDM1MjQzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO",
	"PQMBBwNCAAT3xEbSk8SrjeMMDMt5pa5Rv28nKOlQFwXT3CUniY3amSRwsLZvTqgb",
	"mva8bstWWS/L1CcFy6m2oWMEBOWxGZA/o0gwRjAdBgNVHQ4EFgQUAfjDp3cmI+fs",
	"+Jtk6kPbHROnxG4wDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhv",
	"c3QwCgYIKoZIzj0EAwIDRwAwRAIgf8sXdLqrOYIFpxPT+e1wiPLlMKasrwFD0qvx",
	"xXqYkWwCID9bsteNQLS0cKJwRgtCZBWOAhDGWUwTWWXcsv6AWYCV",
	"-----END CERTIFICATE-----",
].join("\n");

let server: Server;
let port = 0;
let hits = 0;
let mode: "json" | "redirect" | "big" | "500" = "json";

beforeAll(async () => {
	server = createServer({ key: KEY, cert: CERT }, (_req, res) => {
		hits++;
		if (mode === "redirect") {
			res.writeHead(302, { location: "https://localhost/x" });
			res.end();
		} else if (mode === "500") {
			res.writeHead(500, { "content-type": "application/json" });
			res.end("{}");
		} else if (mode === "big") {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(`{"a":"${"x".repeat(9000)}"}`);
		} else {
			res.writeHead(200, { "content-type": "application/json", "cache-control": "max-age=60" });
			res.end('{"ok":1}');
		}
	});
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
	port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
	server.closeAllConnections();
	await new Promise<void>((r) => server.close(() => r()));
});

afterEach(() => {
	setNodeHttpsForTests(undefined);
	vi.restoreAllMocks();
	hits = 0;
	mode = "json";
});

const base = () => ({ allowLoopbackForTests: true, timeoutMs: 2000, caForTests: CERT }) as const;
const PUBLIC = "93.184.216.34";

describe("createPinnedLookup", () => {
	const run = (
		addrs: string[],
		opts: { all?: boolean; family?: number },
		vet = publicVetter(false),
	) =>
		new Promise<{ err: Error | null; address?: unknown; family?: number; refused: string[] }>(
			(resolve) => {
				const refused: string[] = [];
				createPinnedLookup(addrs, vet, (d) => refused.push(d))(
					"example.com",
					opts,
					(err, address, family) => resolve({ err, address, family, refused }),
				);
			},
		);

	it("returns a single vetted IPv4 address", async () => {
		const r = await run([PUBLIC], {});
		expect(r.err).toBeNull();
		expect(r.address).toBe(PUBLIC);
		expect(r.family).toBe(4);
	});

	it("returns every vetted address with all:true, IPv4 and IPv6, and honors the family filter", async () => {
		const addrs = [PUBLIC, "2606:2800:220:1:248:1893:25c8:1946"];
		const all = await run(addrs, { all: true });
		expect(all.address).toEqual([
			{ address: PUBLIC, family: 4 },
			{ address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
		]);
		const v6 = await run(addrs, { all: true, family: 6 });
		expect(v6.address).toEqual([{ address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }]);
		const none = await run([PUBLIC], { family: 6 });
		expect(none.err).not.toBeNull();
	});

	it("refuses the whole answer when any address is not public (mixed answers, none skipped)", async () => {
		const r = await run([PUBLIC, "10.0.0.5"], { all: true });
		expect(r.err).not.toBeNull();
		expect(r.address).toBeUndefined();
		expect(r.refused).toHaveLength(1);
	});

	it.each([
		"::ffff:10.0.0.1",
		"::ffff:7f00:1",
		"::1",
		"fd00::1",
		"169.254.169.254",
		"64:ff9b::a00:1",
	])("refuses %s at connect", async (a) => {
		expect((await run([a], {})).err).not.toBeNull();
	});

	it("never returns an address the caller did not pin, whatever DNS would say now", async () => {
		const r = await run([PUBLIC], { all: true });
		expect(JSON.stringify(r.address)).not.toContain("127.0.0.1");
	});
});

describe("pinned connect through a fake node:https", () => {
	type Captured = { options: Parameters<NodeHttpsModule["request"]>[0] | null; agentOpts: unknown };
	const fake = (captured: Captured, respond: "never" | "ok" = "ok"): NodeHttpsModule => ({
		Agent: class {
			constructor(o: { keepAlive: false; maxSockets: number }) {
				captured.agentOpts = o;
			}
			destroy(): void {}
		},
		request(options, onResponse) {
			captured.options = options;
			const listeners = new Map<string, (...a: never[]) => void>();
			return {
				on(ev, fn) {
					listeners.set(ev, fn);
				},
				end() {
					if (respond === "never") return;
					const handlers = new Map<string, (...a: never[]) => void>();
					onResponse({
						statusCode: 200,
						rawHeaders: ["Content-Type", "application/json"],
						complete: true,
						on(ev: string, fn: (...a: never[]) => void) {
							handlers.set(ev, fn);
						},
						pause() {},
						resume() {},
						destroy() {},
					});
					queueMicrotask(() => {
						(handlers.get("data") as ((c: Uint8Array) => void) | undefined)?.(
							new TextEncoder().encode('{"v":1}'),
						);
						(handlers.get("end") as (() => void) | undefined)?.();
					});
				},
				destroy() {},
			};
		},
	});

	it("pins to the vetted answer, keeps the original hostname for SNI, no keep-alive, validation on", async () => {
		const cap: Captured = { options: null, agentOpts: null };
		setNodeHttpsForTests(fake(cap));
		let dnsCalls = 0;
		const r = await safeFetchJson("https://client.example.com/meta", {
			resolver: async () => {
				dnsCalls++;
				return dnsCalls === 1 ? [PUBLIC] : ["10.0.0.5"];
			},
		});
		expect(r).toEqual({ ok: true, json: { v: 1 } });
		const o = cap.options;
		expect(o?.host).toBe("client.example.com");
		expect(o?.servername).toBe("client.example.com");
		expect(o?.rejectUnauthorized).toBe(true);
		expect(o?.headers.Connection).toBe("close");
		expect(cap.agentOpts).toEqual({ keepAlive: false, maxSockets: 1 });
		expect(o?.ca).toBeUndefined();
		// The connect lookup answers from the pinned vetted set and never asks DNS again.
		const got = await new Promise<unknown>((resolve) =>
			o?.lookup("client.example.com", { all: true }, (_e, a) => resolve(a)),
		);
		expect(got).toEqual([{ address: PUBLIC, family: 4 }]);
		expect(dnsCalls).toBe(1);
	});

	it("refuses a multi A answer with one private address before any connection", async () => {
		const cap: Captured = { options: null, agentOpts: null };
		setNodeHttpsForTests(fake(cap));
		const r = await safeFetchJson("https://client.example.com/meta", {
			resolver: async () => [PUBLIC, "192.168.1.9"],
		});
		expect(r).toMatchObject({ ok: false, reason: "blocked_host" });
		expect(cap.options).toBeNull();
	});

	it("refuses an IPv4 mapped IPv6 private answer", async () => {
		const cap: Captured = { options: null, agentOpts: null };
		setNodeHttpsForTests(fake(cap));
		const r = await safeFetchJson("https://client.example.com/meta", {
			resolver: async () => ["::ffff:10.0.0.1"],
		});
		expect(r).toMatchObject({ ok: false, reason: "blocked_host" });
		expect(cap.options).toBeNull();
	});

	it("reports a connect that never completes as a timeout within one deadline", async () => {
		const cap: Captured = { options: null, agentOpts: null };
		setNodeHttpsForTests(fake(cap, "never"));
		const events: SafeFetchEvent[] = [];
		const started = Date.now();
		const r = await safeFetchJson("https://client.example.com/meta", {
			resolver: async () => [PUBLIC],
			timeoutMs: 250,
			onEvent: (e) => events.push(e),
		});
		expect(r).toEqual({ ok: false, reason: "timeout", message: "request timed out" });
		expect(Date.now() - started).toBeLessThan(1500);
		expect(events[0]?.reason).toBe("timeout");
	});

	it("maps a connect-time refusal to PinnedConnectRefused", async () => {
		const failing: NodeHttpsModule = {
			Agent: class {
				destroy(): void {}
			},
			request(options) {
				let onError: (e: Error) => void = () => undefined;
				return {
					on(_ev: string, fn: (e: Error) => void) {
						onError = fn;
					},
					end() {
						options.lookup("x", {}, (err) => onError(err ?? new Error("unexpected")));
					},
					destroy() {},
				};
			},
		};
		await expect(
			pinnedHttpsGet(failing, {
				url: new URL("https://client.example.com/m"),
				addresses: ["10.0.0.5"],
				vet: publicVetter(false),
				signal: new AbortController().signal,
				headers: {},
			}),
		).rejects.toBeInstanceOf(PinnedConnectRefused);
	});
});

describe("pinned connect against a local https server", () => {
	it("fetches a document with certificate validation on", async () => {
		const r = await safeFetchJson(`https://localhost:${port}/doc`, base());
		expect(r).toEqual({ ok: true, json: { ok: 1 }, cacheControl: "max-age=60" });
		expect(hits).toBe(1);
	});

	it("refuses a certificate that does not match the hostname", async () => {
		const events: SafeFetchEvent[] = [];
		const r = await safeFetchJson(`https://127.0.0.1:${port}/doc`, {
			...base(),
			onEvent: (e) => events.push(e),
		});
		expect(r).toMatchObject({
			ok: false,
			reason: "network_error",
			message: "request could not be completed",
		});
		expect(hits).toBe(0);
		expect(events[0]?.detail).toMatch(/fetch failed/);
	});

	it("refuses an untrusted certificate when no test CA is supplied", async () => {
		const r = await safeFetchJson(`https://localhost:${port}/doc`, {
			allowLoopbackForTests: true,
			timeoutMs: 2000,
		});
		expect(r.ok).toBe(false);
		expect(hits).toBe(0);
	});

	it("never connects to a private address a public looking name resolves to", async () => {
		const r = await safeFetchJson("https://rebind.example.com/x", {
			resolver: async () => ["127.0.0.1"],
			caForTests: CERT,
		});
		expect(r).toMatchObject({ ok: false, reason: "blocked_host" });
		expect(hits).toBe(0);
	});

	it("keeps exact 200, no redirects and the size cap", async () => {
		mode = "redirect";
		expect(await safeFetchJson(`https://localhost:${port}/a`, base())).toMatchObject({
			reason: "redirect",
		});
		mode = "500";
		expect(await safeFetchJson(`https://localhost:${port}/a`, base())).toMatchObject({
			reason: "http_error",
		});
		mode = "big";
		expect(await safeFetchJson(`https://localhost:${port}/a`, base())).toMatchObject({
			reason: "too_large",
		});
	});
});

describe("fallback and Workers safety", () => {
	it("uses fetch when node:https is unavailable", async () => {
		setNodeHttpsForTests(null);
		const spy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(
				new Response('{"f":1}', { headers: { "content-type": "application/json" } }),
			);
		const r = await safeFetchJson("https://client.example.com/meta", {
			resolver: async () => [PUBLIC],
		});
		expect(r).toEqual({ ok: true, json: { f: 1 } });
		expect(spy).toHaveBeenCalledOnce();
	});

	it("uses fetch when pinnedConnect is off or a fetchImpl is given", async () => {
		const cap = vi.fn(
			async () => new Response('{"g":1}', { headers: { "content-type": "application/json" } }),
		);
		const r = await safeFetchJson("https://client.example.com/meta", {
			resolver: async () => [PUBLIC],
			fetchImpl: cap as unknown as typeof fetch,
		});
		expect(r.ok).toBe(true);
		expect(cap).toHaveBeenCalledOnce();
	});

	it("has no top level node: import in the files Workers load", () => {
		for (const f of ["safe-fetch.ts", "safe-fetch-node.ts", "safe-fetch-dns.ts"]) {
			const src = readFileSync(new URL(`../src/mcp/${f}`, import.meta.url), "utf8");
			expect(src, f).not.toMatch(/^\s*import[^;]*["']node:/m);
			expect(src, f).not.toMatch(/^\s*export[^;]*from\s*["']node:/m);
			expect(src, f).not.toMatch(/require\(["']node:/);
		}
	});
});
