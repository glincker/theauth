import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { RequestBodyTooLargeError, sendWebResponse, toWebRequest } from "../../src/http/index.js";

let server: Server | undefined;

afterEach(async () => {
	await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
	server = undefined;
});

async function serve(
	onRequest: (req: IncomingMessage, res: ServerResponse) => Promise<void>,
): Promise<string> {
	server = createServer((req, res) => {
		onRequest(req, res).catch(() => {
			res.statusCode = 500;
			res.end("boom");
		});
	});
	await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
	return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("toWebRequest", () => {
	it("keeps method, path, query, headers and body", async () => {
		let seen: Request | undefined;
		const base = await serve(async (req, res) => {
			seen = await toWebRequest(req);
			res.end("ok");
		});
		await fetch(`${base}/api/theauth/agents?x=1`, {
			method: "POST",
			headers: { "x-custom": "a", "content-type": "application/json" },
			body: JSON.stringify({ hello: "world" }),
		});
		expect(seen?.method).toBe("POST");
		const url = new URL(seen?.url ?? "");
		expect(url.pathname).toBe("/api/theauth/agents");
		expect(url.search).toBe("?x=1");
		expect(seen?.headers.get("x-custom")).toBe("a");
		expect(await seen?.json()).toEqual({ hello: "world" });
	});

	it("builds a GET without a body", async () => {
		let seen: Request | undefined;
		const base = await serve(async (req, res) => {
			seen = await toWebRequest(req);
			res.end("ok");
		});
		await fetch(`${base}/a`);
		expect(seen?.method).toBe("GET");
		expect(seen?.body).toBeNull();
	});

	it("ignores forwarded headers unless trustProxy is set", async () => {
		const seen: string[] = [];
		const base = await serve(async (req, res) => {
			seen.push((await toWebRequest(req)).url);
			seen.push((await toWebRequest(req, { trustProxy: true })).url);
			res.end("ok");
		});
		await fetch(`${base}/p`, {
			headers: { "x-forwarded-proto": "https", "x-forwarded-host": "app.example.com" },
		});
		expect(seen[0]).toBe(`${base}/p`);
		expect(seen[1]).toBe("https://app.example.com/p");
	});

	it("prefers originalUrl (express mounts) and reuses a parsed body", async () => {
		const req = Object.assign(Object.create(null) as IncomingMessage, {
			method: "POST",
			url: "/agents",
			originalUrl: "/api/theauth/agents",
			headers: { host: "h.test" },
			socket: {},
			readableEnded: true,
			body: { a: 1 },
		});
		const web = await toWebRequest(req);
		expect(new URL(web.url).pathname).toBe("/api/theauth/agents");
		expect(await web.json()).toEqual({ a: 1 });
	});

	it("rejects a body over the limit", async () => {
		let error: unknown;
		const base = await serve(async (req, res) => {
			try {
				await toWebRequest(req, { maxBodyBytes: 10 });
			} catch (err) {
				error = err;
			}
			res.end("x");
		});
		await fetch(`${base}/p`, { method: "POST", body: "x".repeat(100) });
		expect(error).toBeInstanceOf(RequestBodyTooLargeError);
	});
});

describe("sendWebResponse", () => {
	it("writes status, headers, multiple cookies and a streamed body", async () => {
		const base = await serve(async (_req, res) => {
			const headers = new Headers({ "content-type": "text/plain", "x-a": "1" });
			headers.append("set-cookie", "a=1; Path=/");
			headers.append("set-cookie", "b=2; Path=/");
			const stream = new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new TextEncoder().encode("hello "));
					controller.enqueue(new TextEncoder().encode("world"));
					controller.close();
				},
			});
			await sendWebResponse(res, new Response(stream, { status: 201, headers }));
		});
		const res = await fetch(`${base}/`);
		expect(res.status).toBe(201);
		expect(res.headers.get("x-a")).toBe("1");
		expect(res.headers.getSetCookie()).toEqual(["a=1; Path=/", "b=2; Path=/"]);
		expect(await res.text()).toBe("hello world");
	});

	it("handles an empty body", async () => {
		const base = await serve(async (_req, res) => {
			await sendWebResponse(res, new Response(null, { status: 204 }));
		});
		const res = await fetch(`${base}/`);
		expect(res.status).toBe(204);
		expect(await res.text()).toBe("");
	});

	it("round trips a Request through the bridge", async () => {
		const base = await serve(async (req, res) => {
			const web = await toWebRequest(req);
			await sendWebResponse(res, Response.json({ echo: await web.json() }));
		});
		const res = await fetch(`${base}/`, { method: "POST", body: JSON.stringify({ n: 1 }) });
		expect(await res.json()).toEqual({ echo: { n: 1 } });
	});
});
