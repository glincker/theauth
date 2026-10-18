import { describe, expect, it, vi } from "vitest";
import { createTheAuthHandler } from "../../src/http/index.js";
import { readBoundedText, readJsonBody } from "../../src/http/respond.js";
import { createTheAuth } from "../../src/theauth.js";
import { makeHarness } from "../mcp-test-harness.js";
import { BASE, SESSION_SECRET } from "./helpers.js";

const MIB = 1024 * 1024;

function chunkedRequest(url: string, totalBytes: number, pulledRef: { n: number }): Request {
	const chunk = new Uint8Array(MIB).fill(0x20);
	const body = new ReadableStream<Uint8Array>({
		pull(c) {
			if (pulledRef.n >= totalBytes) return c.close();
			pulledRef.n += chunk.length;
			c.enqueue(chunk);
		},
	});
	return new Request(url, {
		method: "POST",
		body,
		// @ts-expect-error node fetch needs duplex for stream bodies
		duplex: "half",
		headers: { "content-type": "application/x-www-form-urlencoded" },
	});
}

describe("body cap is enforced while streaming", () => {
	it("readJsonBody stops reading shortly after the cap on a chunked body", async () => {
		const pulled = { n: 0 };
		const res = await readJsonBody(chunkedRequest(`${BASE}/mcp/register`, 64 * MIB, pulled), MIB);
		expect(res.ok).toBe(false);
		if (!res.ok) expect(res.response.status).toBe(413);
		expect(pulled.n).toBeLessThanOrEqual(4 * MIB);
	});

	it("rejects a Content-Length over the cap without reading", async () => {
		const req = new Request(`${BASE}/x`, {
			method: "POST",
			body: "{}",
			headers: { "content-length": String(10 * MIB) },
		});
		await expect(readBoundedText(req, MIB)).rejects.toThrow("too large");
	});

	it("/mcp/token answers 413 and stops reading a 64 MiB chunked body", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SESSION_SECRET } },
		});
		const h = makeHarness({});
		const handler = createTheAuthHandler(auth, { mcp: h.mcp, rateLimit: false, maxBodyBytes: MIB });
		const pulled = { n: 0 };
		const res = await handler(chunkedRequest(`${BASE}/mcp/token`, 64 * MIB, pulled));
		expect(res.status).toBe(413);
		expect(pulled.n).toBeLessThanOrEqual(4 * MIB);
	});
});

describe("MCP 500 responses are generic", () => {
	it("returns fixed text and logs the original error", async () => {
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SESSION_SECRET } },
			logger,
		});
		const h = makeHarness({});
		const secret = "SQLITE_CONSTRAINT: UNIQUE constraint failed: mcp_clients.client_id";
		const boom = async (): Promise<never> => {
			throw new Error(secret);
		};
		const mcp = { ...h.mcp, token: boom, registerClient: boom, getJwks: boom, authorize: boom };
		const handler = createTheAuthHandler(auth, { mcp, rateLimit: false });
		const post = (path: string, body: string, type: string) =>
			handler(
				new Request(`${BASE}${path}`, {
					method: "POST",
					headers: { "content-type": type },
					body,
				}),
			);
		const responses = [
			await post("/mcp/token", "grant_type=x", "application/x-www-form-urlencoded"),
			await post("/mcp/register", "{}", "application/json"),
			await handler(new Request(`${BASE}/mcp/jwks`)),
			await handler(new Request(`${BASE}/mcp/authorize?client_id=a`)),
		];
		for (const res of responses) {
			expect(res.status).toBe(500);
			const text = await res.text();
			expect(text).not.toContain("SQLITE");
			expect(text).not.toContain("mcp_clients");
			expect(text).toContain("server_error");
		}
		expect(logger.error).toHaveBeenCalledTimes(4);
		expect(JSON.stringify(logger.error.mock.calls)).toContain("SQLITE_CONSTRAINT");
	});
});
