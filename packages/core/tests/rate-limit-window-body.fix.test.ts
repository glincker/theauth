import { describe, expect, it } from "vitest";
import { rateLimit } from "../src/auth/rate-limit.js";

const post = (body: BodyInit, type: string) =>
	new Request("http://localhost/mcp/token", {
		method: "POST",
		headers: { "content-type": type },
		body,
	});

describe("rateLimit window validation", () => {
	it("rejects a zero window at construction", () => {
		expect(() => rateLimit({ signIn: { window: "0m", max: 1 } })).toThrow(/above 0/);
		expect(() => rateLimit({ default: { window: "0s", max: 1 } })).toThrow(/above 0/);
	});
	it("rejects a malformed window at construction", () => {
		expect(() => rateLimit({ signIn: { window: "abc", max: 1 } })).toThrow(/Invalid/);
	});
	it("accepts valid windows", () => {
		expect(() => rateLimit({ signIn: { window: "15m", max: 1 } })).not.toThrow();
	});
});

describe("client_id body scan is bounded", () => {
	it("reads at most 8192 bytes of a huge body", async () => {
		let pulled = 0;
		const chunk = new TextEncoder().encode("x".repeat(4096));
		const stream = new ReadableStream<Uint8Array>({
			pull(c) {
				pulled += chunk.byteLength;
				c.enqueue(chunk);
				if (pulled > 50_000_000) c.close();
			},
		});
		const p = rateLimit({ keyBy: "client_id", mcpToken: { window: "1m", max: 100 } });
		const req = new Request("http://localhost/mcp/token", {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: stream,
			// @ts-expect-error duplex is required by Node for stream bodies
			duplex: "half",
		});
		await p.hooks?.onRequest?.(req);
		expect(pulled).toBeLessThan(1_000_000);
	});
	it("still finds client_id within the limit", async () => {
		const p = rateLimit({ keyBy: "client_id", mcpToken: { window: "1m", max: 1 } });
		const mk = () => post("client_id=abc&x=1", "application/x-www-form-urlencoded");
		await p.hooks?.onRequest?.(mk());
		const second = await p.hooks?.onRequest?.(mk());
		expect((second as Response).status).toBe(429);
	});
});
