import type { Server } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import * as schema from "../../core/src/db/schema.js";
import { createTheAuth } from "../../core/src/theauth.js";
import { createGateway } from "../src/gateway.js";

// Real sockets end to end: a local upstream, the gateway's own listener, real fetch.

function listen(server: Server): Promise<number> {
	return new Promise((resolve) =>
		server.listen(0, () => resolve((server.address() as AddressInfo).port)),
	);
}

async function freePort(): Promise<number> {
	const s = createServer();
	const port = await listen(s);
	await new Promise<void>((r) => s.close(() => r()));
	return port;
}

describe("standalone listener", () => {
	const closers: Array<() => Promise<void>> = [];
	afterEach(async () => {
		for (const c of closers.splice(0)) await c();
	});

	async function boot(handler: Parameters<typeof createServer>[1], maxBodyBytes = 1024) {
		const upstream = createServer(handler);
		const upstreamPort = await listen(upstream);
		closers.push(() => new Promise((r) => upstream.close(() => r())));
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
		});
		theauth.db
			.insert(schema.users)
			.values({
				id: "u",
				email: "a@b.test",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const agent = await theauth.agent.create({
			ownerId: "u",
			name: "a",
			type: "autonomous",
			permissions: [],
		});
		const gw = createGateway({
			upstream: `http://127.0.0.1:${upstreamPort}`,
			theauth,
			maxBodyBytes,
		});
		const port = await freePort();
		await gw.listen(port);
		closers.push(() => gw.close());
		return { base: `http://127.0.0.1:${port}`, token: agent.token };
	}

	it("rejects a body over the limit with 413 and a body under it passes", async () => {
		const { base, token } = await boot((req, res) => {
			let n = 0;
			req.on("data", (c: Buffer) => {
				n += c.length;
			});
			req.on("end", () => res.end(String(n)));
		});
		const headers = { Authorization: `Bearer ${token}` };
		const small = await fetch(`${base}/x`, { method: "POST", headers, body: "x".repeat(100) });
		expect(await small.text()).toBe("100");
		const big = await fetch(`${base}/x`, { method: "POST", headers, body: "x".repeat(5000) });
		expect(big.status).toBe(413);
	});

	it("streams SSE chunks as they are produced, not at the end", async () => {
		let release: () => void = () => undefined;
		const gate = new Promise<void>((r) => {
			release = r;
		});
		const { base, token } = await boot((_req, res) => {
			res.writeHead(200, { "Content-Type": "text/event-stream" });
			res.write("data: first\n\n");
			void gate.then(() => {
				res.write("data: second\n\n");
				res.end();
			});
		});
		const res = await fetch(`${base}/events`, { headers: { Authorization: `Bearer ${token}` } });
		expect(res.status).toBe(200);
		const reader = (res.body as ReadableStream<Uint8Array>).getReader();
		const first = await reader.read();
		expect(new TextDecoder().decode(first.value)).toContain("first");
		release();
		const second = await reader.read();
		expect(new TextDecoder().decode(second.value)).toContain("second");
	});
});
