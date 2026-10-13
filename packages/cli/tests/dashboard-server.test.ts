import { describe, expect, it } from "vitest";
import { decodePathname, secretsMatch } from "../src/dashboard-server.js";

describe("dashboard server path and secret handling", () => {
	it("decodes an ordinary path", () => {
		expect(decodePathname("/assets/app%20one.js")).toBe("/assets/app one.js");
	});

	it("returns null for a malformed escape instead of throwing", () => {
		expect(decodePathname("/%E0%A4%A")).toBeNull();
		expect(decodePathname("/%")).toBeNull();
	});

	it("returns null for an embedded NUL byte", () => {
		expect(decodePathname("/assets/app.js%00.png")).toBeNull();
	});

	it("compares secrets by value and by length", () => {
		expect(secretsMatch("s3cret", "s3cret")).toBe(true);
		expect(secretsMatch("s3cret", "s3cret!")).toBe(false);
		expect(secretsMatch("", "s3cret")).toBe(false);
		expect(secretsMatch("S3cret", "s3cret")).toBe(false);
	});
});

describe("static file serving", () => {
	async function withServer(
		run: (request: (path: string) => Promise<{ status: number; body: string }>) => Promise<void>,
	) {
		const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const { createServer, request: httpRequest } = await import("node:http");
		const base = mkdtempSync(join(tmpdir(), "dash-"));
		const root = join(base, "dist");
		mkdirSync(join(root, "assets"), { recursive: true });
		writeFileSync(join(root, "assets", "app.js"), "console.log(1)");
		writeFileSync(join(base, "secret.txt"), "top secret");
		const { serveStatic } = await import("../src/dashboard-server.js");
		const server = createServer((req, res) => {
			const pathname = decodePathname((req.url ?? "/").split("?")[0] ?? "/") ?? "/";
			if (serveStatic(root, pathname, res)) return;
			res.writeHead(200);
			res.end("index");
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address();
		const port = typeof address === "object" && address ? address.port : 0;
		const request = (path: string) =>
			new Promise<{ status: number; body: string }>((resolve, reject) => {
				// http.request sends the path verbatim, unlike fetch which normalizes "..".
				const req = httpRequest({ host: "127.0.0.1", port, path }, (res) => {
					let body = "";
					res.on("data", (c) => {
						body += c;
					});
					res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
				});
				req.on("error", reject);
				req.end();
			});
		try {
			await run(request);
		} finally {
			await new Promise((resolve) => server.close(resolve));
		}
	}

	it("serves a file inside the root", async () => {
		await withServer(async (request) => {
			expect(await request("/assets/app.js")).toEqual({ status: 200, body: "console.log(1)" });
		});
	});

	it("does not serve a file outside the root", async () => {
		await withServer(async (request) => {
			for (const path of ["/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt"]) {
				const res = await request(path);
				expect(res.body).not.toContain("top secret");
			}
		});
	});

	it("falls back to index for a missing file and for a directory", async () => {
		await withServer(async (request) => {
			expect((await request("/assets/missing.js")).body).toBe("index");
			expect((await request("/assets")).body).toBe("index");
		});
	});
});
