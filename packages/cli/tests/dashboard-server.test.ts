import { describe, expect, it } from "vitest";
import {
	DASHBOARD_COOKIE,
	decodePathname,
	handleAuthRequest,
	secretsMatch,
	signDashboardCookie,
	verifyDashboardCookie,
} from "../src/dashboard-server.js";

// The first test boots the server and pays the cold start, which is about 4s on a busy machine and over the 5s default on shared CI runners.
const FIRST_REQUEST_TIMEOUT_MS = 30_000;

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

	it(
		"serves a file inside the root",
		async () => {
			await withServer(async (request) => {
				expect(await request("/assets/app.js")).toEqual({ status: 200, body: "console.log(1)" });
			});
		},
		FIRST_REQUEST_TIMEOUT_MS,
	);

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

describe("dashboard session cookie", () => {
	const secret = "s3cret";

	it("accepts a cookie it signed and rejects tampering, expiry and other secrets", () => {
		const now = Date.parse("2026-10-13T12:00:00Z");
		const value = signDashboardCookie(secret, now);
		expect(verifyDashboardCookie(secret, value, now + 1000)).toBe(true);
		expect(verifyDashboardCookie("other", value, now + 1000)).toBe(false);
		expect(verifyDashboardCookie(secret, `9${value}`, now + 1000)).toBe(false);
		expect(verifyDashboardCookie(secret, `${value}x`, now + 1000)).toBe(false);
		expect(verifyDashboardCookie(secret, value, now + 9 * 60 * 60 * 1000)).toBe(false);
		expect(verifyDashboardCookie(secret, "", now)).toBe(false);
		expect(verifyDashboardCookie(secret, "nodot", now)).toBe(false);
	});

	async function call(
		method: string,
		headers: Record<string, string>,
		configured: string | null = secret,
	): Promise<{ status: number; setCookie: string }> {
		const { createServer, request: httpRequest } = await import("node:http");
		const server = createServer((req, res) => {
			if (!handleAuthRequest(req, res, configured)) {
				res.writeHead(404);
				res.end();
			}
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address();
		const port = typeof address === "object" && address ? address.port : 0;
		try {
			return await new Promise((resolve, reject) => {
				const req = httpRequest(
					{ host: "127.0.0.1", port, path: "/api/dashboard/auth", method, headers },
					(res) => {
						res.resume();
						res.on("end", () =>
							resolve({
								status: res.statusCode ?? 0,
								setCookie: String(res.headers["set-cookie"]?.[0] ?? ""),
							}),
						);
					},
				);
				req.on("error", reject);
				req.end();
			});
		} finally {
			server.close();
		}
	}

	it("sets an HttpOnly SameSite=Strict cookie on a correct sign-in", async () => {
		const ok = await call("POST", { authorization: `Bearer ${secret}` });
		expect(ok.status).toBe(200);
		expect(ok.setCookie).toContain(`${DASHBOARD_COOKIE}=`);
		expect(ok.setCookie).toContain("HttpOnly");
		expect(ok.setCookie).toContain("SameSite=Strict");
		expect(ok.setCookie).not.toContain(secret);
		expect((await call("POST", { authorization: "Bearer nope" })).status).toBe(401);
	});

	it("checks the cookie on GET and clears it on DELETE", async () => {
		const cookie = `${DASHBOARD_COOKIE}=${signDashboardCookie(secret)}`;
		expect((await call("GET", { cookie })).status).toBe(200);
		expect((await call("GET", {})).status).toBe(401);
		expect((await call("GET", { cookie: `${DASHBOARD_COOKIE}=forged.value` })).status).toBe(401);
		const out = await call("DELETE", { cookie });
		expect(out.setCookie).toContain("Max-Age=0");
	});

	it("is open in dev mode when no secret is configured", async () => {
		expect((await call("GET", {}, null)).status).toBe(200);
	});
});
