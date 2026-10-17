import { mkdtemp, readFile, rm } from "node:fs/promises";
import type { Server } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseArgs } from "../src/args.js";
import { buildBadge } from "../src/badge.js";
import { ALL_CHECKS } from "../src/checks/index.js";
import { main } from "../src/cli.js";
import { formatReport } from "../src/report.js";
import { runSuite } from "../src/runner.js";
import type { CheckStatus, Report } from "../src/types.js";
import type { RunningServer } from "./theauth-server.js";
import { startTheauthServer } from "./theauth-server.js";

let server: RunningServer;
let report: Report;

function statusOf(id: string): CheckStatus {
	const found = report.results.find((r) => r.id === id);
	if (!found) throw new Error(`no result for ${id}`);
	return found.status;
}

beforeAll(async () => {
	server = await startTheauthServer();
	report = await runSuite({ target: server.url, timeoutMs: 10000 });
});

afterAll(async () => {
	await server.close();
});

describe("against theauth's own MCP OAuth server", () => {
	it("returns one result per check, each with id, spec, severity and a summary", () => {
		expect(report.results).toHaveLength(ALL_CHECKS.length);
		for (const result of report.results) {
			expect(result.id).toBeTruthy();
			expect(result.spec).toBeTruthy();
			expect(["must", "should", "may"]).toContain(result.severity);
			expect(result.summary.length).toBeGreaterThan(0);
		}
	});

	it("passes the checks theauth implements", () => {
		const expectedPass = [
			"as-metadata",
			"rs-metadata",
			"metadata-consistency",
			"pkce-s256-advertised",
			"pkce-required",
			"pkce-plain-rejected",
			"redirect-exact-match",
			"dcr-registration",
			"dcr-validation",
			"refresh-garbage-rejected",
			"dpop-advertised",
			"dpop-enforced",
			"www-authenticate-resource-metadata",
		];
		for (const id of expectedPass) {
			expect({ id, status: statusOf(id) }).toEqual({ id, status: "pass" });
		}
	});

	it("skips, with a reason, what needs credentials or an unadvertised feature", () => {
		const expectedSkip = [
			"refresh-rotation",
			"resource-indicator-audience",
			"token-exchange-rejects-garbage",
			"token-exchange-act-chain",
			"introspection-inactive",
		];
		for (const id of expectedSkip) {
			expect({ id, status: statusOf(id) }).toEqual({ id, status: "skip" });
		}
	});

	it("has no failures and a green badge that counts skips honestly", () => {
		expect(report.summary.fail).toBe(0);
		const badge = buildBadge(report);
		expect(badge).toEqual({
			schemaVersion: 1,
			label: "agent-auth",
			message: `${report.summary.pass}/${report.summary.pass} passed, ${report.summary.skip} skipped`,
			color: "brightgreen",
		});
	});
});

async function startStub(
	handler: (
		url: URL,
		origin: string,
	) => { status: number; headers?: Record<string, string>; body?: unknown },
): Promise<{ url: string; stop: () => Promise<void> }> {
	let origin = "";
	const stub: Server = createServer((req, res) => {
		const out = handler(new URL(req.url ?? "/", origin), origin);
		res.writeHead(out.status, { "Content-Type": "application/json", ...out.headers });
		res.end(out.body === undefined ? "" : JSON.stringify(out.body));
		req.resume();
	});
	await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
	origin = `http://127.0.0.1:${(stub.address() as AddressInfo).port}`;
	return {
		url: origin,
		stop: () =>
			new Promise<void>((resolve) => {
				stub.close(() => resolve());
				stub.closeAllConnections();
			}),
	};
}

describe("honesty on servers that do not conform", () => {
	it("fails the metadata check against a server that serves nothing", async () => {
		const bare = await startStub(() => ({ status: 404 }));
		try {
			const empty = await runSuite({ target: bare.url, timeoutMs: 5000 });
			const byId = new Map(empty.results.map((r) => [r.id, r.status]));
			expect(byId.get("as-metadata")).toBe("fail");
			expect(byId.get("pkce-required")).toBe("skip");
			expect(byId.get("dcr-registration")).toBe("skip");
			expect(buildBadge(empty).color).toBe("red");
		} finally {
			await bare.stop();
		}
	});

	it("fails a lenient server that issues codes without PKCE and accepts any redirect", async () => {
		const lenient = await startStub((url, origin) => {
			switch (url.pathname) {
				case "/.well-known/oauth-authorization-server":
					return {
						status: 200,
						body: {
							issuer: origin,
							authorization_endpoint: `${origin}/authorize`,
							token_endpoint: `${origin}/token`,
							registration_endpoint: `${origin}/register`,
							response_types_supported: ["code"],
							code_challenge_methods_supported: ["S256", "plain"],
						},
					};
				case "/register":
					return {
						status: 201,
						body: { client_id: "c1", redirect_uris: ["https://conformance.example.test/callback"] },
					};
				case "/authorize": {
					const redirect = url.searchParams.get("redirect_uri") ?? origin;
					return { status: 302, headers: { Location: `${redirect}?code=abc` } };
				}
				default:
					return { status: 404 };
			}
		});
		try {
			const lax = await runSuite({ target: lenient.url, timeoutMs: 5000 });
			const byId = new Map(lax.results.map((r) => [r.id, r.status]));
			expect(byId.get("pkce-s256-advertised")).toBe("fail");
			expect(byId.get("pkce-required")).toBe("fail");
			expect(byId.get("pkce-plain-rejected")).toBe("fail");
			expect(byId.get("redirect-exact-match")).toBe("fail");
			expect(byId.get("dcr-validation")).toBe("fail");
			expect(lax.summary.mustFailed).toBeGreaterThan(0);
		} finally {
			await lenient.stop();
		}
	});

	it("reports unreachable servers as failures, not passes", async () => {
		const down = await runSuite({ target: "http://127.0.0.1:9", timeoutMs: 1000 });
		expect(down.summary.pass).toBe(0);
	});
});

describe("CLI", () => {
	it("prints a human report and writes the shields badge file", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-"));
		try {
			const badgePath = join(dir, "badge.json");
			const code = await main([server.url, "--badge", badgePath], {});
			expect(code).toBe(0);
			const badge = JSON.parse(await readFile(badgePath, "utf8")) as Record<string, unknown>;
			expect(badge.schemaVersion).toBe(1);
			expect(badge.color).toBe("brightgreen");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("formats the report with PASS, SKIP markers and no dashes used as punctuation", () => {
		const text = formatReport(report);
		expect(text).toContain("[PASS] as-metadata");
		expect(text).toContain("[SKIP] refresh-rotation");
		expect(text).not.toMatch(
			new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`),
		);
	});

	it("rejects a missing URL with a usage error", () => {
		expect(() => parseArgs([], {})).toThrow("Missing <url>");
	});
});
