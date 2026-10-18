/** httpGuard and verifyGuardRequest against a real local HTTP server. */
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { GuardCheckInput } from "../src/hooks/guard.js";
import { guardHook } from "../src/hooks/guard.js";
import {
	GUARD_PROTOCOL_VERSION,
	httpGuard,
	signGuardBody,
	verifyGuardRequest,
} from "../src/hooks/http-guard.js";
import { auditRows, makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

const SECRET = "s3cret-value-do-not-leak";

const INPUT: GuardCheckInput = {
	agentId: "agent_1",
	action: "read",
	resource: "mcp:github:issues",
	arguments: { q: "bugs", email: "a@b.c" },
	agent: {
		id: "agent_1",
		ownerId: "u1",
		type: "autonomous",
		name: "bot",
	} as GuardCheckInput["agent"],
	delegation: { path: ["agent_1"], links: [], inbound: [] },
	source: "authorize",
	dryRun: false,
};

type Handler = (req: IncomingMessage, res: ServerResponse, body: string) => void | Promise<void>;
let handler: Handler;
let server: Server;
let base: string;
const seen: { headers: IncomingMessage["headers"]; body: string }[] = [];

beforeAll(async () => {
	server = createServer((req, res) => {
		let body = "";
		req.on("data", (c) => {
			body += c;
		});
		req.on("end", () => {
			seen.push({ headers: req.headers, body });
			void handler(req, res, body);
		});
	});
	await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
	base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

function json(res: ServerResponse, body: unknown, status = 200): void {
	res.writeHead(status, { "content-type": "application/json" });
	res.end(JSON.stringify(body));
}

const signal = () => new AbortController().signal;
const guard = () => httpGuard({ name: "vendor", url: `${base}/check`, secret: SECRET });

describe("httpGuard verdicts", () => {
	it("allow, with a signed request the vendor can verify", async () => {
		handler = async (req, res, body) => {
			const v = await verifyGuardRequest(SECRET, req.headers as Record<string, string>, body);
			json(res, v.ok ? { decision: "allow" } : { decision: "deny", reason: v.reason });
		};
		expect(await guard().check(INPUT, signal())).toEqual({ decision: "allow" });
		const last = seen[seen.length - 1];
		expect(last?.headers["x-theauth-guard-version"]).toBe(GUARD_PROTOCOL_VERSION);
		expect(last?.headers["x-theauth-signature"]).toMatch(/^v1=[0-9a-f]{64}$/);
		const wire = JSON.parse(last?.body ?? "{}");
		expect(wire).toMatchObject({
			version: GUARD_PROTOCOL_VERSION,
			input: { action: "read", dryRun: false },
		});
		expect(JSON.stringify(wire)).not.toContain(SECRET);
	});

	it("deny keeps reason and maps code to ruleId", async () => {
		handler = (_q, res) => json(res, { decision: "deny", reason: "blocked", code: "R1" });
		expect(await guard().check(INPUT, signal())).toEqual({
			decision: "deny",
			reason: "blocked",
			ruleId: "R1",
		});
	});

	it("escalate passes through", async () => {
		handler = (_q, res) => json(res, { decision: "escalate", reason: "ask a human" });
		expect(await guard().check(INPUT, signal())).toMatchObject({ decision: "escalate" });
	});

	it("redact runs before sending", async () => {
		handler = (_q, res) => json(res, { decision: "allow" });
		const g = httpGuard({
			name: "v",
			url: `${base}/x`,
			secret: SECRET,
			redact: (i) => ({ ...i, arguments: undefined }),
		});
		await g.check(INPUT, signal());
		expect(JSON.parse(seen[seen.length - 1]?.body ?? "{}").input.arguments).toBeUndefined();
	});
});

describe("httpGuard fails closed", () => {
	const bad: [string, Handler][] = [
		["non-2xx", (_q, res) => json(res, { decision: "allow" }, 500)],
		["not JSON", (_q, res) => void res.end("<html>")],
		["unknown decision", (_q, res) => json(res, { decision: "maybe" })],
		["extra field", (_q, res) => json(res, { decision: "allow", admin: true })],
		["deny without reason", (_q, res) => json(res, { decision: "deny" })],
		["legacy shape", (_q, res) => json(res, { allow: true })],
		[
			"redirect",
			(_q, res) => {
				res.writeHead(302, { location: "http://127.0.0.1:1/evil" });
				res.end();
			},
		],
	];
	for (const [name, h] of bad) {
		it(`rejects ${name}`, async () => {
			handler = h;
			await expect(guard().check(INPUT, signal())).rejects.toThrow();
		});
	}

	it("rejects an oversized response", async () => {
		handler = (_q, res) => json(res, { decision: "allow", reason: "x".repeat(70000) });
		await expect(guard().check(INPUT, signal())).rejects.toThrow();
	});

	it("network error rejects and does not leak the secret", async () => {
		const g = httpGuard({ name: "v", url: "http://127.0.0.1:1/x", secret: SECRET });
		const err = await g.check(INPUT, signal()).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(Error);
		expect(JSON.stringify(err, Object.getOwnPropertyNames(err))).not.toContain(SECRET);
	});

	it("aborts on timeout signal", async () => {
		handler = () => undefined; // never answers
		const ac = new AbortController();
		const p = guard().check(INPUT, ac.signal);
		setTimeout(() => ac.abort(), 50);
		await expect(p).rejects.toThrow();
	});

	it("error messages carry no secret, query or path", async () => {
		handler = (_q, res) => json(res, { nope: true });
		const g = httpGuard({ name: "v", url: `${base}/p/token=abc?key=zzz`, secret: SECRET });
		const err = (await g.check(INPUT, signal()).catch((e: unknown) => e)) as Error;
		expect(err.message).not.toMatch(/SECRET|s3cret|zzz|token=abc/i);
	});
});

describe("url policy", () => {
	it("refuses plain http for non-localhost hosts", () => {
		expect(() =>
			httpGuard({ name: "v", url: "http://guard.example.com/x", secret: SECRET }),
		).toThrow(/https/);
	});
	it("refuses credentials in the url and a missing secret", () => {
		expect(() =>
			httpGuard({ name: "v", url: "https://u:p@guard.example.com", secret: SECRET }),
		).toThrow();
		expect(() => httpGuard({ name: "v", url: "https://guard.example.com", secret: "" })).toThrow();
	});
	it("accepts https", () => {
		expect(httpGuard({ name: "v", url: "https://guard.example.com/x", secret: SECRET }).name).toBe(
			"v",
		);
	});
});

describe("verifyGuardRequest", () => {
	async function signed(ts: number, secret = SECRET) {
		const body = JSON.stringify({
			version: GUARD_PROTOCOL_VERSION,
			requestId: "r1",
			issuedAt: new Date().toISOString(),
			input: INPUT,
		});
		return {
			body,
			headers: {
				"x-theauth-timestamp": String(ts),
				"x-theauth-signature": await signGuardBody(secret, ts, body),
			},
		};
	}
	const now = Math.floor(Date.now() / 1000);

	it("accepts a fresh signed request, also with a Headers object", async () => {
		const { body, headers } = await signed(now);
		const r = await verifyGuardRequest(SECRET, new Headers(headers), body);
		expect(r).toMatchObject({ ok: true, requestId: "r1" });
	});
	it("rejects a wrong secret, tampered body, and missing headers", async () => {
		const { body, headers } = await signed(now, "other");
		expect(await verifyGuardRequest(SECRET, headers, body)).toEqual({
			ok: false,
			reason: "bad signature",
		});
		const good = await signed(now);
		expect((await verifyGuardRequest(SECRET, good.headers, `${good.body} `)).ok).toBe(false);
		expect((await verifyGuardRequest(SECRET, {}, good.body)).ok).toBe(false);
	});
	it("enforces the replay window both directions", async () => {
		const old = await signed(now - 600);
		expect(await verifyGuardRequest(SECRET, old.headers, old.body)).toEqual({
			ok: false,
			reason: "stale timestamp",
		});
		const future = await signed(now + 600);
		expect((await verifyGuardRequest(SECRET, future.headers, future.body)).ok).toBe(false);
		expect(
			(await verifyGuardRequest(SECRET, old.headers, old.body, { toleranceSec: 900 })).ok,
		).toBe(true);
	});
	it("rejects a replayed requestId through the seen callback", async () => {
		const { body, headers } = await signed(now);
		const ids = new Set<string>();
		const seenFn = (id: string) => (ids.has(id) ? true : (ids.add(id), false));
		expect((await verifyGuardRequest(SECRET, headers, body, { seen: seenFn })).ok).toBe(true);
		expect((await verifyGuardRequest(SECRET, headers, body, { seen: seenFn })).ok).toBe(false);
	});
});

describe("through the hook runner", () => {
	it("a malformed vendor answer denies the call (fail closed)", async () => {
		handler = (_q, res) => json(res, { decision: "maybe" });
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: guardHook(guard()) } });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, {
			action: "read",
			resource: "mcp:github:issues",
		});
		expect(result.allowed).toBe(false);
		expect((await auditRows(theauth, agent.id)).length).toBeGreaterThan(0);
	});
	it("an allow lets permission evaluation proceed", async () => {
		handler = (_q, res) => json(res, { decision: "allow" });
		const theauth = await makeTheAuth({ hooks: { beforeAuthorize: guardHook(guard()) } });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		expect(
			(await theauth.authorize(agent.id, { action: "read", resource: "mcp:github:issues" }))
				.allowed,
		).toBe(true);
	});
});
