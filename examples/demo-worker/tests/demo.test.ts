import { agents } from "@glinr/theauth";
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { cleanupExpired, countAgents } from "../src/store.js";
import { makeHarness } from "./helpers.js";

interface CreateBody {
	agent: { id: string; name: string; permissions: unknown[] };
	token: string;
}
interface AuthorizeBody {
	allowed: boolean;
	reason: string | null;
	auditId: string | null;
}
interface AuditBody {
	rows: Array<{ agentId: string; action: string; resource: string; result: string; at: string }>;
}

async function create(
	h: Awaited<ReturnType<typeof makeHarness>>,
	preset: "reader" | "editor" = "reader",
	ip?: string,
) {
	const res = await h.call("/api/agents", { body: { name: "report-bot", preset }, ip });
	return { res, body: (await res.json()) as CreateBody };
}

describe("demo worker app", () => {
	it("serves the page with a nonce based CSP", async () => {
		const h = await makeHarness();
		const res = await h.call("/");
		expect(res.status).toBe(200);
		const csp = res.headers.get("content-security-policy") ?? "";
		const html = await res.text();
		const nonce = /nonce-([a-f0-9]+)/.exec(csp)?.[1];
		expect(nonce).toBeTruthy();
		expect(html).toContain(`nonce="${nonce}"`);
		expect(html).toContain("Shared sandbox");
		expect(html).toContain("Revoke this agent");
		expect(csp).not.toContain("unsafe-inline");
	});

	it("creates an agent and returns the token once", async () => {
		const h = await makeHarness();
		const { res, body } = await create(h);
		expect(res.status).toBe(201);
		expect(body.token.startsWith("kv_")).toBe(true);
		expect(body.agent.permissions).toHaveLength(1);

		const rows = await h.auth.db.select().from(agents).where(eq(agents.id, body.agent.id));
		expect(rows[0]?.tokenHash).toBeTruthy();
		expect(rows[0]?.tokenHash).not.toBe(body.token);
		expect(JSON.stringify(rows[0])).not.toContain(body.token);
	});

	it("allows a permitted action and denies a forbidden one with a reason", async () => {
		const h = await makeHarness();
		const { body } = await create(h, "reader");

		const allowed = (await (
			await h.call("/api/authorize", {
				body: { agentId: body.agent.id, action: "read", resource: "docs:handbook" },
			})
		).json()) as AuthorizeBody;
		expect(allowed.allowed).toBe(true);
		expect(allowed.auditId).toBeTruthy();

		const denied = (await (
			await h.call("/api/authorize", {
				body: { agentId: body.agent.id, action: "write", resource: "docs:handbook" },
			})
		).json()) as AuthorizeBody;
		expect(denied.allowed).toBe(false);
		expect(denied.reason).toContain("write");
	});

	it("lists audit rows for the agent with action, resource, result and time", async () => {
		const h = await makeHarness();
		const { body } = await create(h, "reader");
		await h.call("/api/authorize", {
			body: { agentId: body.agent.id, action: "read", resource: "docs:a" },
		});
		await h.call("/api/authorize", {
			body: { agentId: body.agent.id, action: "delete", resource: "billing:invoices" },
		});

		const audit = (await (await h.call(`/api/audit?agentId=${body.agent.id}`)).json()) as AuditBody;
		expect(audit.rows).toHaveLength(2);
		const results = audit.rows.map((r) => r.result).sort();
		expect(results).toEqual(["allowed", "denied"]);
		for (const row of audit.rows) {
			expect(row.agentId).toBe(body.agent.id);
			expect(Number.isNaN(Date.parse(row.at))).toBe(false);
		}
	});

	it("denies after revoke and records the denied retry", async () => {
		const h = await makeHarness();
		const { body } = await create(h, "editor");
		const request = { agentId: body.agent.id, action: "write", resource: "docs:handbook" };

		const before = (await (
			await h.call("/api/authorize", { body: request })
		).json()) as AuthorizeBody;
		expect(before.allowed).toBe(true);

		const revoke = await h.call(`/api/agents/${body.agent.id}/revoke`, { method: "POST" });
		expect(revoke.status).toBe(200);

		const after = (await (
			await h.call("/api/authorize", { body: request })
		).json()) as AuthorizeBody;
		expect(after.allowed).toBe(false);
		expect(after.reason).toContain("revoked");

		const audit = (await (await h.call(`/api/audit?agentId=${body.agent.id}`)).json()) as AuditBody;
		expect(audit.rows).toHaveLength(2);
		expect(audit.rows.filter((r) => r.result === "denied")).toHaveLength(1);
	});

	it("kicks in the per client rate limit with a 429 and Retry-After", async () => {
		const h = await makeHarness({ requestsPerMinute: 3 });
		const statuses: number[] = [];
		let retryAfter: string | null = null;
		for (let i = 0; i < 5; i++) {
			const res = await h.call("/api/info", { ip: "198.51.100.9" });
			statuses.push(res.status);
			if (res.status === 429) retryAfter = res.headers.get("retry-after");
		}
		expect(statuses).toEqual([200, 200, 200, 429, 429]);
		expect(Number(retryAfter)).toBeGreaterThan(0);

		// A different client IP has its own bucket.
		const other = await h.call("/api/info", { ip: "198.51.100.10" });
		expect(other.status).toBe(200);
	});

	it("ignores x-forwarded-for, so it cannot be used to dodge the limit", async () => {
		const h = await makeHarness({ requestsPerMinute: 2 });
		const codes: number[] = [];
		for (let i = 0; i < 4; i++) {
			const res = await h.app.request("/api/info", {
				headers: { "cf-connecting-ip": "192.0.2.1", "x-forwarded-for": `10.0.0.${i}` },
			});
			codes.push(res.status);
		}
		expect(codes).toEqual([200, 200, 429, 429]);
	});

	it("caps agents per client and across the instance", async () => {
		const h = await makeHarness({ maxAgentsPerClient: 2, maxAgents: 3 });
		expect((await create(h, "reader", "192.0.2.10")).res.status).toBe(201);
		expect((await create(h, "reader", "192.0.2.10")).res.status).toBe(201);
		const capped = await create(h, "reader", "192.0.2.10");
		expect(capped.res.status).toBe(429);

		expect((await create(h, "reader", "192.0.2.11")).res.status).toBe(201);
		const full = await create(h, "reader", "192.0.2.12");
		expect(full.res.status).toBe(503);
	});

	it("caps actions per agent", async () => {
		const h = await makeHarness({ maxActionsPerAgent: 2 });
		const { body } = await create(h);
		const req = { agentId: body.agent.id, action: "read", resource: "docs:a" };
		expect((await h.call("/api/authorize", { body: req })).status).toBe(200);
		expect((await h.call("/api/authorize", { body: req })).status).toBe(200);
		expect((await h.call("/api/authorize", { body: req })).status).toBe(429);
	});

	it("rejects malformed input", async () => {
		const h = await makeHarness();
		const badName = await h.call("/api/agents", { body: { name: "<script>", preset: "reader" } });
		expect(badName.status).toBe(400);
		const badPreset = await h.call("/api/agents", { body: { name: "ok", preset: "admin" } });
		expect(badPreset.status).toBe(400);
		const badAction = await h.call("/api/authorize", {
			body: { agentId: "x", action: "READ!", resource: "docs:a" },
		});
		expect(badAction.status).toBe(400);
	});

	it("cleanup removes expired agents and their audit rows", async () => {
		const h = await makeHarness();
		const { body } = await create(h);
		await h.call("/api/authorize", {
			body: { agentId: body.agent.id, action: "read", resource: "docs:a" },
		});
		expect(await countAgents(h.auth)).toBe(1);

		expect(await cleanupExpired(h.auth, new Date(Date.now() - 60_000))).toBe(0);
		expect(await cleanupExpired(h.auth, new Date(Date.now() + 60_000))).toBe(1);
		expect(await countAgents(h.auth)).toBe(0);

		const audit = (await (await h.call(`/api/audit?agentId=${body.agent.id}`)).json()) as AuditBody;
		expect(audit.rows).toHaveLength(0);
	});

	it("stores a fingerprint, never the raw IP", async () => {
		const h = await makeHarness();
		const { body } = await create(h, "reader", "203.0.113.99");
		await h.call("/api/authorize", {
			body: { agentId: body.agent.id, action: "read", resource: "docs:a" },
		});
		const rows = await h.auth.db.select().from(agents);
		expect(JSON.stringify(rows)).not.toContain("203.0.113.99");
	});
});
