/** Hook blocks write a chained audit row with decision_code; the decision_code column migration. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { verifyAuditChain } from "../src/audit/index.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";
import type { TheAuth } from "./hook-test-utils.js";
import { auditRows, delegateTo, makeTheAuth, newAgent, READ_GITHUB } from "./hook-test-utils.js";

const REQ = { action: "read", resource: "mcp:github:issues" };
async function verify(theauth: TheAuth, agentId: string) {
	const r = await verifyAuditChain(theauth.db, { agentId }, "test-key");
	if (!r.success) throw new Error(r.error.message);
	return r.data;
}

const never = () => new Promise<never>(() => {});

describe("hook block audit rows", () => {
	it("a deny writes one row and returns its id", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => ({
					decision: "deny",
					reason: "policy says no",
					guard: "demo-guard",
					ruleId: "r-1",
					metadata: { score: 9, flag: true },
				}),
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);

		const result = await theauth.authorize(agent.id, { ...REQ, arguments: { q: "x" } });

		expect(result).toMatchObject({ allowed: false, code: "hook_denied", reason: "policy says no" });
		expect(result.auditId).not.toBe("");
		const rows = await auditRows(theauth, agent.id);
		expect(rows).toHaveLength(1);
		const row = rows[0];
		expect(row?.id).toBe(result.auditId);
		expect(row?.result).toBe("denied");
		expect(row?.decisionCode).toBe("hook_denied");
		expect(row?.reason).toBe("policy says no");
		expect(row?.userId).toBe("user-1");
		expect(row?.actorId).toBe(agent.id);
		expect(row?.subjectId).toBe("user-1");
		expect(row?.parameters).toMatchObject({
			q: "x",
			theauthHook: {
				hook: "beforeAuthorize",
				outcome: "deny",
				guard: "demo-guard",
				ruleId: "r-1",
				metadata: { score: 9, flag: true },
			},
		});
	});

	it("a timeout row has hook_timeout and a duration near the timeout", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 40 },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		const row = (await auditRows(theauth, agent.id))[0];
		expect(row?.decisionCode).toBe("hook_timeout");
		expect(row?.durationMs).toBeGreaterThanOrEqual(30);
		expect(row?.durationMs).toBeLessThan(1000);
		expect(row?.parameters).toMatchObject({ theauthHook: { outcome: "timeout" } });
	});

	it("an error row has hook_error", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => {
					throw new Error("x");
				},
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		const row = (await auditRows(theauth, agent.id))[0];
		expect(row?.decisionCode).toBe("hook_error");
		expect(row?.parameters).toMatchObject({ theauthHook: { outcome: "error" } });
	});

	it("a delegated agent's row has the root owner as subject and the path as chain", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ allow: false }) },
		});
		const a = await newAgent(theauth, "a", READ_GITHUB, "user-1");
		const b = await newAgent(theauth, "b", [], "user-2");
		await delegateTo(theauth, a.id, b.id);
		await theauth.authorize(b.id, REQ);
		const row = (await auditRows(theauth, b.id))[0];
		expect(row?.userId).toBe("user-2");
		expect(row?.subjectId).toBe("user-1");
		expect(row?.delegationChain).toEqual([a.id, b.id]);
	});

	it("keeps the tamper-evident chain valid", async () => {
		const theauth = await makeTheAuth({
			tamperEvident: true,
			hooks: {
				beforeAuthorize: async (ctx) =>
					ctx.action === "write" ? { allow: false, reason: "no writes" } : undefined,
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		await theauth.authorize(agent.id, { action: "write", resource: "mcp:github:issues" });
		await theauth.authorize(agent.id, REQ);
		const res = await verify(theauth, agent.id);
		expect(res.ok).toBe(true);
		expect(res.checked).toBeGreaterThanOrEqual(3);
		const rows = await auditRows(theauth, agent.id);
		expect(rows.every((r) => r.chainSeq !== null)).toBe(true);
	});

	it("auditAll false writes no row and returns an empty auditId", async () => {
		const theauth = await makeTheAuth({
			auditAll: false,
			hooks: { beforeAuthorize: async () => ({ allow: false }) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		expect(result.allowed).toBe(false);
		expect(result.auditId).toBe("");
		expect(await auditRows(theauth, agent.id)).toHaveLength(0);
	});

	it("an unknown agent writes no row and does not call the hook", async () => {
		let called = false;
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async () => {
					called = true;
					return undefined;
				},
			},
		});
		const result = await theauth.authorize("ghost", REQ);
		expect(result.auditId).toBe("");
		expect(called).toBe(false);
		expect(await theauth.db.select().from(auditLogs)).toHaveLength(0);
	});

	it("fail open attaches the bypass to the allowed row", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: never },
			hookSafety: { timeoutMs: 20, onTimeout: "allow" },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const result = await theauth.authorize(agent.id, REQ);
		const row = (await auditRows(theauth, agent.id))[0];
		expect(row?.id).toBe(result.auditId);
		expect(row?.result).toBe("allowed");
		expect(row?.decisionCode).toBe("allowed");
		expect(row?.parameters).toMatchObject({ theauthHook: { outcome: "fail_open" } });
	});

	it("a tool argument named theauthHook cannot spoof the hook detail", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ allow: false }) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, { ...REQ, arguments: { theauthHook: "forged" } });
		const row = (await auditRows(theauth, agent.id))[0];
		expect(row?.parameters).toMatchObject({ theauthHook: { outcome: "deny" } });
	});

	it("policy.evaluate writes the same kind of row for a hook block", async () => {
		const theauth = await makeTheAuth({
			hooks: { beforeAuthorize: async () => ({ decision: "deny", reason: "p" }) },
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		const d = await theauth.policy.evaluate({ subject: { agentId: agent.id }, ...REQ });
		await new Promise((r) => setTimeout(r, 20));
		const rows = await auditRows(theauth, agent.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.id).toBe(d.auditId);
		expect(rows[0]?.decisionCode).toBe("hook_denied");
		expect(rows[0]?.parameters).toMatchObject({ theauthHook: { outcome: "deny" } });
	});
});

describe("decision_code on audit rows", () => {
	it("query({ codes }) returns only the matching rows; code maps to entry.code", async () => {
		const theauth = await makeTheAuth({
			hooks: {
				beforeAuthorize: async (ctx) =>
					ctx.action === "write" ? { allow: false, reason: "no" } : undefined,
			},
		});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		await theauth.authorize(agent.id, { action: "write", resource: "mcp:github:x" });
		await theauth.authorize(agent.id, { action: "delete", resource: "mcp:github:x" });

		const hook = await theauth.audit.query({ agentId: agent.id, codes: ["hook_denied"] });
		expect(hook).toHaveLength(1);
		expect(hook[0]?.code).toBe("hook_denied");
		const multi = await theauth.audit.query({
			agentId: agent.id,
			codes: ["allowed", "no_permission"],
		});
		expect(multi.map((e) => e.code).sort()).toEqual(["allowed", "no_permission"]);
	});

	it("ordinary rows carry no_permission and allowed", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		await theauth.authorize(agent.id, { action: "delete", resource: "mcp:other" });
		const codes = (await auditRows(theauth, agent.id)).map((r) => r.decisionCode).sort();
		expect(codes).toEqual(["allowed", "no_permission"]);
	});

	it("revoked agent rows carry agent_revoked", async () => {
		const theauth = await makeTheAuth({});
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.agent.revoke(agent.id);
		await theauth.authorize(agent.id, REQ);
		const rows = await auditRows(theauth, agent.id);
		expect(rows.map((r) => r.decisionCode)).toContain("agent_revoked");
	});

	it("the code is not part of the hash: changing it does not break the chain", async () => {
		const theauth = await makeTheAuth({ tamperEvident: true });
		const agent = await newAgent(theauth, "a", READ_GITHUB);
		await theauth.authorize(agent.id, REQ);
		await theauth.db
			.update(auditLogs)
			.set({ decisionCode: "no_permission" })
			.where(eq(auditLogs.agentId, agent.id));
		const res = await verify(theauth, agent.id);
		expect(res.ok).toBe(true);
	});
});

/** The audit table exactly as 1.3.0 created it (no decision_code). */
const OLD_DDL = `CREATE TABLE theauth_audit_logs (
  id           TEXT    NOT NULL PRIMARY KEY,
  agent_id     TEXT    NOT NULL REFERENCES theauth_agents(id),
  user_id      TEXT    NOT NULL REFERENCES theauth_users(id),
  action       TEXT    NOT NULL,
  resource     TEXT    NOT NULL,
  parameters   TEXT,
  result       TEXT    NOT NULL,
  reason       TEXT,
  duration_ms  INTEGER NOT NULL,
  tokens_cost  INTEGER,
  ip           TEXT,
  user_agent   TEXT,
  cache_hit    INTEGER NOT NULL DEFAULT 0,
  timestamp    INTEGER NOT NULL,
  chain_seq    INTEGER,
  prev_hash    TEXT,
  hash         TEXT,
  hash_version INTEGER,
  subject_id   TEXT,
  actor_id     TEXT,
  policy_version TEXT,
  approver_id  TEXT,
  delegation_chain TEXT,
  input_provenance TEXT,
  id_pseudonyms TEXT
)`;

describe("decision_code migration", () => {
	it("adds the column to an existing table, keeps old rows, and is idempotent", async () => {
		const { sql } = await import("drizzle-orm");
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		// Rebuild the audit table in its pre-change shape and insert an old row.
		await db.run(sql.raw("DROP INDEX IF EXISTS theauth_audit_logs_code"));
		await db.run(sql.raw("DROP TABLE theauth_audit_logs"));
		await db.run(sql.raw(OLD_DDL));
		// A database from before the ledger: drop the ledger so the upgrade path is exercised.
		await db.run(sql.raw("DROP TABLE theauth_schema_migrations"));
		const now = new Date();
		await db
			.insert(users)
			.values({ id: "u", email: "u@x.io", name: "U", createdAt: now, updatedAt: now });
		await db.insert(agents).values({
			id: "ag",
			ownerId: "u",
			name: "ag",
			type: "autonomous",
			tokenHash: "h",
			tokenPrefix: "kv_x",
			metadata: {},
			status: "active",
			createdAt: now,
			updatedAt: now,
		});
		await db.run(
			sql.raw(
				`INSERT INTO theauth_audit_logs (id, agent_id, user_id, action, resource, result, duration_ms, timestamp)
				 VALUES ('old1', 'ag', 'u', 'read', 'r', 'allowed', 0, ${Math.floor(now.getTime() / 1000)})`,
			),
		);

		await createTables(db, "sqlite");
		await createTables(db, "sqlite");

		const info = db.all<{ name: string }>(sql.raw("PRAGMA table_info(theauth_audit_logs)"));
		expect(info.filter((c) => c.name === "decision_code")).toHaveLength(1);
		const idx = db.all<{ name: string }>(sql.raw("PRAGMA index_list(theauth_audit_logs)"));
		expect(idx.map((i) => i.name)).toContain("theauth_audit_logs_code");
		const rows = await db.select().from(auditLogs).where(eq(auditLogs.id, "old1"));
		expect(rows[0]?.decisionCode).toBeNull();
	});
});
