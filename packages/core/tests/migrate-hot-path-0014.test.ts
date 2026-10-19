import { describe, expect, it } from "vitest";
import { MIGRATIONS, runMigrations } from "../src/db/migrate/index.js";
import { indexNames, ledgerIds, memoryDb } from "./helpers-schema-db.js";

/** Each hot lookup and the index its plan must use, so a dropped index shows up as a scan. */
const LOOKUPS: Array<[string, string, string]> = [
	[
		"agent by token hash",
		"SELECT * FROM theauth_agents WHERE token_hash = 'x' LIMIT 1",
		"theauth_agents_token_hash",
	],
	[
		"active agents of an owner",
		"SELECT count(*) FROM theauth_agents WHERE owner_id = 'x' AND status = 'active'",
		"theauth_agents_owner_status",
	],
	[
		"permissions of an agent",
		"SELECT * FROM theauth_permissions WHERE agent_id = 'x'",
		"theauth_permissions_agent",
	],
	[
		"inbound delegation links",
		"SELECT * FROM theauth_delegation_chains WHERE to_agent_id = 'x' AND status = 'active'",
		"theauth_delegation_chains_to",
	],
	[
		"outbound delegation links",
		"SELECT * FROM theauth_delegation_chains WHERE from_agent_id = 'x'",
		"theauth_delegation_chains_from",
	],
	[
		"hourly rate limit read",
		"SELECT * FROM theauth_rate_limits WHERE agent_id = 'x' AND resource = 'y' AND window_start > 1",
		"theauth_rate_limits_lookup",
	],
	[
		"pending approvals",
		"SELECT * FROM theauth_approval_requests WHERE status = 'pending' ORDER BY created_at DESC LIMIT 50",
		"theauth_approval_requests_status",
	],
];

describe("migration 0014-hot-path-indexes on SQLite", () => {
	it("adds the indexes on top of a 0013 database without touching rows", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite", {
			to: "0013",
			config: { agents: { enabled: true } } as never,
		});
		expect(await ledgerIds(exec)).not.toContain("0014");
		await exec.run(
			"INSERT INTO theauth_users (id, email, name, created_at, updated_at) VALUES ('u1', 'u1@example.com', 'U1', 1700000000, 1700000000)",
		);
		const result = await runMigrations(db, "sqlite", {
			config: { agents: { enabled: true } } as never,
		});
		expect(result.applied).toContain("0014");
		expect(await ledgerIds(exec)).toContain("0014");
		expect(await exec.all("SELECT email AS e FROM theauth_users")).toEqual([
			{ e: "u1@example.com" },
		]);
		expect(await indexNames(exec, "theauth_agents")).toEqual(
			expect.arrayContaining(["theauth_agents_token_hash", "theauth_agents_owner_status"]),
		);
	});

	it("rerunning the statements is harmless", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		const migration = MIGRATIONS.find((m) => m.id === "0014");
		if (!migration) throw new Error("0014 missing");
		for (const sql of migration.up.sqlite) await exec.run(sql);
	});

	it.each(LOOKUPS)("%s uses an index, not a table scan", async (_label, sql, index) => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		const plan = (await exec.all(`EXPLAIN QUERY PLAN ${sql}`))
			.map((r) => String(r.detail))
			.join("\n");
		expect(plan).toContain(index);
		expect(plan).not.toMatch(/SCAN theauth_/);
	});
});
