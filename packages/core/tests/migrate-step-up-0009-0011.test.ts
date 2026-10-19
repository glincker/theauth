import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrate/index.js";
import { columnsOf, ledgerIds, memoryDb } from "./helpers-schema-db.js";

describe("migrations 0009 (step-up and confirmation) and 0011 (oauth auth evidence) on SQLite", () => {
	it("adds nullable columns to a database at 0008 and keeps existing rows", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite", { to: "0008" });
		expect(await columnsOf(exec, "theauth_agents")).not.toContain("cnf");
		await exec.run(
			"INSERT INTO theauth_users (id, email, created_at, updated_at) VALUES ('u1', 'u1@x.test', 1700000000, 1700000000)",
		);
		await exec.run(
			"INSERT INTO theauth_agents (id, owner_id, name, type, status, token_hash, token_prefix, created_at, updated_at) VALUES ('a1', 'u1', 'a', 'autonomous', 'active', 'h', 'p', 1700000000, 1700000000)",
		);
		await exec.run(
			"INSERT INTO theauth_approval_requests (id, agent_id, user_id, action, resource, status, expires_at, created_at) VALUES ('r1', 'a1', 'u1', 'x', 'y', 'pending', 1900000000, 1700000000)",
		);

		await runMigrations(db, "sqlite");
		expect(await ledgerIds(exec)).toEqual(expect.arrayContaining(["0009", "0011"]));

		expect(await columnsOf(exec, "theauth_agents")).toContain("cnf");
		const approval = await columnsOf(exec, "theauth_approval_requests");
		expect(approval).toEqual(expect.arrayContaining(["required_acr", "max_auth_age"]));
		for (const table of ["theauth_oauth_authorization_codes", "theauth_oauth_access_tokens"]) {
			expect(await columnsOf(exec, table)).toEqual(
				expect.arrayContaining(["auth_acr", "auth_amr", "auth_time"]),
			);
		}

		const [agent] = await exec.all("SELECT cnf AS cnf FROM theauth_agents WHERE id = 'a1'");
		expect(agent).toEqual({ cnf: null });
		const [req] = await exec.all(
			"SELECT required_acr AS acr, max_auth_age AS age FROM theauth_approval_requests WHERE id = 'r1'",
		);
		expect(req).toEqual({ acr: null, age: null });
	});
});
