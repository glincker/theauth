import { describe, expect, it } from "vitest";
import { MIGRATIONS, runMigrations } from "../src/db/migrate/index.js";
import { columnsOf, indexNames, ledgerIds, memoryDb } from "./helpers-schema-db.js";

const COLUMNS = ["kind", "id", "revoked_at_ms", "expires_at", "reason", "source_id"];

describe("migration 0007-mcp-revocation on SQLite", () => {
	it("upgrades a 0006 database, keeps existing rows and adds the table and chain indexes", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite", { to: "0006" });
		expect(await ledgerIds(exec)).not.toContain("0007");
		await exec.run(
			"INSERT INTO theauth_users (id, email, name, created_at, updated_at) VALUES ('u1', 'u1@example.com', 'U1', 1700000000, 1700000000)",
		);
		await exec.run(
			"INSERT INTO theauth_oauth_clients (id, client_id, client_name, redirect_uris, grant_types, response_types, disabled, created_at, updated_at) VALUES ('c1', 'client-1', 'Existing', '[\"https://x.test/cb\"]', '[\"authorization_code\"]', '[\"code\"]', 0, 1700000000, 1700000000)",
		);

		const result = await runMigrations(db, "sqlite", { to: "0007" });
		expect(result.applied).toEqual(["0007"]);
		expect(await columnsOf(exec, "theauth_mcp_revocations")).toEqual(COLUMNS);
		expect(await indexNames(exec, "theauth_mcp_revocations")).toEqual(
			expect.arrayContaining(["theauth_mcp_revocations_exp", "theauth_mcp_revocations_ms"]),
		);
		expect(await indexNames(exec, "theauth_delegation_chains")).toEqual(
			expect.arrayContaining(["theauth_delegation_chains_to", "theauth_delegation_chains_from"]),
		);
		const clients = await exec.all("SELECT client_id AS cid FROM theauth_oauth_clients");
		expect(clients).toEqual([{ cid: "client-1" }]);
		const users = await exec.all("SELECT email AS e FROM theauth_users");
		expect(users).toEqual([{ e: "u1@example.com" }]);
	});

	it("a fresh create has the table, a composite primary key and every migration in the ledger", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		expect(await ledgerIds(exec)).toEqual(MIGRATIONS.map((m) => m.id));
		expect(await columnsOf(exec, "theauth_mcp_revocations")).toEqual(COLUMNS);
		await exec.run(
			"INSERT INTO theauth_mcp_revocations (kind, id, revoked_at_ms, expires_at, reason) VALUES ('jti', 'j1', 1, 2, 'r')",
		);
		await exec.run(
			"INSERT INTO theauth_mcp_revocations (kind, id, revoked_at_ms, expires_at, reason) VALUES ('sub', 'j1', 1, 2, 'r')",
		);
		await expect(
			exec.run(
				"INSERT INTO theauth_mcp_revocations (kind, id, revoked_at_ms, expires_at, reason) VALUES ('jti', 'j1', 3, 4, 'r')",
			),
		).rejects.toThrow();
	});

	it("a second run is a no-op", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		const again = await runMigrations(db, "sqlite");
		expect(again.applied).toEqual([]);
		expect(await ledgerIds(exec)).toEqual(MIGRATIONS.map((m) => m.id));
	});
});
