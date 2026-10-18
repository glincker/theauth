import { describe, expect, it } from "vitest";
import { MIGRATIONS, runMigrations } from "../src/db/migrate/index.js";
import { columnsOf, indexNames, ledgerIds, memoryDb } from "./helpers-schema-db.js";

const CIMD_COLUMNS = [
	"cimd_document",
	"cimd_digest",
	"cimd_fetched_at",
	"cimd_expires_at",
	"disabled_reason",
];
const BLOCK_COLUMNS = ["id", "kind", "value", "reason", "created_by", "created_at"];

describe("migration 0008-cimd on SQLite", () => {
	it("upgrades a 0006 database, keeps the existing client row and gives the new columns their defaults", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite", { to: "0006" });
		expect(await ledgerIds(exec)).not.toContain("0008");
		expect(await columnsOf(exec, "theauth_oauth_clients")).not.toContain("cimd_document");

		await exec.run(
			`INSERT INTO theauth_oauth_clients (id, client_id, client_name, redirect_uris, grant_types, response_types, disabled, created_at, updated_at) VALUES ('c1', 'client-1', 'Existing', '["https://x.test/cb"]', '["authorization_code"]', '["code"]', 0, 1700000000, 1700000000)`,
		);

		const result = await runMigrations(db, "sqlite");
		expect(result.applied).toEqual(["0007", "0008"]);
		expect(await ledgerIds(exec)).toEqual(MIGRATIONS.map((m) => m.id));

		const rows = await exec.all(
			"SELECT client_id AS cid, client_name AS name, disabled AS d, cimd_document AS doc, cimd_digest AS digest, cimd_fetched_at AS fetched, cimd_expires_at AS expires, disabled_reason AS reason, created_at AS created FROM theauth_oauth_clients WHERE id = 'c1'",
		);
		expect(rows).toEqual([
			{
				cid: "client-1",
				name: "Existing",
				d: 0,
				doc: null,
				digest: null,
				fetched: null,
				expires: null,
				reason: null,
				created: 1700000000,
			},
		]);
	});

	it("a fresh create has the CIMD columns and the blocks table with its unique rule index", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		const clientColumns = await columnsOf(exec, "theauth_oauth_clients");
		for (const column of CIMD_COLUMNS) expect(clientColumns).toContain(column);
		expect(await columnsOf(exec, "theauth_mcp_client_blocks")).toEqual(BLOCK_COLUMNS);
		expect(await indexNames(exec, "theauth_mcp_client_blocks")).toContain(
			"theauth_mcp_client_blocks_rule",
		);

		await exec.run(
			"INSERT INTO theauth_mcp_client_blocks (id, kind, value, created_at) VALUES ('b1', 'host', 'evil.test', 1700000000)",
		);
		await expect(
			exec.run(
				"INSERT INTO theauth_mcp_client_blocks (id, kind, value, created_at) VALUES ('b2', 'host', 'evil.test', 1700000001)",
			),
		).rejects.toThrow();
		await exec.run(
			"INSERT INTO theauth_mcp_client_blocks (id, kind, value, created_at) VALUES ('b3', 'url', 'evil.test', 1700000001)",
		);
	});

	it("a second run is a no-op", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		const before = await exec.all(
			"SELECT id AS id, applied_at AS at FROM theauth_schema_migrations ORDER BY id",
		);
		const again = await runMigrations(db, "sqlite");
		expect(again.applied).toEqual([]);
		const after = await exec.all(
			"SELECT id AS id, applied_at AS at FROM theauth_schema_migrations ORDER BY id",
		);
		expect(after).toEqual(before);
		expect(await columnsOf(exec, "theauth_oauth_clients")).toEqual(
			expect.arrayContaining(CIMD_COLUMNS),
		);
	});
});
