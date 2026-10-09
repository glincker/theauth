import type BetterSqlite3 from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";

describe("audit chain columns on an existing database", () => {
	it("adds nullable columns to a pre-chain audit table and is safe to rerun", async () => {
		const db = await createDatabase({ provider: "sqlite-native", url: ":memory:" });
		await createTables(db, "sqlite-native");
		// Rebuild the audit table the way an older release created it.
		const client = (db as unknown as { $client: InstanceType<typeof BetterSqlite3> }).$client;
		client.exec("DROP INDEX theauth_audit_logs_chain");
		client.exec("ALTER TABLE theauth_audit_logs DROP COLUMN chain_seq");
		client.exec("ALTER TABLE theauth_audit_logs DROP COLUMN prev_hash");
		client.exec("ALTER TABLE theauth_audit_logs DROP COLUMN hash");

		await createTables(db, "sqlite-native");
		await createTables(db, "sqlite-native");

		const cols = client
			.prepare("PRAGMA table_info(theauth_audit_logs)")
			.all()
			.map((c) => (c as { name: string }).name);
		expect(cols).toEqual(expect.arrayContaining(["chain_seq", "prev_hash", "hash"]));
		const idx = client.prepare("PRAGMA index_list(theauth_audit_logs)").all();
		expect(idx.map((i) => (i as { name: string }).name)).toContain("theauth_audit_logs_chain");
	});
});
