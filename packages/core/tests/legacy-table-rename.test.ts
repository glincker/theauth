import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";

type RawDb = any;

const LEGACY = "ka" + "vach_users";

function raw(db: RawDb) {
	return db.session.client as { run: (sql: string) => void; exec: (sql: string) => unknown };
}

describe("createTables upgrades legacy tables in place", () => {
	it("renames a pre-existing legacy table and keeps its rows", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		const client = raw(db);
		const run = (sql: string) => (client.run ? client.run(sql) : client.exec(sql));

		run(
			`CREATE TABLE ${LEGACY} (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
		);
		run(
			`INSERT INTO ${LEGACY} (id, email, name, created_at, updated_at) VALUES ('u1','a@b.co','A',1,1)`,
		);

		await createTables(db, "sqlite");

		const users = await (db as RawDb).all("SELECT id, email FROM theauth_users");
		expect(JSON.stringify(users)).toContain("a@b.co");

		const legacyLeft = await (db as RawDb).all(
			`SELECT name FROM sqlite_master WHERE type='table' AND name='${LEGACY}'`,
		);
		expect(legacyLeft).toHaveLength(0);
	});

	it("is a no-op on a fresh database", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await expect(createTables(db, "sqlite")).resolves.toBeUndefined();
		await expect(createTables(db, "sqlite")).resolves.toBeUndefined();
	});
});
