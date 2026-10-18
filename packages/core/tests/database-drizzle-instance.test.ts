import BetterSqlite3 from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { describe, expect, it } from "vitest";
import { databaseProvider } from "../src/db/database.js";
import { SchemaOutdatedError } from "../src/db/migrate/index.js";
import { createTheAuth } from "../src/theauth.js";

function handle() {
	const sqlite = new BetterSqlite3(":memory:");
	sqlite.pragma("foreign_keys = ON");
	return { sqlite, db: drizzle(sqlite) };
}

describe("database: { drizzle, dialect }", () => {
	it("boots on a caller supplied better-sqlite3 handle, migrates, and does not close it", async () => {
		const { sqlite, db } = handle();
		const auth = await createTheAuth({ database: { drizzle: db, dialect: "sqlite" } });
		const user = await auth.user.create({ email: "byo@example.com" });
		expect(user.email).toBe("byo@example.com");
		expect((await auth.schema.status()).pending).toEqual([]);
		// The same handle is the one core queries.
		expect(auth.db).toBe(db);
		const row = sqlite.prepare("SELECT email FROM theauth_users").get() as { email: string };
		expect(row.email).toBe("byo@example.com");
		expect(sqlite.open).toBe(true);
		sqlite.close();
	});

	it("passes the dialect, not a provider, to migrations", () => {
		expect(databaseProvider({ drizzle: {}, dialect: "postgres" })).toBe("postgres");
		expect(databaseProvider({ provider: "sqlite", url: ":memory:" })).toBe("sqlite");
	});

	it("with skipMigrations fails loudly on an unmigrated handle, and boots on a migrated one", async () => {
		const { sqlite, db } = handle();
		await expect(
			createTheAuth({ database: { drizzle: db, dialect: "sqlite", skipMigrations: true } }),
		).rejects.toBeInstanceOf(SchemaOutdatedError);
		await createTheAuth({ database: { drizzle: db, dialect: "sqlite" } });
		const again = await createTheAuth({
			database: { drizzle: db, dialect: "sqlite", skipMigrations: true },
		});
		expect((await again.schema.status()).pending).toEqual([]);
		sqlite.close();
	});

	it("rejects a bad dialect and a value that is not a Drizzle instance", async () => {
		const { sqlite, db } = handle();
		await expect(
			createTheAuth({ database: { drizzle: db, dialect: "oracle" as never } }),
		).rejects.toThrow(/THEAUTH_DRIZZLE_DIALECT/);
		await expect(createTheAuth({ database: { drizzle: {}, dialect: "sqlite" } })).rejects.toThrow(
			/THEAUTH_DRIZZLE_HANDLE/,
		);
		await expect(
			createTheAuth({ database: { drizzle: sqlite, dialect: "sqlite" } }),
		).rejects.toThrow(/THEAUTH_DRIZZLE_HANDLE/);
		sqlite.close();
	});
});
