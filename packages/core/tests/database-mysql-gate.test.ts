import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";

describe("mysql provider gate", () => {
	it("throws THEAUTH_MYSQL_UNSUPPORTED without experimental: true", async () => {
		const attempt = createDatabase({
			provider: "mysql",
			url: "mysql://user:pass@127.0.0.1:3306/theauth",
		});
		await expect(attempt).rejects.toThrow(/THEAUTH_MYSQL_UNSUPPORTED/);
		await expect(attempt).rejects.toThrow(/docs\/choose-storage/);
	});

	it("passes the gate with experimental: true (the pool connects lazily, so no server is needed)", async () => {
		const attempt = createDatabase({
			provider: "mysql",
			url: "mysql://user:pass@127.0.0.1:3306/theauth",
			experimental: true,
		});
		await expect(attempt).resolves.toBeTruthy();
	});

	it("leaves sqlite and postgres configs unaffected", async () => {
		await expect(createDatabase({ provider: "sqlite", url: ":memory:" })).resolves.toBeTruthy();

		const pg = createDatabase({
			provider: "postgres",
			url: "postgres://user:pass@127.0.0.1:5432/theauth",
		});
		await pg.then(
			() => undefined,
			(err: unknown) => {
				expect(String(err)).not.toContain("THEAUTH_MYSQL_UNSUPPORTED");
			},
		);
	});
});
