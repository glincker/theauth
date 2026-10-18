import { randomUUID } from "node:crypto";
import { existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTheAuth } from "../src/theauth.js";

async function betterSqliteLoads(): Promise<boolean> {
	try {
		const mod = await import("better-sqlite3");
		const Ctor = mod.default;
		new Ctor(":memory:").close();
		return true;
	} catch {
		return false;
	}
}

const nativeAvailable = await betterSqliteLoads();
if (!nativeAvailable) {
	process.stderr.write(
		"SKIPPED: better-sqlite3 could not load, the sqlite-native persistence test is skipped.\n",
	);
}

describe("sqlite persistence guard", () => {
	it("throws THEAUTH_SQLITE_NOT_PERSISTENT for sql.js with a file url", async () => {
		const attempt = createDatabase({ provider: "sqlite", url: "./should-not-exist.db" });
		await expect(attempt).rejects.toThrow(/THEAUTH_SQLITE_NOT_PERSISTENT/);
		await expect(attempt).rejects.toThrow(/sqlite-native/);
		await expect(attempt).rejects.toThrow(/better-sqlite3/);
		await expect(attempt).rejects.toThrow(/:memory:/);
		expect(existsSync("./should-not-exist.db")).toBe(false);
	});

	it("also throws through createTheAuth", async () => {
		await expect(
			createTheAuth({ database: { provider: "sqlite", url: "theauth.db" } }),
		).rejects.toThrow(/THEAUTH_SQLITE_NOT_PERSISTENT/);
	});

	it("accepts :memory: and an empty url", async () => {
		await expect(createDatabase({ provider: "sqlite", url: ":memory:" })).resolves.toBeTruthy();
		await expect(createDatabase({ provider: "sqlite", url: "" })).resolves.toBeTruthy();
		const theauth = await createTheAuth({ database: { provider: "sqlite", url: ":memory:" } });
		const user = await theauth.user.create({ email: "mem@example.com", name: "Mem" });
		expect(user.email).toBe("mem@example.com");
	});

	it.skipIf(!nativeAvailable)(
		"sqlite-native persists data across two createTheAuth instances",
		async () => {
			const file = join(tmpdir(), `theauth-persist-${randomUUID()}.db`);
			try {
				const first = await createTheAuth({ database: { provider: "sqlite-native", url: file } });
				const created = await first.user.create({ email: "persist@example.com", name: "P" });
				expect(existsSync(file)).toBe(true);

				const second = await createTheAuth({ database: { provider: "sqlite-native", url: file } });
				const found = await second.user.get(created.id);
				expect(found?.email).toBe("persist@example.com");
			} finally {
				for (const suffix of ["", "-wal", "-shm"]) rmSync(`${file}${suffix}`, { force: true });
			}
		},
	);
});
