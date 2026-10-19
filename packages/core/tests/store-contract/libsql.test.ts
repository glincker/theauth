import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { afterAll, describe, expect, it } from "vitest";
import { runStoreContract } from "../../../test-utils/src/store-contract/index.js";
import { createTheAuth } from "../../src/theauth.js";
import { bootTarget } from "./boot.js";

/** libSQL (the engine behind Turso) on a real file: the preset and a bring-your-own handle. */
const dir = mkdtempSync(join(tmpdir(), "theauth-libsql-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

runStoreContract("libsql preset (file)", () =>
	bootTarget(() => ({ provider: "libsql", url: `file:${join(dir, "preset.db")}` }), true),
);

runStoreContract("drizzle instance (libsql file)", () =>
	bootTarget(
		() => ({
			drizzle: drizzle(createClient({ url: `file:${join(dir, "byo.db")}` })),
			dialect: "sqlite",
		}),
		true,
	),
);

describe("libsql preset", () => {
	const url = () => `file:${join(dir, "persist.db")}`;

	it("keeps data across a restart", async () => {
		const first = await createTheAuth({ database: { provider: "libsql", url: url() } });
		const user = await first.user.create({ email: "persist@example.com" });
		const second = await createTheAuth({ database: { provider: "libsql", url: url() } });
		expect((await second.user.get("persist@example.com"))?.id).toBe(user.id);
	});

	it("verifies the schema with skipMigrations once it exists", async () => {
		await createTheAuth({ database: { provider: "libsql", url: `file:${join(dir, "skip.db")}` } });
		const again = await createTheAuth({
			database: { provider: "libsql", url: `file:${join(dir, "skip.db")}`, skipMigrations: true },
		});
		expect((await again.schema.status()).pending).toEqual([]);
	});

	it("fails boot with SchemaOutdatedError on an empty database with skipMigrations", async () => {
		await expect(
			createTheAuth({
				database: {
					provider: "libsql",
					url: `file:${join(dir, "empty.db")}`,
					skipMigrations: true,
				},
			}),
		).rejects.toThrow();
	});
});
