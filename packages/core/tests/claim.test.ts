import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { oauthStates } from "../src/auth/oauth/schema.js";
import { affectedRows, claimCount } from "../src/db/claim.js";
import { createDatabase } from "../src/db/database.js";
import { runMigrations } from "../src/db/migrate/index.js";

describe("affectedRows", () => {
	it("reads the count each driver reports", () => {
		expect(affectedRows({ changes: 2 })).toBe(2);
		expect(affectedRows({ rowCount: 3 })).toBe(3);
		expect(affectedRows({ rowsAffected: 1 })).toBe(1);
		// mysql2 resolves [ResultSetHeader, fields]
		expect(affectedRows([{ affectedRows: 1 }, undefined])).toBe(1);
		expect(affectedRows(undefined)).toBe(0);
		expect(affectedRows([])).toBe(0);
	});
});

describe("claimCount", () => {
	it("uses RETURNING when the builder has it", async () => {
		const query = Object.assign(Promise.resolve([{ id: "x" }]), {
			returning: async () => [{ id: "x" }, { id: "y" }],
		});
		expect(await claimCount(query)).toBe(2);
	});

	it("falls back to the affected row count when there is no RETURNING (MySQL)", async () => {
		expect(await claimCount(Promise.resolve([{ affectedRows: 1 }, undefined]))).toBe(1);
		expect(await claimCount(Promise.resolve([{ affectedRows: 0 }, undefined]))).toBe(0);
	});

	it("lets exactly one of two deletes win on a real database", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await runMigrations(db, "sqlite");
		const now = new Date();
		await db.insert(oauthStates).values({
			state: "s1",
			provider: "github",
			codeVerifier: "v",
			redirectUri: "https://app.example.test/cb",
			expiresAt: new Date(now.getTime() + 60_000),
			createdAt: now,
		});
		const run = () =>
			claimCount(db.delete(oauthStates).where(eq(oauthStates.state, "s1")), {
				state: oauthStates.state,
			});
		expect([await run(), await run()]).toEqual([1, 0]);
	});
});
