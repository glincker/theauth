/** Regression: the refresh token `used` column stores the consume time in epoch seconds, not a 0/1 flag. */

import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { columnKind } from "../src/db/schema/columns.js";
import { refreshTokens, users } from "../src/db/schema.js";
import { createTokenFamilyStore } from "../src/session/token-family.js";

async function setup(reuseGraceMs: number) {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	db.insert(users)
		.values({ id: "u1", email: "a@example.com", createdAt: new Date(), updatedAt: new Date() })
		.run();
	const store = createTokenFamilyStore(db, { reuseGraceMs });
	const family = await store.createFamily("u1", new Date(Date.now() + 86_400_000));
	const issued = await store.issueToken(family.id, 86_400_000);
	return { db, store, family, issued };
}

describe("refresh token used column", () => {
	it("is a bigint, not a flag", () => {
		expect(columnKind(refreshTokens.used)).toBe("bigint");
	});

	it("keeps the consume time in epoch seconds and 0 for unused", async () => {
		const { db, store, family, issued } = await setup(10_000);
		const read = async () =>
			(await db.select().from(refreshTokens).where(eq(refreshTokens.familyId, family.id)))[0]?.used;
		expect(await read()).toBe(0);
		const before = Math.floor(Date.now() / 1000);
		await store.consumeToken(issued.rawToken);
		const stored = await read();
		expect(stored).toBeGreaterThanOrEqual(before);
		expect(stored).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
	});

	it("accepts a replay inside the grace window and revokes after it", async () => {
		const { store, issued } = await setup(10_000);
		await store.consumeToken(issued.rawToken);
		const replay = await store.consumeToken(issued.rawToken);
		expect(replay.status).toBe("ok");
		expect(replay.graceReplay).toBe(true);
		expect(replay.family?.revoked).toBe(false);
		expect((await store.consumeToken(issued.rawToken, { graceMs: 0 })).status).toBe("reuse");
		expect((await store.consumeToken(issued.rawToken)).status).toBe("revoked");
	});

	it("treats a legacy used = 1 row as outside any window", async () => {
		const { db, store, family, issued } = await setup(10_000);
		await db.update(refreshTokens).set({ used: 1 }).where(eq(refreshTokens.familyId, family.id));
		expect((await store.consumeToken(issued.rawToken)).status).toBe("reuse");
	});
});
