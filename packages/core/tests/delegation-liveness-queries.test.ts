/** The delegator liveness walk reads each agent's inbound links once and answers the same as before. */
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, delegationChains, permissions, users } from "../src/db/schema.js";
import { getDelegatedPermissions } from "../src/delegation/delegation.js";

let db: Database;
const now = new Date();
const later = new Date(Date.now() + 3_600_000);
const earlier = new Date(Date.now() - 3_600_000);
const PERM = [{ resource: "tool:*", actions: ["read"] }];

async function chain(ids: string[]): Promise<void> {
	await db.insert(agents).values(
		ids.map((id) => ({
			id,
			ownerId: "u1",
			name: id,
			type: "autonomous",
			status: "active",
			tokenHash: `h${id}`,
			tokenPrefix: id,
			createdAt: now,
			updatedAt: now,
		})),
	);
	await db.insert(permissions).values({
		id: "p0",
		agentId: ids[0] as string,
		resource: "tool:*",
		actions: ["read"],
		createdAt: now,
	});
	for (let i = 0; i < ids.length - 1; i++) {
		await db.insert(delegationChains).values({
			id: `l${i + 1}`,
			fromAgentId: ids[i] as string,
			toAgentId: ids[i + 1] as string,
			permissions: PERM,
			depth: i + 1,
			maxDepth: 5,
			status: "active",
			expiresAt: later,
			createdAt: now,
		});
	}
}

beforeEach(async () => {
	db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite", {
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true },
	} as never);
	await db
		.insert(users)
		.values({ id: "u1", email: "u1@example.com", name: "u1", createdAt: now, updatedAt: now });
});

describe("getDelegatedPermissions", () => {
	it("a live three hop chain costs seven reads and grants the permission", async () => {
		await chain(["a0", "a1", "a2", "a3"]);
		const spy = vi.spyOn(db, "select");
		const perms = await getDelegatedPermissions(db, "a3");
		expect(perms).toEqual(PERM);
		expect(spy.mock.calls.length).toBe(7);
	});

	it("a revoked agent at the top takes the branch out", async () => {
		await chain(["a0", "a1", "a2"]);
		await db.update(agents).set({ status: "revoked" }).where(eq(agents.id, "a0"));
		await db.delete(permissions).where(eq(permissions.id, "p0"));
		expect(await getDelegatedPermissions(db, "a2")).toEqual([]);
	});

	it("an agent whose only inbound link expired is not self standing", async () => {
		await chain(["a0", "a1", "a2"]);
		await db
			.update(delegationChains)
			.set({ expiresAt: earlier })
			.where(eq(delegationChains.id, "l1"));
		await db.delete(permissions).where(eq(permissions.id, "p0"));
		expect(await getDelegatedPermissions(db, "a2")).toEqual([]);
	});

	it("an agent that never had inbound links stands on its own", async () => {
		await chain(["a0", "a1"]);
		expect(await getDelegatedPermissions(db, "a1")).toEqual(PERM);
	});
});
