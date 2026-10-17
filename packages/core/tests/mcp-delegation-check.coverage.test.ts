/** The delegation_chains-backed store and the failure reasons of the live delegation check, end to end against a real database. */

import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, delegationChains, users } from "../src/db/schema.js";
import { checkLiveDelegation, createDbDelegationStore } from "../src/mcp/delegation-check.js";

const T0 = new Date("2026-10-01T00:00:00Z");
const FUTURE = new Date("2030-01-01T00:00:00Z");

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	await db.insert(users).values({
		id: "u1",
		email: "u1@example.com",
		name: "U1",
		username: "u1",
		createdAt: T0,
		updatedAt: T0,
	});
	for (const id of ["a1", "a2", "a3"]) {
		await db.insert(agents).values({
			id,
			ownerId: "u1",
			name: id,
			type: "autonomous",
			status: "active",
			tokenHash: `h-${id}`,
			tokenPrefix: "kv_x",
			metadata: {},
			createdAt: T0,
			updatedAt: T0,
		});
	}
	return db;
}

interface LinkInit {
	id: string;
	from: string;
	to: string;
	status?: "active" | "revoked" | "expired";
	expiresAt?: Date;
	createdAt?: Date;
}

async function link(db: Database, init: LinkInit): Promise<void> {
	await db.insert(delegationChains).values({
		id: init.id,
		fromAgentId: init.from,
		toAgentId: init.to,
		permissions: [],
		depth: 1,
		maxDepth: 3,
		status: init.status ?? "active",
		expiresAt: init.expiresAt ?? FUTURE,
		createdAt: init.createdAt ?? T0,
	});
}

describe("createDbDelegationStore", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	it("returns null when no link exists between the two agents", async () => {
		const store = createDbDelegationStore(db);
		expect(await store.findLink("a1", "a2")).toBeNull();
	});

	it("reports the status and expiry of a live link", async () => {
		await link(db, { id: "d1", from: "a1", to: "a2" });
		const found = await createDbDelegationStore(db).findLink("a1", "a2");
		expect(found?.status).toBe("active");
		expect(found?.expiresAt.getTime()).toBe(FUTURE.getTime());
	});

	it("prefers a live link over a newer revoked one for the same pair", async () => {
		await link(db, { id: "old-live", from: "a1", to: "a2", createdAt: T0 });
		await link(db, {
			id: "new-revoked",
			from: "a1",
			to: "a2",
			status: "revoked",
			createdAt: new Date(T0.getTime() + 1000),
		});
		const found = await createDbDelegationStore(db).findLink("a1", "a2");
		expect(found?.status).toBe("active");
	});

	it("falls back to a revoked link when no live link exists", async () => {
		await link(db, { id: "r1", from: "a1", to: "a2", status: "revoked" });
		const found = await createDbDelegationStore(db).findLink("a1", "a2");
		expect(found?.status).toBe("revoked");
	});

	it("does not treat a link as live once its expiry has passed", async () => {
		await link(db, { id: "e1", from: "a1", to: "a2", expiresAt: new Date("2020-01-01T00:00:00Z") });
		const found = await createDbDelegationStore(db).findLink("a1", "a2");
		expect(found?.expiresAt.getTime()).toBe(new Date("2020-01-01T00:00:00Z").getTime());
		const failure = await checkLiveDelegation(createDbDelegationStore(db), "a1", [{ sub: "a2" }]);
		expect(failure).toEqual({ from: "a1", to: "a2", reason: "expired" });
	});

	it("is directional: a link from b to a does not satisfy a to b", async () => {
		await link(db, { id: "rev", from: "a2", to: "a1" });
		expect(await createDbDelegationStore(db).findLink("a1", "a2")).toBeNull();
	});
});

describe("checkLiveDelegation over the database store", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
	});

	it("accepts a chain whose every link is live", async () => {
		await link(db, { id: "d1", from: "a1", to: "a2" });
		await link(db, { id: "d2", from: "a2", to: "a3" });
		const failure = await checkLiveDelegation(createDbDelegationStore(db), "a1", [
			{ sub: "a3" },
			{ sub: "a2" },
		]);
		expect(failure).toBeNull();
	});

	it("names the first missing link in the authority path", async () => {
		await link(db, { id: "d1", from: "a1", to: "a2" });
		const failure = await checkLiveDelegation(createDbDelegationStore(db), "a1", [
			{ sub: "a3" },
			{ sub: "a2" },
		]);
		expect(failure).toEqual({ from: "a2", to: "a3", reason: "missing" });
	});

	it("reports a revoked link with the raw ids from the token", async () => {
		await link(db, { id: "d1", from: "a1", to: "a2", status: "revoked" });
		const failure = await checkLiveDelegation(createDbDelegationStore(db), "a1", [{ sub: "a2" }]);
		expect(failure).toEqual({ from: "a1", to: "a2", reason: "revoked" });
	});

	it("treats a mapped empty string as unmapped", async () => {
		await link(db, { id: "d1", from: "a1", to: "a2" });
		const store = createDbDelegationStore(db);
		const failure = await checkLiveDelegation(store, "a1", [{ sub: "a2" }], {
			resolveActorAgentId: (actor) => (actor.sub === "a2" ? "" : actor.sub),
		});
		expect(failure).toEqual({ from: "a1", to: "a2", reason: "unmapped actor" });
		const allowed = await checkLiveDelegation(store, "a1", [{ sub: "a2" }], {
			resolveActorAgentId: (actor) => (actor.sub === "a2" ? "" : actor.sub),
			allowUnmappedActors: true,
		});
		expect(allowed).toBeNull();
	});
});
