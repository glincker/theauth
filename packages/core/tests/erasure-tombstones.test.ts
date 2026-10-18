/** Dialect-neutral erasure: tombstone rows replace the old PRAGMA foreign_keys toggle. */

import { and, eq, sql } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { enableAuditChain, insertAuditRow, verifyAuditChain } from "../src/audit/index.js";
import { createGdprModule } from "../src/auth/gdpr.js";
import type { FilterClause } from "../src/auth/scim-helpers.js";
import { buildUserSqlConditions } from "../src/auth/scim-helpers.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, organizations, users } from "../src/db/schema.js";

const KEY = "tombstone-test-key";
const T0 = new Date("2026-10-01T00:00:00Z");

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	for (const id of ["u1", "u2", "u3"]) {
		await db.insert(users).values({
			id,
			email: `${id}@Example.com`,
			username: id,
			createdAt: T0,
			updatedAt: T0,
		});
	}
	for (const [id, owner] of [
		["a1", "u1"],
		["a2", "u2"],
	] as const) {
		await db.insert(agents).values({
			id,
			ownerId: owner,
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

function row(id: string, agentId: string, userId: string, secs: number) {
	return {
		id,
		agentId,
		userId,
		action: "execute",
		resource: `mcp:test:${id}`,
		parameters: {},
		result: "allowed" as const,
		durationMs: 1,
		timestamp: new Date(T0.getTime() + secs * 1000),
	};
}

async function fkViolations(db: Database): Promise<unknown[]> {
	return (await db.all(sql`PRAGMA foreign_key_check`)) as unknown[];
}

describe("GDPR erasure with tombstones", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
		enableAuditChain(db, { hmacKey: KEY });
	});

	it("keeps FK enforcement on and leaves no dangling reference (keep logs)", async () => {
		await insertAuditRow(db, row("r1", "a1", "u1", 1));
		await insertAuditRow(db, row("r2", "a1", "u1", 2));
		await createGdprModule(db).deleteUser("u1", { keepAuditLogs: true });

		expect(await fkViolations(db)).toEqual([]);
		expect(await db.select().from(users).where(eq(users.id, "u1"))).toHaveLength(0);
		const logs = await db.select().from(auditLogs);
		const anonUser = logs[0]?.userId ?? "";
		const anonAgent = logs[0]?.agentId ?? "";
		expect(anonUser).toMatch(/^\[deleted-[0-9a-f]{12}\]$/);
		const tombUser = (await db.select().from(users).where(eq(users.id, anonUser)))[0];
		expect(tombUser?.banned).toBe(1);
		expect(tombUser?.email.endsWith("@erased.invalid")).toBe(true);
		const tombAgent = (await db.select().from(agents).where(eq(agents.id, anonAgent)))[0];
		expect(tombAgent?.status).toBe("revoked");
		expect(tombAgent?.tokenHash.startsWith("erased:")).toBe(true);
		// the surviving revoked agent no longer names the erased user
		const survivor = (await db.select().from(agents).where(eq(agents.id, "a1")))[0];
		expect(survivor?.status).toBe("revoked");
		expect(survivor?.ownerId).toBe(anonUser);
		// version 2 hashes cover pseudonyms, so the chain still verifies after repointing
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.ok).toBe(true);
	});

	it("leaves no dangling reference when deleting logs", async () => {
		await insertAuditRow(db, row("r1", "a1", "u1", 1));
		await createGdprModule(db).deleteUser("u1", { keepAuditLogs: false });
		expect(await fkViolations(db)).toEqual([]);
		expect(await db.select().from(agents).where(eq(agents.id, "a1"))).toHaveLength(0);
		const result = await verifyAuditChain(db, {}, KEY);
		expect(result.success && result.data.ok).toBe(true);
	});

	it("erases rows the user caused on another user's agent and for a user with no agents", async () => {
		await insertAuditRow(db, row("r1", "a2", "u3", 1));
		await insertAuditRow(db, row("r2", "a2", "u2", 2));
		const result = await createGdprModule(db).deleteUser("u3", { keepAuditLogs: true });
		expect(result.anonymizedAuditLogs).toBe(1);
		const r1 = (await db.select().from(auditLogs).where(eq(auditLogs.id, "r1")))[0];
		expect(r1?.userId).toMatch(/^\[deleted-/);
		expect(r1?.agentId).toBe("a2");
		expect(await fkViolations(db)).toEqual([]);
		const verify = await verifyAuditChain(db, {}, KEY);
		expect(verify.success && verify.data.ok).toBe(true);
	});

	it("moves a kept organization to the tombstone user", async () => {
		await db.insert(organizations).values({
			id: "o1",
			name: "Org",
			slug: "org",
			ownerId: "u3",
			createdAt: T0,
			updatedAt: T0,
		});
		await createGdprModule(db).deleteUser("u3", { keepAuditLogs: false });
		const org = (await db.select().from(organizations).where(eq(organizations.id, "o1")))[0];
		expect(org?.ownerId).toMatch(/^\[deleted-/);
		expect(await fkViolations(db)).toEqual([]);
	});

	it("is repeatable: two erasures share nothing and a re-run of one tombstone is idempotent", async () => {
		await insertAuditRow(db, row("r1", "a1", "u1", 1));
		await insertAuditRow(db, row("r2", "a2", "u2", 1));
		const mod = createGdprModule(db);
		await mod.deleteUser("u1", { keepAuditLogs: true });
		await mod.deleteUser("u2", { keepAuditLogs: true });
		const tombs = await db.select().from(users).where(sql`${users.email} LIKE '%@erased.invalid'`);
		expect(tombs).toHaveLength(2);
		expect(await fkViolations(db)).toEqual([]);
	});
});

describe("SCIM user filters are case insensitive (RFC 7644 userName and emails.value)", () => {
	it("matches eq, co and sw regardless of case, on username and email", async () => {
		const db = await setup();
		const find = async (attribute: string, op: FilterClause["op"], value: string) => {
			const conds = buildUserSqlConditions([{ attribute, op, value }]);
			expect(conds).not.toBeNull();
			return db
				.select({ id: users.id })
				.from(users)
				.where(and(...(conds ?? [])));
		};
		expect(await find("username", "eq", "U1")).toHaveLength(1);
		expect(await find("username", "co", "EXAMPLE")).toHaveLength(3);
		expect(await find("username", "sw", "U2@EX")).toHaveLength(1);
		expect(await find("emails.value", "eq", "u1@example.COM")).toHaveLength(1);
		expect(await find("emails.value", "co", "AMPLE.c")).toHaveLength(3);
		expect(await find("emails.value", "sw", "U3")).toHaveLength(1);
		// wildcards in the value are literal
		expect(await find("emails.value", "co", "%")).toHaveLength(0);
		expect(await find("emails.value", "co", "u_")).toHaveLength(0);
	});
});
