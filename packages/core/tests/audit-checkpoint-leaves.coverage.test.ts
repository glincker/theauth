/**
 * Leaf construction, receipt key resolution and paging of the checkpoint leaf set.
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import type { LeafRow } from "../src/audit/checkpoint-leaves.js";
import {
	fieldValuesOf,
	loadLeaf,
	loadLeafSet,
	receiptFieldsFor,
	resolveReceiptKey,
} from "../src/audit/checkpoint-leaves.js";
import { RECEIPT_FIELDS_V1, RECEIPT_FIELDS_V2 } from "../src/audit/checkpoint-types.js";
import { enableAuditChain, insertAuditRow } from "../src/audit/index.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const HMAC = "leaves-coverage-key";
const T0 = new Date("2026-10-01T00:00:00Z");

async function setup(withKey = true): Promise<Database> {
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
	for (const id of ["a1", "a2"]) {
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
	enableAuditChain(db, withKey ? { hmacKey: HMAC } : {});
	return db;
}

async function add(db: Database, id: string, sec: number) {
	await insertAuditRow(db, {
		id,
		agentId: sec % 2 ? "a1" : "a2",
		userId: "u1",
		action: "execute",
		resource: `mcp:github:${id}`,
		parameters: { n: sec },
		result: "allowed",
		reason: null,
		durationMs: 5,
		timestamp: new Date(T0.getTime() + sec * 1000),
		approverId: "u1",
	});
}

async function rowOf(db: Database, id: string): Promise<LeafRow> {
	const rows = await db.select().from(auditLogs).where(eq(auditLogs.id, id)).limit(1);
	const row = rows[0];
	if (!row) throw new Error(`no row ${id}`);
	return row;
}

// Hashing 2000 rows through WebCrypto is quick alone but slow when the pre-push hook runs suites in parallel.
const PAGING_TIMEOUT_MS = 60_000;

describe("fieldValuesOf", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
		await add(db, "r1", 1);
	});

	it("refuses a row with a non-finite number instead of hashing it", async () => {
		const row = await rowOf(db, "r1");
		expect(() => fieldValuesOf({ ...row, durationMs: Number.NaN })).toThrow(/non-finite/);
		expect(() => fieldValuesOf({ ...row, tokensCost: Number.POSITIVE_INFINITY })).toThrow(
			/non-finite/,
		);
	});

	it("reads a numeric timestamp as epoch milliseconds", async () => {
		const row = await rowOf(db, "r1");
		const values = fieldValuesOf({ ...row, timestamp: T0.getTime() as unknown as Date });
		expect(values.timestamp).toBe(T0.getTime());
	});

	it("covers the version 1 field set, with agent and user ids and no v2 fields", async () => {
		const row = await rowOf(db, "r1");
		const v1 = fieldValuesOf({ ...row, hashVersion: 1 });
		expect(v1).toMatchObject({ agentId: row.agentId, userId: row.userId });
		expect(v1).not.toHaveProperty("policyVersion");
		const v2 = fieldValuesOf({ ...row, hashVersion: 2 });
		expect(v2).toHaveProperty("policyVersion");
		expect(v2).not.toHaveProperty("agentId");
	});

	it("hashes absent optional columns as null and an absent cache flag as false", async () => {
		const row = await rowOf(db, "r1");
		const bare = fieldValuesOf({
			...row,
			parameters: null,
			reason: null,
			tokensCost: null,
			ip: null,
			userAgent: null,
			cacheHit: null,
		});
		expect(bare).toMatchObject({
			parameters: null,
			reason: null,
			tokensCost: null,
			ip: null,
			userAgent: null,
			cacheHit: false,
		});
	});

	it("hashes absent version 2 columns as null", async () => {
		const row = await rowOf(db, "r1");
		const v2 = fieldValuesOf({
			...row,
			hashVersion: 2,
			policyVersion: null,
			delegationChain: null,
			inputProvenance: null,
			idPseudonyms: null,
		});
		expect(v2).toMatchObject({
			policyVersion: null,
			delegationChain: null,
			inputProvenance: null,
			idPseudonyms: null,
		});
	});

	it("treats a row with no hash version as version 1", async () => {
		const row = await rowOf(db, "r1");
		expect(fieldValuesOf({ ...row, hashVersion: null })).toHaveProperty("agentId", row.agentId);
	});

	it("selects the receipt field list by hash version", () => {
		expect(receiptFieldsFor(1)).toBe(RECEIPT_FIELDS_V1);
		expect(receiptFieldsFor(2)).toBe(RECEIPT_FIELDS_V2);
		expect(RECEIPT_FIELDS_V1).toContain("agentId");
		expect(RECEIPT_FIELDS_V2).toContain("policyVersion");
	});
});

describe("loadLeaf", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
		await add(db, "r1", 1);
		await add(db, "r2", 2);
	});

	it("returns undefined for a row that does not exist", async () => {
		expect(await loadLeaf(db, "missing", HMAC)).toBeUndefined();
	});

	it("returns undefined for a row that was never chained", async () => {
		await db.update(auditLogs).set({ hash: null }).where(eq(auditLogs.id, "r1"));
		expect(await loadLeaf(db, "r1", HMAC)).toBeUndefined();
	});

	it("builds the same leaf hash that the leaf set uses for that row", async () => {
		const set = await loadLeafSet(db, { since: null, until: null }, HMAC);
		const leaf = await loadLeaf(db, "r2", HMAC);
		expect(leaf).toBeDefined();
		const index = set.ids.indexOf("r2");
		expect(Array.from(leaf?.leafHash ?? [])).toEqual(Array.from(set.hashes[index] ?? []));
		expect(Object.keys(leaf?.commitments ?? {}).sort()).toEqual([...RECEIPT_FIELDS_V2].sort());
	});

	it("commits to the version 1 field list when the hash version is missing", async () => {
		await db.update(auditLogs).set({ hashVersion: null }).where(eq(auditLogs.id, "r1"));
		const leaf = await loadLeaf(db, "r1", HMAC);
		expect(Object.keys(leaf?.commitments ?? {}).sort()).toEqual([...RECEIPT_FIELDS_V1].sort());
	});

	it("commits to the version 1 field list for a version 1 row", async () => {
		await db.update(auditLogs).set({ hashVersion: 1 }).where(eq(auditLogs.id, "r1"));
		const leaf = await loadLeaf(db, "r1", HMAC);
		expect(Object.keys(leaf?.commitments ?? {}).sort()).toEqual([...RECEIPT_FIELDS_V1].sort());
	});
});

describe("resolveReceiptKey", () => {
	it("uses the configured audit key when no key is passed", async () => {
		const db = await setup(HMAC);
		expect(await resolveReceiptKey(db)).toBe(HMAC);
		expect(await resolveReceiptKey(db, "explicit")).toBe("explicit");
	});

	it("creates an installation secret once when no audit key is configured", async () => {
		const db = await setup(false);
		const first = await resolveReceiptKey(db);
		expect(first).toMatch(/^[0-9a-f]{64}$/);
		expect(await resolveReceiptKey(db)).toBe(first);
	});
});

describe("loadLeafSet range and limit", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
		for (let i = 1; i <= 5; i++) await add(db, `r${i}`, i);
	});

	it("limits the number of leaves in log order", async () => {
		const set = await loadLeafSet(db, { since: null, until: null }, HMAC, 2);
		expect(set.ids).toEqual(["r1", "r2"]);
		expect(set.hashes.length).toBe(2);
	});

	it("returns nothing for a zero limit", async () => {
		expect(await loadLeafSet(db, { since: null, until: null }, HMAC, 0)).toEqual({
			ids: [],
			hashes: [],
		});
	});

	it("bounds by since and until, both inclusive", async () => {
		const range = {
			since: T0.getTime() + 2000,
			until: T0.getTime() + 4000,
		};
		const set = await loadLeafSet(db, range, HMAC);
		expect(set.ids).toEqual(["r2", "r3", "r4"]);
	});

	it(
		"pages past a full page of rows without losing or repeating any",
		async () => {
			// Clone one chained row into many more, spread over the timestamp order.
			const source = await rowOf(db, "r1");
			const extra = 2001;
			const batch: LeafRow[] = [];
			for (let i = 0; i < extra; i++) {
				batch.push({
					...source,
					id: `bulk-${String(i).padStart(5, "0")}`,
					timestamp: new Date(T0.getTime() + (10 + i) * 1000),
					hash: i.toString(16).padStart(64, "0"),
					chainSeq: null,
					prevHash: null,
				});
			}
			for (let i = 0; i < batch.length; i += 40) {
				await db.insert(auditLogs).values(batch.slice(i, i + 40));
			}
			const set = await loadLeafSet(db, { since: null, until: null }, HMAC);
			expect(set.ids.length).toBe(5 + extra);
			expect(new Set(set.ids).size).toBe(5 + extra);
			expect(set.ids.slice(0, 5)).toEqual(["r1", "r2", "r3", "r4", "r5"]);
			expect(set.ids.at(-1)).toBe(`bulk-${String(extra - 1).padStart(5, "0")}`);
			expect(set.hashes.length).toBe(set.ids.length);
		},
		PAGING_TIMEOUT_MS,
	);
});
