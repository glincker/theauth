/** recordAuditEvent stays non-blocking but no longer fails silently. */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { enableAuditChain, verifyAuditChain } from "../src/audit/index.js";
import type { AuditWriteError } from "../src/audit/record.js";
import {
	getAuditWriteFailures,
	recordAuditEvent,
	setAuditWriteErrorHandler,
	WRITE_FAILED_ACTION,
} from "../src/audit/record.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const T0 = new Date("2026-10-01T00:00:00Z");

async function setup(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	await db.insert(users).values({
		id: "u1",
		email: "u1@example.com",
		name: "u1",
		username: "u1",
		createdAt: T0,
		updatedAt: T0,
	});
	await db.insert(agents).values({
		id: "a1",
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		status: "active",
		tokenHash: "h",
		tokenPrefix: "kv_x",
		metadata: {},
		createdAt: T0,
		updatedAt: T0,
	});
	return db;
}

const event = (action: string, agentId = "a1") => ({
	agentId,
	action,
	resource: "delegation:x",
	result: "allowed" as const,
});

describe("audit write failures", () => {
	let db: Database;
	beforeEach(async () => {
		db = await setup();
		enableAuditChain(db, { hmacKey: "k" });
	});

	it("counts failures, calls the handler and never throws", async () => {
		const seen: AuditWriteError[] = [];
		setAuditWriteErrorHandler(db, (info) => seen.push(info));
		// unknown agent: no owner to attribute the row to
		expect(await recordAuditEvent(db, event("delegation.create", "ghost"))).toBe(false);
		expect(await recordAuditEvent(db, event("delegation.create", "ghost"))).toBe(false);
		expect(getAuditWriteFailures(db)).toBe(2);
		expect(seen.map((s) => s.pendingFailures)).toEqual([1, 2]);
	});

	it("survives a throwing handler", async () => {
		setAuditWriteErrorHandler(db, () => {
			throw new Error("boom");
		});
		expect(await recordAuditEvent(db, event("delegation.create", "ghost"))).toBe(false);
		expect(getAuditWriteFailures(db)).toBe(1);
	});

	it("writes one audit.write_failed row, in the chain, before the next success", async () => {
		await recordAuditEvent(db, event("delegation.create", "ghost"));
		await recordAuditEvent(db, event("delegation.create", "ghost"));
		expect(await recordAuditEvent(db, event("approval.grant"))).toBe(true);
		expect(await recordAuditEvent(db, event("approval.grant"))).toBe(true);

		const rows = await db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.agentId, "a1"))
			.orderBy(auditLogs.chainSeq);
		expect(rows.map((r) => r.action)).toEqual([
			WRITE_FAILED_ACTION,
			"approval.grant",
			"approval.grant",
		]);
		expect(rows[0]?.parameters).toMatchObject({ failed: 2, markerSynthetic: true });
		const verified = await verifyAuditChain(db, {}, "k");
		expect(verified.success && verified.data.ok).toBe(true);
		expect(verified.success && verified.data.checked).toBe(3);
	});
});
