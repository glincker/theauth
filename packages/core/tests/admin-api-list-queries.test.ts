/**
 * Admin list endpoints read a fixed number of times no matter how many rows they return, and keep the
 * output they had when they read once per row.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listPendingApprovals } from "../src/admin-api/approval-decisions.js";
import { delegationImpact } from "../src/admin-api/revocations.js";
import { listApproversMany } from "../src/approval/quorum.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	approvalRequests,
	approvalVotes,
	delegationChains,
	mcpRevocations,
	users,
} from "../src/db/schema.js";

let db: Database;
const now = new Date();
const later = new Date(Date.now() + 3_600_000);

beforeEach(async () => {
	db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite", {
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true },
		mcp: { enabled: true },
	} as never);
	await db
		.insert(users)
		.values({ id: "u1", email: "u1@example.com", name: "u1", createdAt: now, updatedAt: now });
	await db.insert(agents).values(
		["a1", "a2", "a3", "a4"].map((id) => ({
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
});

function countSelects(): { calls: () => number } {
	const spy = vi.spyOn(db, "select");
	return { calls: () => spy.mock.calls.length };
}

describe("listPendingApprovals", () => {
	it("reads quorum approvers in one query for the whole page, in vote order", async () => {
		const rows = Array.from({ length: 6 }, (_, i) => ({
			id: `ap${i}`,
			agentId: "a1",
			userId: "u1",
			action: "send",
			resource: `mail:${i}`,
			arguments: {},
			status: "pending" as const,
			expiresAt: later,
			createdAt: new Date(Date.now() - i * 1000),
			requiredApprovals: 3,
		}));
		await db.insert(approvalRequests).values(rows);
		await db.insert(approvalVotes).values([
			{ approvalId: "ap0", approverId: "zed", decidedAt: 2 },
			{ approvalId: "ap0", approverId: "amy", decidedAt: 1 },
			{ approvalId: "ap1", approverId: "bob", decidedAt: 5 },
			{ approvalId: "ap1", approverId: "al", decidedAt: 5 },
		]);
		const counter = countSelects();
		const list = await listPendingApprovals(db, 50);
		expect(counter.calls()).toBe(2);
		const byId = new Map(list.map((r) => [r.id, r]));
		expect(byId.get("ap0")).toMatchObject({ approvers: ["amy", "zed"], approvalsReceived: 2 });
		expect(byId.get("ap1")).toMatchObject({ approvers: ["al", "bob"], approvalsReceived: 2 });
		expect(byId.get("ap2")).toMatchObject({ approvers: [], approvalsReceived: 0 });
	});

	it("does not look up approvers for single approver requests", async () => {
		await db.insert(approvalRequests).values({
			id: "single",
			agentId: "a1",
			userId: "u1",
			action: "send",
			resource: "mail:x",
			arguments: {},
			status: "pending",
			expiresAt: later,
			createdAt: now,
		});
		const counter = countSelects();
		const list = await listPendingApprovals(db, 50);
		expect(list).toHaveLength(1);
		expect(list[0]).not.toHaveProperty("approvers");
		expect(counter.calls()).toBe(1);
	});

	it("listApproversMany answers every id, empty for no votes, none for no ids", async () => {
		expect((await listApproversMany(db, [])).size).toBe(0);
		const m = await listApproversMany(db, ["x", "y"]);
		expect(m.get("x")).toEqual([]);
		expect(m.get("y")).toEqual([]);
	});
});

describe("delegationImpact", () => {
	it("marks denied links and groups sibling links by delegator", async () => {
		const link = (id: string, from: string, to: string) => ({
			id,
			fromAgentId: from,
			toAgentId: to,
			permissions: [{ resource: "tool:*", actions: ["read"] }],
			depth: 1,
			maxDepth: 3,
			status: "active" as const,
			expiresAt: later,
			createdAt: now,
		});
		await db
			.insert(delegationChains)
			.values([link("l1", "a1", "a2"), link("l2", "a2", "a3"), link("l3", "a1", "a4")]);
		await db.insert(mcpRevocations).values([
			{
				kind: "dlg",
				id: "l2",
				revokedAtMs: 1,
				expiresAt: 4_000_000_000,
				reason: "x",
				sourceId: null,
			},
			{
				kind: "dlg",
				id: "gone-link",
				revokedAtMs: 1,
				expiresAt: 4_000_000_000,
				reason: "x",
				sourceId: null,
			},
			{
				kind: "jti",
				id: "l1",
				revokedAtMs: 1,
				expiresAt: 4_000_000_000,
				reason: "x",
				sourceId: null,
			},
		]);
		const view = await delegationImpact(db);
		const byId = new Map(view.map((v) => [v.id, v]));
		expect(byId.get("l1")).toMatchObject({
			denied: false,
			cascade: ["l1", "l2"],
			agents: ["a2", "a3"],
		});
		expect(byId.get("l2")?.denied).toBe(true);
		expect(byId.get("l3")?.denied).toBe(false);
	});
});
