/**
 * Tests for policy/rebac-bridge.ts.
 *
 * Verifies the bridge correctly maps policy-engine subject/resource shapes to
 * the ReBAC graph, handles wildcards and malformed inputs early, and surfaces
 * graph errors without leaking exceptions.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createReBACModule } from "../src/auth/rebac.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import type { RebacBridge } from "../src/policy/rebac-bridge.js";
import { createRebacBridge } from "../src/policy/rebac-bridge.js";
import type { PolicyDecisionSubject } from "../src/policy/types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite
// ─────────────────────────────────────────────────────────────────────────────

describe("createRebacBridge", () => {
	let db: Database;
	let bridge: RebacBridge;

	beforeEach(async () => {
		db = await createTestDb();
		bridge = createRebacBridge({ db });

		// Seed one resource and one relationship for positive-path tests.
		const rebac = createReBACModule({}, db);
		await rebac.createResource({ id: "doc-1", type: "doc" });
		await rebac.addRelationship({
			subjectType: "user",
			subjectId: "user-1",
			relation: "viewer",
			objectType: "doc",
			objectId: "doc-1",
		});
	});

	// ── Wildcard / malformed resource ─────────────────────────────────────────

	it("returns matched=false for wildcard resource 'doc:*'", async () => {
		const subject: PolicyDecisionSubject = { userId: "user-1" };
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:*",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:wildcard-resource-not-supported");
	});

	it("returns matched=false for resource with embedded wildcard 'doc:pre*fix'", async () => {
		const subject: PolicyDecisionSubject = { userId: "user-1" };
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:pre*fix",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:wildcard-resource-not-supported");
	});

	it("returns matched=false for malformed resource with no colon", async () => {
		const subject: PolicyDecisionSubject = { userId: "user-1" };
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "justastring",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:wildcard-resource-not-supported");
	});

	// ── Invalid subject combinations ──────────────────────────────────────────

	it("returns matched=false when subject has no identity fields set", async () => {
		const subject: PolicyDecisionSubject = {};
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:invalid-subject");
	});

	it("returns matched=false when subject has both agentId and userId set", async () => {
		const subject: PolicyDecisionSubject = { agentId: "agent-1", userId: "user-1" };
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:invalid-subject");
	});

	it("returns matched=false when all three subject fields are set", async () => {
		const subject: PolicyDecisionSubject = {
			agentId: "agent-1",
			userId: "user-1",
			orgId: "org-1",
		};
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:invalid-subject");
	});

	// ── Positive path: tuple exists ───────────────────────────────────────────

	it("returns matched=true when user has the relation on the resource", async () => {
		const subject: PolicyDecisionSubject = { userId: "user-1" };
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(true);
		expect(result.reason).toBe("rebac:matched");
	});

	it("resolves agentId subject type to 'agent' in the graph", async () => {
		const rebac = createReBACModule({}, db);
		await rebac.createResource({ id: "tool-1", type: "tool" });
		await rebac.addRelationship({
			subjectType: "agent",
			subjectId: "agent-99",
			relation: "owner",
			objectType: "tool",
			objectId: "tool-1",
		});

		const subject: PolicyDecisionSubject = { agentId: "agent-99" };
		const result = await bridge.checkRelation({
			subject,
			relation: "owner",
			resource: "tool:tool-1",
		});
		expect(result.matched).toBe(true);
		expect(result.reason).toBe("rebac:matched");
	});

	it("resolves orgId subject type to 'org' in the graph", async () => {
		const rebac = createReBACModule({}, db);
		await rebac.createResource({ id: "ws-1", type: "workspace" });
		await rebac.addRelationship({
			subjectType: "org",
			subjectId: "org-42",
			relation: "member",
			objectType: "workspace",
			objectId: "ws-1",
		});

		const subject: PolicyDecisionSubject = { orgId: "org-42" };
		const result = await bridge.checkRelation({
			subject,
			relation: "member",
			resource: "workspace:ws-1",
		});
		expect(result.matched).toBe(true);
		expect(result.reason).toBe("rebac:matched");
	});

	// ── Negative path: tuple absent ───────────────────────────────────────────

	it("returns matched=false with no-tuple reason when relation does not exist", async () => {
		const subject: PolicyDecisionSubject = { userId: "user-1" };
		const result = await bridge.checkRelation({
			subject,
			relation: "editor",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:no-tuple");
	});

	it("returns matched=false when resource exists but subject has no relation", async () => {
		const subject: PolicyDecisionSubject = { userId: "user-nobody" };
		const result = await bridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:no-tuple");
	});

	// ── Graph error handling ──────────────────────────────────────────────────

	it("returns matched=false with graph-query-failed when db throws", async () => {
		// Create a stub db that throws on select
		const throwingDb = new Proxy(db, {
			get(target, prop) {
				if (prop === "select") {
					return () => {
						throw new Error("simulated DB failure");
					};
				}
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				return (target as any)[prop];
			},
		});

		const errorBridge = createRebacBridge({ db: throwingDb as unknown as Database });
		const subject: PolicyDecisionSubject = { userId: "user-1" };
		const result = await errorBridge.checkRelation({
			subject,
			relation: "viewer",
			resource: "doc:doc-1",
		});
		expect(result.matched).toBe(false);
		expect(result.reason).toBe("rebac:graph-query-failed");
	});
});
