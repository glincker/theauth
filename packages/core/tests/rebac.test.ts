/** Tests for the ReBAC (Relationship-Based Access Control) engine. */

import { beforeEach, describe, expect, it } from "vitest";
import type { ReBACModule } from "../src/auth/rebac.js";
import { createReBACModule } from "../src/auth/rebac.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

describe("ReBACModule", () => {
	let db: Database;
	let rebac: ReBACModule;

	beforeEach(async () => {
		db = await createTestDb();
		rebac = createReBACModule({}, db);
	});

	describe("createResource", () => {
		it("creates a root resource", async () => {
			const result = await rebac.createResource({ id: "org1", type: "org" });
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.id).toBe("org1");
				expect(result.data.type).toBe("org");
			}
		});

		it("creates a child resource with parent", async () => {
			await rebac.createResource({ id: "org1", type: "org" });
			const result = await rebac.createResource({
				id: "ws1",
				type: "workspace",
				parentId: "org1",
				parentType: "org",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.parentId).toBe("org1");
				expect(result.data.parentType).toBe("org");
			}
		});

		it("fails when parent does not exist", async () => {
			const result = await rebac.createResource({
				id: "ws1",
				type: "workspace",
				parentId: "nonexistent",
				parentType: "org",
			});
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("PARENT_NOT_FOUND");
			}
		});

		it("fails when resource already exists", async () => {
			await rebac.createResource({ id: "org1", type: "org" });
			const result = await rebac.createResource({ id: "org1", type: "org" });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("RESOURCE_EXISTS");
			}
		});

		it("allows resources of different types with unique ids", async () => {
			await rebac.createResource({ id: "org_item1", type: "org" });
			const result = await rebac.createResource({ id: "proj_item1", type: "project" });
			expect(result.success).toBe(true);
		});
	});

	describe("deleteResource", () => {
		it("deletes a resource", async () => {
			await rebac.createResource({ id: "org1", type: "org" });
			const result = await rebac.deleteResource("org", "org1");
			expect(result.success).toBe(true);

			const get = await rebac.getResource("org", "org1");
			expect(get.success).toBe(true);
			if (get.success) expect(get.data).toBeNull();
		});

		it("cascades to child resources", async () => {
			await rebac.createResource({ id: "org1", type: "org" });
			await rebac.createResource({
				id: "ws1",
				type: "workspace",
				parentId: "org1",
				parentType: "org",
			});
			await rebac.deleteResource("org", "org1");

			const get = await rebac.getResource("workspace", "ws1");
			expect(get.success).toBe(true);
			if (get.success) expect(get.data).toBeNull();
		});

		it("removes relationships on the deleted resource", async () => {
			await rebac.createResource({ id: "org1", type: "org" });
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "org",
				objectId: "org1",
			});
			await rebac.deleteResource("org", "org1");

			const expanded = await rebac.expand({ type: "user", id: "u1" });
			expect(expanded.success).toBe(true);
			if (expanded.success) expect(expanded.data).toHaveLength(0);
		});
	});

	describe("getResource", () => {
		it("returns null for nonexistent resource", async () => {
			const result = await rebac.getResource("org", "nope");
			expect(result.success).toBe(true);
			if (result.success) expect(result.data).toBeNull();
		});

		it("returns the resource when it exists", async () => {
			await rebac.createResource({ id: "org1", type: "org" });
			const result = await rebac.getResource("org", "org1");
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data?.id).toBe("org1");
				expect(result.data?.type).toBe("org");
			}
		});
	});

	describe("addRelationship", () => {
		it("creates a relationship", async () => {
			const result = await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "org",
				objectId: "org1",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.id).toMatch(/^rel_/);
				expect(result.data.relation).toBe("owner");
			}
		});

		it("rejects duplicate relationship", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "org",
				objectId: "org1",
			});
			const result = await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "org",
				objectId: "org1",
			});
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.code).toBe("RELATIONSHIP_EXISTS");
			}
		});

		it("allows different relations for same subject-object pair", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "org",
				objectId: "org1",
			});
			const result = await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "org",
				objectId: "org1",
			});
			expect(result.success).toBe(true);
		});
	});

	describe("removeRelationship", () => {
		it("removes an existing relationship", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "project",
				objectId: "p1",
			});
			const result = await rebac.removeRelationship("user", "u1", "editor", "project", "p1");
			expect(result.success).toBe(true);

			const expanded = await rebac.expand({ type: "user", id: "u1" });
			expect(expanded.success).toBe(true);
			if (expanded.success) expect(expanded.data).toHaveLength(0);
		});

		it("succeeds silently when relationship does not exist", async () => {
			const result = await rebac.removeRelationship("user", "u1", "editor", "project", "p1");
			expect(result.success).toBe(true);
		});
	});

	describe("check", () => {
		it("grants direct access", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.allowed).toBe(true);
				expect(result.data.path).toBeDefined();
				expect(result.data.path!.length).toBeGreaterThan(0);
			}
		});

		it("grants implied access (editor implies viewer)", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "document",
				objectId: "doc1",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("grants implied access (owner implies editor)", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "document",
				objectId: "doc1",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "editor",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("grants implied access (owner implies viewer)", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "document",
				objectId: "doc1",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("denies when no relationship exists", async () => {
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});

		it("denies when relation does not imply permission", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "editor",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});

		it("grants inherited access through parent", async () => {
			await rebac.createResource({ id: "proj1", type: "project" });
			await rebac.createResource({
				id: "doc1",
				type: "document",
				parentId: "proj1",
				parentType: "project",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "proj1",
			});

			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.allowed).toBe(true);
				expect(result.data.path).toBeDefined();
				expect(result.data.path!.length).toBeGreaterThan(1);
			}
		});

		it("grants access through implied parent relation", async () => {
			// owner on project implies viewer, which inherits to document
			await rebac.createResource({ id: "proj1", type: "project" });
			await rebac.createResource({
				id: "doc1",
				type: "document",
				parentId: "proj1",
				parentType: "project",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "project",
				objectId: "proj1",
			});

			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("denies when parent has no matching permission", async () => {
			await rebac.createResource({ id: "proj1", type: "project" });
			await rebac.createResource({
				id: "doc1",
				type: "document",
				parentId: "proj1",
				parentType: "project",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "proj1",
			});

			// viewer on project does NOT imply editor on child document
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "editor",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});
	});

	describe("complex hierarchy (org > workspace > project > document)", () => {
		beforeEach(async () => {
			await rebac.createResource({ id: "acme", type: "org" });
			await rebac.createResource({
				id: "eng",
				type: "workspace",
				parentId: "acme",
				parentType: "org",
			});
			await rebac.createResource({
				id: "backend",
				type: "project",
				parentId: "eng",
				parentType: "workspace",
			});
			await rebac.createResource({
				id: "readme",
				type: "document",
				parentId: "backend",
				parentType: "project",
			});
		});

		it("org owner can view document four levels down", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "alice",
				relation: "owner",
				objectType: "org",
				objectId: "acme",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "alice",
				permission: "viewer",
				objectType: "document",
				objectId: "readme",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("workspace member can view project under that workspace", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "bob",
				relation: "member",
				objectType: "workspace",
				objectId: "eng",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "bob",
				permission: "viewer",
				objectType: "project",
				objectId: "backend",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("user with no relationships is denied", async () => {
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "stranger",
				permission: "viewer",
				objectType: "document",
				objectId: "readme",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});

		it("editor on workspace implies editor on child project", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "carol",
				relation: "editor",
				objectType: "workspace",
				objectId: "eng",
			});
			const result = await rebac.check({
				subjectType: "user",
				subjectId: "carol",
				permission: "editor",
				objectType: "project",
				objectId: "backend",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});
	});

	describe("max depth", () => {
		it("denies when depth limit is exceeded", async () => {
			// Create a deep chain: r0 > r1 > r2 > r3
			await rebac.createResource({ id: "r0", type: "project" });
			await rebac.createResource({
				id: "r1",
				type: "document",
				parentId: "r0",
				parentType: "project",
			});

			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "r0",
			});

			// With maxDepth=1, we can check r1 (depth 0 + 1 parent traversal)
			// but a module with maxDepth=0 should not traverse at all
			const shallow = createReBACModule({ maxDepth: 0 }, db);
			const result = await shallow.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "r1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});

		it("allows when within depth limit", async () => {
			await rebac.createResource({ id: "r0", type: "project" });
			await rebac.createResource({
				id: "r1",
				type: "document",
				parentId: "r0",
				parentType: "project",
			});

			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "r0",
			});

			const mod = createReBACModule({ maxDepth: 5 }, db);
			const result = await mod.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
				objectId: "r1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});
	});

	describe("listObjects", () => {
		it("lists directly accessible objects", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "p1",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "project",
				objectId: "p2",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u2",
				relation: "viewer",
				objectType: "project",
				objectId: "p3",
			});

			const result = await rebac.listObjects({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "project",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.sort()).toEqual(["p1", "p2"]);
			}
		});

		it("includes inherited objects", async () => {
			await rebac.createResource({ id: "proj1", type: "project" });
			await rebac.createResource({
				id: "doc1",
				type: "document",
				parentId: "proj1",
				parentType: "project",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "proj1",
			});

			const result = await rebac.listObjects({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "document",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data).toContain("doc1");
			}
		});

		it("returns empty array when no objects accessible", async () => {
			const result = await rebac.listObjects({
				subjectType: "user",
				subjectId: "nobody",
				permission: "viewer",
				objectType: "project",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data).toEqual([]);
		});
	});

	describe("listSubjects", () => {
		it("lists subjects with direct access", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "project",
				objectId: "p1",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u2",
				relation: "viewer",
				objectType: "project",
				objectId: "p1",
			});

			const result = await rebac.listSubjects({
				objectType: "project",
				objectId: "p1",
				permission: "viewer",
				subjectType: "user",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				// u1 (editor implies viewer) and u2 (direct viewer)
				expect(result.data.sort()).toEqual(["u1", "u2"]);
			}
		});

		it("includes subjects from parent inheritance", async () => {
			await rebac.createResource({ id: "proj1", type: "project" });
			await rebac.createResource({
				id: "doc1",
				type: "document",
				parentId: "proj1",
				parentType: "project",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "proj1",
			});

			const result = await rebac.listSubjects({
				objectType: "document",
				objectId: "doc1",
				permission: "viewer",
				subjectType: "user",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data).toContain("u1");
			}
		});

		it("returns empty array when no subjects have access", async () => {
			const result = await rebac.listSubjects({
				objectType: "project",
				objectId: "p1",
				permission: "editor",
				subjectType: "user",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data).toEqual([]);
		});
	});

	describe("expand", () => {
		it("returns all relationships for a subject", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "org",
				objectId: "org1",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "project",
				objectId: "p1",
			});

			const result = await rebac.expand({ type: "user", id: "u1" });
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data).toHaveLength(2);
				const relations = result.data.map((r) => r.relation).sort();
				expect(relations).toEqual(["editor", "owner"]);
			}
		});

		it("returns relationships where entity is the object", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "viewer",
				objectType: "project",
				objectId: "p1",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u2",
				relation: "editor",
				objectType: "project",
				objectId: "p1",
			});

			const result = await rebac.expand({ type: "project", id: "p1" });
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data).toHaveLength(2);
			}
		});

		it("returns empty for entity with no relationships", async () => {
			const result = await rebac.expand({ type: "user", id: "ghost" });
			expect(result.success).toBe(true);
			if (result.success) expect(result.data).toEqual([]);
		});
	});

	// Agent-specific checks

	describe("agent checks", () => {
		it("grants access to agent subject type", async () => {
			await rebac.addRelationship({
				subjectType: "agent",
				subjectId: "agent_001",
				relation: "viewer",
				objectType: "document",
				objectId: "doc1",
			});

			const result = await rebac.check({
				subjectType: "agent",
				subjectId: "agent_001",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});

		it("denies agent when only user has access", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "document",
				objectId: "doc1",
			});

			const result = await rebac.check({
				subjectType: "agent",
				subjectId: "agent_001",
				permission: "editor",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});

		it("agent inherits through parent hierarchy", async () => {
			await rebac.createResource({ id: "proj1", type: "project" });
			await rebac.createResource({
				id: "doc1",
				type: "document",
				parentId: "proj1",
				parentType: "project",
			});
			await rebac.addRelationship({
				subjectType: "agent",
				subjectId: "agent_002",
				relation: "editor",
				objectType: "project",
				objectId: "proj1",
			});

			const result = await rebac.check({
				subjectType: "agent",
				subjectId: "agent_002",
				permission: "viewer",
				objectType: "document",
				objectId: "doc1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});
	});

	describe("custom permission rules", () => {
		it("respects custom implies rules", async () => {
			const custom = createReBACModule(
				{
					permissionRules: {
						wiki: {
							implies: {
								admin: ["editor", "viewer", "commenter"],
								editor: ["viewer", "commenter"],
								commenter: ["viewer"],
							},
						},
					},
				},
				db,
			);

			await custom.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "commenter",
				objectType: "wiki",
				objectId: "w1",
			});

			const viewResult = await custom.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "wiki",
				objectId: "w1",
			});
			expect(viewResult.success).toBe(true);
			if (viewResult.success) expect(viewResult.data.allowed).toBe(true);

			const editResult = await custom.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "editor",
				objectType: "wiki",
				objectId: "w1",
			});
			expect(editResult.success).toBe(true);
			if (editResult.success) expect(editResult.data.allowed).toBe(false);
		});

		it("disables inheritance when inheritFromParent is not set", async () => {
			const custom = createReBACModule(
				{
					permissionRules: {
						secret: {
							implies: { owner: ["viewer"] },
						},
					},
				},
				db,
			);

			await custom.createResource({ id: "proj1", type: "project" });
			await custom.createResource({
				id: "s1",
				type: "secret",
				parentId: "proj1",
				parentType: "project",
			});
			await custom.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "owner",
				objectType: "project",
				objectId: "proj1",
			});

			const result = await custom.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "secret",
				objectId: "s1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(false);
		});

		it("selective inheritance with string array", async () => {
			const custom = createReBACModule(
				{
					permissionRules: {
						file: {
							implies: { owner: ["editor", "viewer"], editor: ["viewer"] },
							inheritFromParent: ["viewer"], // only viewer inherits
						},
					},
				},
				db,
			);

			await custom.createResource({ id: "proj1", type: "project" });
			await custom.createResource({
				id: "f1",
				type: "file",
				parentId: "proj1",
				parentType: "project",
			});
			await custom.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "project",
				objectId: "proj1",
			});

			const viewResult = await custom.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "file",
				objectId: "f1",
			});
			expect(viewResult.success).toBe(true);
			if (viewResult.success) expect(viewResult.data.allowed).toBe(true);

			// editor does NOT inherit
			const editResult = await custom.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "editor",
				objectType: "file",
				objectId: "f1",
			});
			expect(editResult.success).toBe(true);
			if (editResult.success) expect(editResult.data.allowed).toBe(false);
		});
	});

	describe("team relationships", () => {
		it("supports team as subject type", async () => {
			await rebac.addRelationship({
				subjectType: "team",
				subjectId: "team_eng",
				relation: "editor",
				objectType: "project",
				objectId: "p1",
			});

			const result = await rebac.check({
				subjectType: "team",
				subjectId: "team_eng",
				permission: "viewer",
				objectType: "project",
				objectId: "p1",
			});
			expect(result.success).toBe(true);
			if (result.success) expect(result.data.allowed).toBe(true);
		});
	});

	describe("edge cases", () => {
		it("handles unknown resource type gracefully (no rules = exact match only)", async () => {
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "custom_role",
				objectType: "gadget",
				objectId: "g1",
			});

			const exactResult = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "custom_role",
				objectType: "gadget",
				objectId: "g1",
			});
			expect(exactResult.success).toBe(true);
			if (exactResult.success) expect(exactResult.data.allowed).toBe(true);

			// no implies = no fallback
			const impliedResult = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "gadget",
				objectId: "g1",
			});
			expect(impliedResult.success).toBe(true);
			if (impliedResult.success) expect(impliedResult.data.allowed).toBe(false);
		});

		it("check returns path showing traversal", async () => {
			await rebac.createResource({ id: "ws1", type: "workspace" });
			await rebac.createResource({
				id: "proj1",
				type: "project",
				parentId: "ws1",
				parentType: "workspace",
			});
			await rebac.addRelationship({
				subjectType: "user",
				subjectId: "u1",
				relation: "editor",
				objectType: "workspace",
				objectId: "ws1",
			});

			const result = await rebac.check({
				subjectType: "user",
				subjectId: "u1",
				permission: "viewer",
				objectType: "project",
				objectId: "proj1",
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect(result.data.allowed).toBe(true);
				expect(result.data.path).toBeDefined();
				// Path should contain parent reference and inheritance step
				const pathStr = result.data.path!.join(" -> ");
				expect(pathStr).toContain("workspace:ws1");
				expect(pathStr).toContain("project:proj1");
			}
		});
	});
});
