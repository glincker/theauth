/**
 * Tests for SCIM audit logging.
 *
 * Every successful provisioning write on /Users or /Groups should produce
 * one row in `kavach_audit_logs` attributed to the configured system agent.
 * Failed writes (validation errors, 404s, 401s) must not produce rows.
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { ScimModule } from "../src/auth/scim.js";
import { createScimModule } from "../src/auth/scim.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, users } from "../src/db/schema.js";

const BEARER = "audit-token";
const BASE = "https://audit.example.com";
const AUDIT_AGENT_ID = "agent-scim-provisioner";

function req(method: string, path: string, body?: unknown, token = BEARER): Request {
	const headers: Record<string, string> = { "Content-Type": "application/scim+json" };
	if (token) headers.Authorization = `Bearer ${token}`;
	return new Request(`${BASE}${path}`, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined,
	});
}

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	const now = new Date();
	// Seed a system user the provisioner agent belongs to.
	await db.insert(users).values({
		id: "sys-owner",
		email: "system@example.com",
		name: "System",
		username: "system",
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(agents).values({
		id: AUDIT_AGENT_ID,
		ownerId: "sys-owner",
		name: "scim-provisioner",
		type: "service",
		status: "active",
		tokenHash: "placeholder-hash",
		tokenPrefix: "kv_sys",
		metadata: {},
		createdAt: now,
		updatedAt: now,
	});
	return db;
}

async function fetchAuditRows(db: Database): Promise<Array<Record<string, unknown>>> {
	return (await db.select().from(auditLogs)) as Array<Record<string, unknown>>;
}

describe("SCIM audit: user lifecycle", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule(
			{
				bearerToken: BEARER,
				audit: { agentId: AUDIT_AGENT_ID },
			},
			db,
		);
	});

	it("writes scim.user.create on POST /Users", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "alice@example.com",
				emails: [{ value: "alice@example.com", primary: true }],
			}),
		);
		expect(res?.status).toBe(201);
		const rows = await fetchAuditRows(db);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.action).toBe("scim.user.create");
		expect(rows[0]?.result).toBe("allowed");
		expect((rows[0]?.resource as string).startsWith("scim:users:")).toBe(true);
	});

	it("writes scim.user.replace on PUT /Users/:id", async () => {
		const created = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "bob@example.com",
				emails: [{ value: "bob@example.com", primary: true }],
			}),
		);
		const body = (await (created as Response).json()) as { id: string };

		const res = await mod.handleRequest(
			req("PUT", `/scim/v2/Users/${body.id}`, {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "bob@example.com",
				emails: [{ value: "bob-new@example.com", primary: true }],
			}),
		);
		expect(res?.status).toBe(200);

		const rows = await fetchAuditRows(db);
		const actions = rows.map((r) => r.action);
		expect(actions).toContain("scim.user.create");
		expect(actions).toContain("scim.user.replace");
	});

	it("writes scim.user.update on PATCH /Users/:id", async () => {
		const created = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "carol@example.com",
				emails: [{ value: "carol@example.com", primary: true }],
			}),
		);
		const body = (await (created as Response).json()) as { id: string };

		const res = await mod.handleRequest(
			req("PATCH", `/scim/v2/Users/${body.id}`, {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "active", value: false }],
			}),
		);
		expect(res?.status).toBe(200);

		const rows = await fetchAuditRows(db);
		expect(rows.map((r) => r.action)).toContain("scim.user.update");
	});

	it("writes scim.user.delete on DELETE /Users/:id", async () => {
		const created = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "dave@example.com",
				emails: [{ value: "dave@example.com", primary: true }],
			}),
		);
		const body = (await (created as Response).json()) as { id: string };

		const res = await mod.handleRequest(req("DELETE", `/scim/v2/Users/${body.id}`));
		expect(res?.status).toBe(204);

		const rows = await fetchAuditRows(db);
		expect(rows.map((r) => r.action)).toContain("scim.user.delete");
	});

	it("does not write an audit row on 400 validation errors", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
			}),
		);
		expect(res?.status).toBe(400);
		const rows = await fetchAuditRows(db);
		expect(rows).toHaveLength(0);
	});

	it("does not write an audit row on unauthenticated calls", async () => {
		const res = await mod.handleRequest(req("POST", "/scim/v2/Users", {}, ""));
		expect(res?.status).toBe(401);
		const rows = await fetchAuditRows(db);
		expect(rows).toHaveLength(0);
	});
});

describe("SCIM audit: group lifecycle", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule(
			{
				bearerToken: BEARER,
				audit: { agentId: AUDIT_AGENT_ID },
			},
			db,
		);
	});

	it("writes scim.group.create on POST /Groups", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Engineers",
			}),
		);
		expect(res?.status).toBe(201);
		const rows = await fetchAuditRows(db);
		expect(rows.map((r) => r.action)).toContain("scim.group.create");
	});

	it("writes scim.group.delete on DELETE /Groups/:id", async () => {
		const created = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Ops",
			}),
		);
		const body = (await (created as Response).json()) as { id: string };

		const res = await mod.handleRequest(req("DELETE", `/scim/v2/Groups/${body.id}`));
		expect(res?.status).toBe(204);

		const rows = await fetchAuditRows(db);
		expect(rows.map((r) => r.action)).toContain("scim.group.delete");
	});
});

describe("SCIM audit: opt-out", () => {
	it("writes nothing when audit is not configured", async () => {
		const db = await createTestDb();
		const mod = createScimModule({ bearerToken: BEARER }, db);

		await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "mute@example.com",
				emails: [{ value: "mute@example.com", primary: true }],
			}),
		);
		const rows = await fetchAuditRows(db);
		expect(rows).toHaveLength(0);
	});

	it("writes nothing when audit.enabled is false", async () => {
		const db = await createTestDb();
		const mod = createScimModule(
			{ bearerToken: BEARER, audit: { agentId: AUDIT_AGENT_ID, enabled: false } },
			db,
		);

		await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "quiet@example.com",
				emails: [{ value: "quiet@example.com", primary: true }],
			}),
		);
		const rows = await fetchAuditRows(db);
		expect(rows).toHaveLength(0);
	});
});

describe("SCIM audit: resilience", () => {
	it("does not fail the SCIM request when the system agent is missing", async () => {
		const db = await createTestDb();
		const mod = createScimModule(
			{ bearerToken: BEARER, audit: { agentId: "nonexistent-agent-id" } },
			db,
		);

		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "resilient@example.com",
				emails: [{ value: "resilient@example.com", primary: true }],
			}),
		);
		expect(res?.status).toBe(201);
		const rows = await fetchAuditRows(db);
		expect(rows).toHaveLength(0);
	});
});
