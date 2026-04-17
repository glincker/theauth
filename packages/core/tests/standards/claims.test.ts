/**
 * Tests for IETF agentic JWT claim constants and JWT session integration.
 *
 * Covers:
 * - AGENTIC_JWT_CLAIMS constant values are stable (snapshot).
 * - Flag off: issued tokens contain none of the agentic claim keys.
 * - Flag on with delegated agent: token contains agent_id, agent_type,
 *   trust_tier.
 * - Partial context: only available claims are emitted; missing ones are absent.
 */

import { decodeJwt } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { createJwtSessionModule } from "../../src/auth/jwt-session.js";
import type { Database } from "../../src/db/database.js";
import { createDatabase } from "../../src/db/database.js";
import { createTables } from "../../src/db/migrations.js";
import { users } from "../../src/db/schema.js";
import { AGENTIC_JWT_CLAIMS } from "../../src/standards/claims.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SECRET = "super-secret-key-at-least-32-chars-long!!";

const SAMPLE_USER = {
	id: "user-abc-123",
	email: "alice@example.com",
	name: "Alice",
};

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db.insert(users).values({
		id: SAMPLE_USER.id,
		email: SAMPLE_USER.email,
		name: SAMPLE_USER.name,
		createdAt: now,
		updatedAt: now,
	});
	return db;
}

// Decode a JWT without verifying the signature (claims inspection only).
function decodePayload(token: string): Record<string, unknown> {
	return decodeJwt(token) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constant stability
// ---------------------------------------------------------------------------

describe("AGENTIC_JWT_CLAIMS", () => {
	it("snapshot: claim name strings are stable", () => {
		expect(AGENTIC_JWT_CLAIMS).toStrictEqual({
			AGENT_ID: "agent_id",
			AGENT_TYPE: "agent_type",
			ON_BEHALF_OF: "on_behalf_of",
			ACT: "act",
			MAY_ACT: "may_act",
			TRUST_TIER: "trust_tier",
			AUDIT_REF: "audit_ref",
			TOOL_CONSTRAINTS: "tool_constraints",
			WORKLOAD_BINDING: "wit",
			OPERATION: "operation",
		});
	});
});

// ---------------------------------------------------------------------------
// JwtSessionModule — flag off
// ---------------------------------------------------------------------------

describe("JwtSessionModule — emitAgenticJwtClaims off (default)", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("issued token has none of the agentic claim keys when flag is omitted", async () => {
		const mod = createJwtSessionModule({ secret: TEST_SECRET }, db);
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const payload = decodePayload(result.data.accessToken);
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_ID]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.ON_BEHALF_OF]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.ACT]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.AUDIT_REF]).toBeUndefined();
	});

	it("issued token has none of the agentic claim keys when flag is false", async () => {
		const mod = createJwtSessionModule(
			{
				secret: TEST_SECRET,
				emitAgenticJwtClaims: false,
			},
			db,
		);
		const result = await mod.createSession({
			...SAMPLE_USER,
			agenticContext: {
				agentId: "agent-xyz",
				agentType: "delegated",
				trustTier: "standard",
			},
		});
		expect(result.success).toBe(true);
		if (!result.success) return;

		const payload = decodePayload(result.data.accessToken);
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_ID]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// JwtSessionModule — flag on
// ---------------------------------------------------------------------------

describe("JwtSessionModule — emitAgenticJwtClaims on", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("delegated agent: token has agent_id, agent_type=delegated, trust_tier", async () => {
		const mod = createJwtSessionModule(
			{
				secret: TEST_SECRET,
				emitAgenticJwtClaims: true,
			},
			db,
		);
		const result = await mod.createSession({
			...SAMPLE_USER,
			agenticContext: {
				agentId: "agent-xyz-456",
				agentType: "delegated",
				trustTier: "standard",
			},
		});
		expect(result.success).toBe(true);
		if (!result.success) return;

		const payload = decodePayload(result.data.accessToken);
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_ID]).toBe("agent-xyz-456");
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBe("delegated");
		expect(payload[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBe("standard");
	});

	it("autonomous agent: token has agent_type=autonomous", async () => {
		const mod = createJwtSessionModule({ secret: TEST_SECRET, emitAgenticJwtClaims: true }, db);
		const result = await mod.createSession({
			...SAMPLE_USER,
			agenticContext: {
				agentId: "agent-auto-1",
				agentType: "autonomous",
				trustTier: "elevated",
			},
		});
		expect(result.success).toBe(true);
		if (!result.success) return;

		const payload = decodePayload(result.data.accessToken);
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBe("autonomous");
		expect(payload[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBe("elevated");
	});

	it("partial context: only available claims are emitted", async () => {
		const mod = createJwtSessionModule({ secret: TEST_SECRET, emitAgenticJwtClaims: true }, db);
		// Only agentId provided — agent_type and trust_tier should be absent.
		const result = await mod.createSession({
			...SAMPLE_USER,
			agenticContext: {
				agentId: "agent-partial",
			},
		});
		expect(result.success).toBe(true);
		if (!result.success) return;

		const payload = decodePayload(result.data.accessToken);
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_ID]).toBe("agent-partial");
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBeUndefined();
	});

	it("no agenticContext on user: no agentic claims emitted even with flag on", async () => {
		const mod = createJwtSessionModule({ secret: TEST_SECRET, emitAgenticJwtClaims: true }, db);
		// Flag is on but no agenticContext provided.
		const result = await mod.createSession(SAMPLE_USER);
		expect(result.success).toBe(true);
		if (!result.success) return;

		const payload = decodePayload(result.data.accessToken);
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_ID]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBeUndefined();
		expect(payload[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBeUndefined();
	});

	it("agentic claims survive a verifySession round-trip", async () => {
		const mod = createJwtSessionModule({ secret: TEST_SECRET, emitAgenticJwtClaims: true }, db);
		const issued = await mod.createSession({
			...SAMPLE_USER,
			agenticContext: {
				agentId: "agent-roundtrip",
				agentType: "supervised",
				trustTier: "high",
			},
		});
		expect(issued.success).toBe(true);
		if (!issued.success) return;

		const verified = await mod.verifySession(issued.data.accessToken);
		expect(verified.success).toBe(true);
		if (!verified.success) return;

		expect(verified.data.claims[AGENTIC_JWT_CLAIMS.AGENT_ID]).toBe("agent-roundtrip");
		expect(verified.data.claims[AGENTIC_JWT_CLAIMS.AGENT_TYPE]).toBe("supervised");
		expect(verified.data.claims[AGENTIC_JWT_CLAIMS.TRUST_TIER]).toBe("high");
	});
});
