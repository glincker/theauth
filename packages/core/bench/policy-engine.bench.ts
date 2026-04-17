/**
 * Benchmark suite for the unified policy engine.
 *
 * Targets (M-series, single-threaded):
 *   Warm cache hit          p99 < 1 ms
 *   Cold direct permission  p99 < 5 ms
 *   Cold RBAC expansion     p99 < 5 ms
 *   Cold ReBAC walk         p99 < 5 ms
 *   Throughput (warm cache) ≥ 50,000 evals/sec
 *
 * Run:
 *   pnpm bench                   (from repo root)
 *   pnpm --filter kavachos bench (package-scoped)
 *
 * Targets are soft-enforced: misses print a warning on stderr, exit 0.
 * A hard CI gate (20% regression from main baseline) is a follow-up.
 */

import { afterAll, bench, describe } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	organizations,
	orgMembers,
	orgRoles,
	permissions as permissionsTable,
	rebacRelationships,
	rebacResources,
	users,
} from "../src/db/schema.js";
import { createPolicyEngine } from "../src/policy/engine.js";
import type { PolicyEngine } from "../src/policy/types.js";

// ──────────────────────────────────────────────────────────────────────────────
// Targets
// ──────────────────────────────────────────────────────────────────────────────

const THROUGHPUT_TARGET_HZ = 50_000; // evals/sec, warm cache

// ──────────────────────────────────────────────────────────────────────────────
// Setup
// ──────────────────────────────────────────────────────────────────────────────

async function buildEngineWithData(): Promise<{ engine: PolicyEngine; db: Database }> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	const now = new Date();

	// 1 user
	await db.insert(users).values({
		id: "user-1",
		email: "bench@kavachos.test",
		createdAt: now,
		updatedAt: now,
	});

	// 1 agent owned by that user
	await db.insert(agents).values({
		id: "agent-1",
		ownerId: "user-1",
		name: "bench-agent",
		type: "autonomous",
		tokenHash: "benchhash",
		tokenPrefix: "bench000",
		createdAt: now,
		updatedAt: now,
	});

	// 5 direct permissions on the agent
	const perms = [
		{ id: "p-hot", resource: "tool:hot", actions: ["read"] },
		{ id: "p-cold", resource: "tool:cold", actions: ["read"] },
		{ id: "p-extra1", resource: "tool:extra1", actions: ["write"] },
		{ id: "p-extra2", resource: "tool:extra2", actions: ["execute"] },
		{ id: "p-rebac", resource: "doc:123", actions: ["view"], relation: "view" },
	] as const;

	for (const p of perms) {
		await db.insert(permissionsTable).values({
			id: p.id,
			agentId: "agent-1",
			resource: p.resource,
			actions: [...p.actions],
			relation: "relation" in p ? p.relation : null,
			createdAt: now,
		});
	}

	// 1 org + role + member for the RBAC expansion bench
	await db.insert(organizations).values({
		id: "org-1",
		name: "Bench Org",
		slug: "bench-org",
		ownerId: "user-1",
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(orgRoles).values({
		id: "role-1",
		orgId: "org-1",
		name: "writer",
		permissions: ["docs:write", "docs:read"],
	});
	await db.insert(orgMembers).values({
		id: "mem-1",
		orgId: "org-1",
		userId: "user-1",
		role: "writer",
		joinedAt: now,
	});

	// 1 ReBAC resource + relationship tuple for the ReBAC bench
	await db.insert(rebacResources).values({
		id: "doc:123",
		type: "doc",
		createdAt: now,
	});
	await db.insert(rebacRelationships).values({
		id: "rel-1",
		subjectType: "agent",
		subjectId: "agent-1",
		relation: "view",
		objectType: "doc",
		objectId: "123",
		createdAt: now,
	});

	const engine = createPolicyEngine({ db, config: { audit: false } });

	// Pre-warm cache for the warm-hit bench
	await engine.evaluate({
		subject: { agentId: "agent-1" },
		action: "read",
		resource: "tool:hot",
	});

	return { engine, db };
}

// ──────────────────────────────────────────────────────────────────────────────
// Benchmarks
//
// The engine is shared across all cases. Invalidation is manual for cold paths.
// ──────────────────────────────────────────────────────────────────────────────

const { engine: _engine } = await buildEngineWithData();
const engine: PolicyEngine = _engine;

describe("policy-engine", () => {
	bench(
		"warm cache hit",
		async () => {
			await engine.evaluate({
				subject: { agentId: "agent-1" },
				action: "read",
				resource: "tool:hot",
			});
		},
		{ time: 1000 },
	);

	bench(
		"cold path - direct permission",
		async () => {
			engine.invalidate({ agentId: "agent-1" });
			await engine.evaluate({
				subject: { agentId: "agent-1" },
				action: "read",
				resource: "tool:cold",
			});
		},
		{ time: 1000 },
	);

	bench(
		"cold path - rbac role expansion",
		async () => {
			engine.invalidate({ userId: "user-1" });
			await engine.evaluate({
				subject: { userId: "user-1", orgId: "org-1" },
				action: "write",
				resource: "docs",
			});
		},
		{ time: 1000 },
	);

	bench(
		"cold path - rebac graph lookup",
		async () => {
			engine.invalidate({ agentId: "agent-1" });
			await engine.evaluate({
				subject: { agentId: "agent-1" },
				action: "view",
				resource: "doc:123",
			});
		},
		{ time: 1000 },
	);

	afterAll(async () => {
		// Throughput check: 1,000 warm-cache evaluations, measure elapsed.
		// This runs after vitest has collected bench results and gives a
		// standalone data point that can be read from CI logs.
		const iterations = 1_000;
		const t0 = performance.now();
		for (let i = 0; i < iterations; i++) {
			await engine.evaluate({
				subject: { agentId: "agent-1" },
				action: "read",
				resource: "tool:hot",
			});
		}
		const elapsed = performance.now() - t0;
		const hz = Math.round((iterations / elapsed) * 1_000);

		if (hz < THROUGHPUT_TARGET_HZ) {
			process.stderr.write(
				`[policy-engine bench] WARN throughput miss: ${hz.toLocaleString()} evals/sec < target ${THROUGHPUT_TARGET_HZ.toLocaleString()} evals/sec\n`,
			);
		}
	});
});
