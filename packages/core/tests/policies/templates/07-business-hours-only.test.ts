/**
 * Tests for template 07 — business-hours-only access.
 *
 * Uses vi.useFakeTimers() to control the server clock and test boundary
 * conditions precisely. The engine calls new Date().getHours()/getMinutes()
 * internally, so fake timers are the correct mechanism here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	BUSINESS_HOURS_END,
	BUSINESS_HOURS_START,
	businessHoursPermissions,
} from "../../../../../docs/policies/templates/07-business-hours-only/policy.js";
import type { Database } from "../../../src/db/database.js";
import { createDatabase } from "../../../src/db/database.js";
import { createTables } from "../../../src/db/migrations.js";
import { agents, permissions as permissionsTable, users } from "../../../src/db/schema.js";
import { createPolicyEngine } from "../../../src/policy/engine.js";

async function makeDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

/**
 * Return a Date pinned to the given local HH:MM on an arbitrary day.
 * Vitest fake timers use the system locale, so we build a local-time Date.
 */
function localDateAt(hh: number, mm: number): Date {
	const d = new Date();
	d.setHours(hh, mm, 0, 0);
	return d;
}

describe("template 07 — business-hours-only", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
		await db
			.insert(users)
			.values({ id: "user-1", email: "u1@test", createdAt: new Date(), updatedAt: new Date() });
		await db.insert(agents).values({
			id: "email-bot",
			ownerId: "user-1",
			name: "email-bot",
			type: "autonomous",
			tokenHash: "hash",
			tokenPrefix: "pref0000",
			createdAt: new Date(),
			updatedAt: new Date(),
		});

		for (let i = 0; i < businessHoursPermissions.length; i++) {
			const perm = businessHoursPermissions[i];
			if (!perm) continue;
			await db.insert(permissionsTable).values({
				id: `p${i}`,
				agentId: "email-bot",
				resource: perm.resource,
				actions: perm.actions,
				constraints: perm.constraints ?? null,
				relation: null,
				createdAt: new Date(),
			});
		}
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("allows at 10:30 (well inside business hours)", async () => {
		vi.useFakeTimers({ now: localDateAt(10, 30) });
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(true);
	});

	it(`allows at ${BUSINESS_HOURS_END} (inclusive end of window)`, async () => {
		vi.useFakeTimers({ now: localDateAt(17, 0) });
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(true);
	});

	it("denies at 17:01 (one minute past end of window)", async () => {
		vi.useFakeTimers({ now: localDateAt(17, 1) });
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(false);
		expect(decision.reason).toContain(BUSINESS_HOURS_START);
		expect(decision.reason).toContain(BUSINESS_HOURS_END);
	});

	it("denies at 08:59 (before business hours start)", async () => {
		vi.useFakeTimers({ now: localDateAt(8, 59) });
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies at midnight (00:00)", async () => {
		vi.useFakeTimers({ now: localDateAt(0, 0) });
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(false);
	});

	it("denies an unknown agent regardless of time", async () => {
		vi.useFakeTimers({ now: localDateAt(12, 0) });
		await db
			.insert(users)
			.values({ id: "user-2", email: "u2@test", createdAt: new Date(), updatedAt: new Date() });
		await db.insert(agents).values({
			id: "rogue-bot",
			ownerId: "user-2",
			name: "rogue-bot",
			type: "autonomous",
			tokenHash: "hash2",
			tokenPrefix: "pref0001",
			createdAt: new Date(),
			updatedAt: new Date(),
		});
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "rogue-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(false);
	});

	it("does not cache business-hours decisions (timeWindow constraint)", async () => {
		vi.useFakeTimers({ now: localDateAt(12, 0) });
		const engine = createPolicyEngine({ db });
		await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		// timeWindow marks the decision as cache-unsafe
		expect(engine.stats().size).toBe(0);
	});

	it(`allows at ${BUSINESS_HOURS_START} (inclusive start of window)`, async () => {
		vi.useFakeTimers({ now: localDateAt(9, 0) });
		const engine = createPolicyEngine({ db });
		const decision = await engine.evaluate({
			subject: { agentId: "email-bot" },
			action: "execute",
			resource: "tool:send_email",
		});
		expect(decision.allowed).toBe(true);
	});
});
