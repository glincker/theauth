/**
 * GDPR erasure as resumable steps (design slice 9). A throwing store wrapper crashes the process-equivalent after N writes, a fresh module retries, and the end state must equal an uninterrupted run: no leftovers, no duplicate erasure records, audit chain still verifying.
 */

import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { computeRowHash, ERASURE_ACTION } from "../src/audit/chain.js";
import { enableAuditChain, insertAuditRow, verifyAuditChain } from "../src/audit/index.js";
import { createGdprModule } from "../src/auth/gdpr.js";
import { createOrgModule } from "../src/auth/organization.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	apiKeys,
	auditLogs,
	delegationChains,
	organizations,
	orgInvitations,
	orgMembers,
	orgRoles,
	passkeyCredentials,
	sessions,
	totpRecords,
	users,
} from "../src/db/schema.js";
import { createDelegationModule } from "../src/delegation/delegation.js";

const KEY = "resumable-test-key";
const T0 = new Date("2026-10-01T00:00:00Z");
const FUTURE = new Date("2030-01-01T00:00:00Z");

interface Crash {
	writes: number;
	failAt: number;
}

/** A database handle that throws once more than `failAt` write calls have been made. A transaction or batch counts as one write. */
function crashable(db: Database): { db: Database; ctl: Crash } {
	const ctl: Crash = { writes: 0, failAt: Number.POSITIVE_INFINITY };
	const writes = new Set(["insert", "update", "delete", "transaction", "batch"]);
	const proxy = new Proxy(db, {
		get(target, prop) {
			const value = Reflect.get(target, prop, target) as unknown;
			if (typeof value !== "function") return value;
			if (typeof prop === "string" && writes.has(prop)) {
				return (...args: unknown[]) => {
					ctl.writes++;
					if (ctl.writes > ctl.failAt) throw new Error("injected crash");
					return (value as (...a: unknown[]) => unknown).apply(target, args);
				};
			}
			return (value as (...a: unknown[]) => unknown).bind(target);
		},
	});
	return { db: proxy, ctl };
}

function auditRow(id: string, agentId: string, userId: string, secs: number) {
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

async function seed(): Promise<{ db: Database; ctl: Crash }> {
	const raw = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(raw, "sqlite");
	const { db, ctl } = crashable(raw);
	for (const id of ["u1", "u2"]) {
		await db.insert(users).values({
			id,
			email: `${id}@example.com`,
			name: id,
			username: id,
			createdAt: T0,
			updatedAt: T0,
		});
	}
	for (const [id, owner] of [
		["a1", "u1"],
		["a1b", "u1"],
		["a3", "u2"],
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
	await db.insert(delegationChains).values({
		id: "d1",
		fromAgentId: "a1",
		toAgentId: "a3",
		permissions: [{ resource: "x", actions: ["read"] }],
		expiresAt: FUTURE,
		createdAt: T0,
	});
	await db.insert(sessions).values([
		{ id: "s1", userId: "u1", expiresAt: FUTURE, createdAt: T0 },
		{ id: "s2", userId: "u1", expiresAt: FUTURE, createdAt: T0 },
	]);
	await db.insert(apiKeys).values({
		id: "k1",
		userId: "u1",
		name: "k",
		keyHash: "kh",
		keyPrefix: "kp",
		permissions: [],
		createdAt: T0,
	});
	await db.insert(totpRecords).values({
		userId: "u1",
		secret: "S",
		backupCodes: [],
		createdAt: T0,
		updatedAt: T0,
	});
	await db.insert(passkeyCredentials).values({
		id: "p1",
		userId: "u1",
		credentialId: "cred1",
		publicKey: "pk",
		createdAt: T0,
		lastUsedAt: T0,
	});
	await db.insert(organizations).values({
		id: "o1",
		name: "Org",
		slug: "org",
		ownerId: "u1",
		createdAt: T0,
		updatedAt: T0,
	});
	await db
		.insert(orgMembers)
		.values({ id: "m1", orgId: "o1", userId: "u1", role: "owner", joinedAt: T0 });
	// Version 1 rows (released format) hash the raw ids, so erasure must account for them.
	let prev: string | null = null;
	for (const [i, id] of ["v1", "v2", "v3"].entries()) {
		const base = auditRow(id, "a1", "u1", i + 1);
		const hash: string = await computeRowHash({ ...base, hashVersion: null }, i + 1, prev, KEY);
		await db.insert(auditLogs).values({ ...base, chainSeq: i + 1, prevHash: prev, hash });
		prev = hash;
	}
	enableAuditChain(db, { hmacKey: KEY });
	await insertAuditRow(db, auditRow("r1", "a1b", "u1", 10));
	await insertAuditRow(db, auditRow("r2", "a3", "u1", 11));
	await insertAuditRow(db, auditRow("r3", "a3", "u2", 12));
	await insertAuditRow(db, { ...auditRow("r4", "a3", "u2", 13), subjectId: "u1", actorId: "a1" });
	ctl.writes = 0;
	return { db, ctl };
}

/** Everything erasure can leave behind, minus random ids and the progress marker. */
async function snapshot(db: Database) {
	const records = (await db.select().from(auditLogs).where(eq(auditLogs.action, ERASURE_ACTION)))
		.map((r) => ({
			agentId: r.agentId,
			ids: ((r.parameters as { rows: Array<{ id: string }> }).rows ?? []).map((e) => e.id).sort(),
		}))
		.sort((a, b) => a.agentId.localeCompare(b.agentId));
	// Rows with generated ids (revocation events, gap markers) come from best-effort writers that
	// swallow a store fault by design, so they are not part of the erasure end state.
	const logs = (await db.select().from(auditLogs))
		.filter((r) => r.action !== ERASURE_ACTION && !r.id.startsWith("aud_"))
		.map((r) => [r.id, r.agentId, r.userId, r.subjectId, r.actorId])
		.sort((a, b) => String(a[0]).localeCompare(String(b[0])));
	return {
		users: (await db.select({ id: users.id, email: users.email }).from(users))
			.map((u) => u.id)
			.sort(),
		agents: (await db.select().from(agents)).map((a) => [a.id, a.ownerId, a.status]).sort(),
		links: (await db.select().from(delegationChains)).map((d) => [
			d.id,
			d.fromAgentId,
			d.toAgentId,
			d.status,
		]),
		sessions: (await db.select().from(sessions)).length,
		apiKeys: (await db.select().from(apiKeys)).length,
		totp: (await db.select().from(totpRecords)).length,
		passkeys: (await db.select().from(passkeyCredentials)).length,
		members: (await db.select().from(orgMembers)).length,
		orgs: (await db.select().from(organizations)).map((o) => [o.id, o.ownerId]),
		records,
		logs,
	};
}

function entryIds(snap: Awaited<ReturnType<typeof snapshot>>): string[] {
	return snap.records.flatMap((r) => r.ids);
}

async function expectChainOk(db: Database): Promise<void> {
	const result = await verifyAuditChain(db, {}, KEY);
	expect(result.success && result.data.ok).toBe(true);
}

const MAX_STEPS = 120;

describe("deleteUser resumes after a crash", () => {
	for (const keepAuditLogs of [true, false]) {
		it(`reaches the uninterrupted end state at every crash point (keepAuditLogs ${keepAuditLogs})`, async () => {
			const control = await seed();
			await createGdprModule(control.db, null, { hmacKey: KEY }).deleteUser("u1", {
				keepAuditLogs,
				deleteOrganizations: !keepAuditLogs,
			});
			const expected = await snapshot(control.db);
			await expectChainOk(control.db);
			expect(expected.users).not.toContain("u1");
			expect(expected.sessions).toBe(0);

			let crashes = 0;
			for (let n = 0; n < MAX_STEPS; n++) {
				const { db, ctl } = await seed();
				ctl.failAt = n;
				let crashed = false;
				try {
					await createGdprModule(db, null, { hmacKey: KEY }).deleteUser("u1", {
						keepAuditLogs,
						deleteOrganizations: !keepAuditLogs,
					});
				} catch (err) {
					expect((err as Error).message).toContain("injected crash");
					crashed = true;
				}
				ctl.failAt = Number.POSITIVE_INFINITY;
				if (!crashed) {
					expect(crashes).toBeGreaterThan(8);
					return;
				}
				crashes++;
				// A fresh module, as after a restart.
				await createGdprModule(db, null, { hmacKey: KEY }).deleteUser("u1", {
					keepAuditLogs,
					deleteOrganizations: !keepAuditLogs,
				});
				const got = await snapshot(db);
				expect(got, `crash after ${n} writes`).toEqual(expected);
				const ids = entryIds(got);
				expect(new Set(ids).size, `duplicate erasure entries after ${n} writes`).toBe(ids.length);
				await expectChainOk(db);
			}
			throw new Error("deleteUser never completed within the step budget");
		}, 120_000);
	}

	it("a second call after completion is a no-op that reports the first result", async () => {
		const { db } = await seed();
		const gdpr = createGdprModule(db, null, { hmacKey: KEY });
		const first = await gdpr.deleteUser("u1");
		const again = await gdpr.deleteUser("u1");
		expect(again).toEqual(first);
		expect(first.deletedSessions).toBe(2);
	});

	for (const keepAuditLogs of [true, false]) {
		it(`two concurrent calls leave one clean end state (keepAuditLogs ${keepAuditLogs})`, async () => {
			const control = await seed();
			await createGdprModule(control.db, null, { hmacKey: KEY }).deleteUser("u1", {
				keepAuditLogs,
			});
			const expected = await snapshot(control.db);

			const { db } = await seed();
			const a = createGdprModule(db, null, { hmacKey: KEY });
			const b = createGdprModule(db, null, { hmacKey: KEY });
			await Promise.all([
				a.deleteUser("u1", { keepAuditLogs }),
				b.deleteUser("u1", { keepAuditLogs }),
			]);
			const got = await snapshot(db);
			expect(got).toEqual(expected);
			const ids = entryIds(got);
			expect(new Set(ids).size).toBe(ids.length);
			await expectChainOk(db);
		});
	}
});

describe("delegation revoke", () => {
	it("a crash mid revoke never doubles the audit row and a retry finishes", async () => {
		for (let n = 0; n < 12; n++) {
			const { db, ctl } = await seed();
			const mod = createDelegationModule({ db });
			ctl.failAt = n;
			let crashed = false;
			try {
				await mod.revokeAllForAgent("a1");
			} catch {
				crashed = true;
			}
			ctl.failAt = Number.POSITIVE_INFINITY;
			await mod.revokeAllForAgent("a1");
			const link = (
				await db.select().from(delegationChains).where(eq(delegationChains.id, "d1"))
			)[0];
			expect(link?.status, `crashed ${crashed} at ${n}`).toBe("revoked");
			const events = (await db.select().from(auditLogs)).filter(
				(r) => r.event === "delegation.revoke" && r.resource === "delegation:d1",
			);
			expect(events.length).toBeLessThanOrEqual(1);
		}
	});
});

describe("exportUserData", () => {
	it("includes audit rows of a user who owns no agent", async () => {
		const { db } = await seed();
		await db
			.insert(users)
			.values({ id: "u9", email: "u9@example.com", createdAt: T0, updatedAt: T0 });
		await insertAuditRow(db, auditRow("x1", "a3", "u9", 20));
		const data = await createGdprModule(db, null, { hmacKey: KEY }).exportUserData("u9");
		expect(data.auditLogs).toHaveLength(1);
	});
});

describe("anonymizeUser", () => {
	it("is atomic or resumable at every crash point", async () => {
		let crashes = 0;
		for (let n = 0; n < 20; n++) {
			const { db, ctl } = await seed();
			ctl.failAt = n;
			let crashed = false;
			try {
				await createGdprModule(db, null, { hmacKey: KEY }).anonymizeUser("u1");
			} catch {
				crashed = true;
			}
			ctl.failAt = Number.POSITIVE_INFINITY;
			if (!crashed) {
				expect(crashes).toBeGreaterThan(0);
				return;
			}
			crashes++;
			// Never the half state: email anonymized while a credential survives.
			const mid = (await db.select().from(users).where(eq(users.id, "u1")))[0];
			const credentials =
				(await db.select().from(totpRecords)).length +
				(await db.select().from(passkeyCredentials)).length;
			if (mid?.email.endsWith("@anon.invalid")) expect(credentials).toBe(0);
			await createGdprModule(db, null, { hmacKey: KEY }).anonymizeUser("u1");
			const user = (await db.select().from(users).where(eq(users.id, "u1")))[0];
			expect(user?.email).toMatch(/^deleted-[0-9a-f]{32}@anon\.invalid$/);
			expect(user?.name).toBeNull();
			expect(await db.select().from(totpRecords)).toHaveLength(0);
			expect(await db.select().from(passkeyCredentials)).toHaveLength(0);
		}
		throw new Error("anonymizeUser never completed within the step budget");
	});

	it("twice gives the same address", async () => {
		const { db } = await seed();
		const gdpr = createGdprModule(db, null, { hmacKey: KEY });
		await gdpr.anonymizeUser("u1");
		const first = (await db.select().from(users).where(eq(users.id, "u1")))[0]?.email;
		await gdpr.anonymizeUser("u1");
		expect((await db.select().from(users).where(eq(users.id, "u1")))[0]?.email).toBe(first);
	});
});

describe("organization.remove", () => {
	it("is all or nothing when the store crashes", async () => {
		for (let n = 0; n < 6; n++) {
			const { db, ctl } = await seed();
			const mod = createOrgModule({ trustedServerUse: true }, db);
			const org = await mod.create({ name: "Two", slug: "two", ownerId: "u2" });
			await db.insert(orgInvitations).values({
				id: "i1",
				orgId: org.id,
				email: "x@example.com",
				invitedBy: "u2",
				expiresAt: FUTURE,
				createdAt: T0,
			});
			ctl.writes = 0;
			ctl.failAt = n;
			let crashed = false;
			try {
				await mod.remove(org.id);
			} catch {
				crashed = true;
			}
			ctl.failAt = Number.POSITIVE_INFINITY;
			const counts = [
				(await db.select().from(organizations).where(eq(organizations.id, org.id))).length,
				(await db.select().from(orgMembers).where(eq(orgMembers.orgId, org.id))).length,
				(await db.select().from(orgRoles).where(eq(orgRoles.orgId, org.id))).length,
				(await db.select().from(orgInvitations).where(eq(orgInvitations.orgId, org.id))).length,
			];
			const allGone = counts.every((c) => c === 0);
			const allThere = counts.every((c) => c > 0);
			expect(allGone || allThere, `crash ${crashed} after ${n} writes: ${counts}`).toBe(true);
			if (crashed) {
				await mod.remove(org.id);
				expect(
					await db.select().from(organizations).where(eq(organizations.id, org.id)),
				).toHaveLength(0);
			}
		}
	});
});
