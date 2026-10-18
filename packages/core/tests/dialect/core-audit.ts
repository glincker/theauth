import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { ERASURE_ACTION, insertAuditRow, verifyAuditChain } from "../../src/audit/index.js";
import { createGdprModule } from "../../src/auth/gdpr.js";
import type { Database } from "../../src/db/database.js";
import { agents, auditLogs, delegationChains, users } from "../../src/db/schema.js";
import { createTheAuth } from "../../src/theauth.js";
import type { CoreBooter } from "./core-boot.js";
import { closeDatabase, HMAC_KEY } from "./core-boot.js";

const T0 = new Date("2026-10-01T00:00:00Z");

async function seedOwner(db: Database, userId: string, agentIds: string[]): Promise<void> {
	await db.insert(users).values({
		id: userId,
		email: `${userId}@example.com`,
		name: userId,
		createdAt: T0,
		updatedAt: T0,
	});
	for (const id of agentIds) {
		await db.insert(agents).values({
			id,
			ownerId: userId,
			name: id,
			type: "autonomous",
			status: "active",
			tokenHash: `h-${id}`,
			tokenPrefix: `p-${id}`,
			metadata: {},
			createdAt: T0,
			updatedAt: T0,
		});
	}
}

function auditRow(id: string, agentId: string, userId: string, secondsAfter: number) {
	return {
		id,
		agentId,
		userId,
		action: "execute",
		resource: `mcp:github:${id}`,
		parameters: { b: 2, a: { z: 1, y: [1, 2] } },
		result: "allowed" as const,
		reason: null,
		durationMs: 5,
		timestamp: new Date(T0.getTime() + secondsAfter * 1000),
	};
}

export function defineAuditCoreTests(booter: CoreBooter): void {
	const { boot } = booter;

	describe("audit", () => {
		it("writes audit rows that read back in write order", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "o@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "w",
				type: "autonomous",
				permissions: [{ resource: "mcp:*", actions: ["execute"] }],
				expiresAt: new Date(Date.now() + 60_000),
			});
			for (let i = 0; i < 8; i++) {
				await auth.authorize(agent.id, { action: "execute", resource: `mcp:x:t${i}` });
			}
			const rows = await auth.audit.query({ agentId: agent.id });
			// audit.query returns the newest row first.
			expect(rows.map((r) => r.resource)).toEqual(
				Array.from({ length: 8 }, (_, i) => `mcp:x:t${7 - i}`),
			);
			expect((await auth.schema.status()).pending).toEqual([]);
		});

		it("verifies a chain of 20 rows and detects an edit", async () => {
			const { auth } = await boot();
			await seedOwner(auth.db, "u1", ["a1"]);
			for (let i = 1; i <= 20; i++) await insertAuditRow(auth.db, auditRow(`r${i}`, "a1", "u1", i));
			const ok = await verifyAuditChain(auth.db, {}, HMAC_KEY);
			expect(ok.success && ok.data.ok).toBe(true);
			expect(ok.success && ok.data.checked).toBe(20);
			expect(ok.success && ok.data.heads[0]?.seq).toBe(20);

			await auth.db.update(auditLogs).set({ resource: "mcp:evil" }).where(eq(auditLogs.id, "r7"));
			const bad = await verifyAuditChain(auth.db, {}, HMAC_KEY);
			expect(bad.success && bad.data.firstBreak?.reason).toBe("hash_mismatch");
		});

		it("produces the same hashes as in-memory SQLite for the same ids and timestamps", async () => {
			const { auth } = await boot();
			const lite = await createTheAuth({
				database: { provider: "sqlite", url: ":memory:" },
				agents: { enabled: true },
				audit: { tamperEvident: true, hmacKey: HMAC_KEY },
			});
			try {
				for (const db of [auth.db, lite.db]) {
					await seedOwner(db, "u1", ["a1"]);
					for (let i = 1; i <= 20; i++) await insertAuditRow(db, auditRow(`r${i}`, "a1", "u1", i));
				}
				const read = async (db: Database) =>
					(await db.select().from(auditLogs).where(eq(auditLogs.agentId, "a1"))).sort(
						(a, b) => (a.chainSeq ?? 0) - (b.chainSeq ?? 0),
					);
				const [pg, sqlite] = [await read(auth.db), await read(lite.db)];
				expect(pg).toHaveLength(20);
				expect(pg.map((r) => [r.id, r.chainSeq, r.prevHash, r.hash])).toEqual(
					sqlite.map((r) => [r.id, r.chainSeq, r.prevHash, r.hash]),
				);
				expect(pg.map((r) => r.idPseudonyms)).toEqual(sqlite.map((r) => r.idPseudonyms));
				expect(pg.map((r) => r.timestamp.getTime())).toEqual(
					sqlite.map((r) => r.timestamp.getTime()),
				);
			} finally {
				await closeDatabase(lite.db);
			}
		});

		it("keeps chains of different agents independent under concurrent writes", async () => {
			const { auth } = await boot();
			await seedOwner(auth.db, "u1", ["a1", "a2", "a3"]);
			await Promise.all(
				["a1", "a2", "a3"].flatMap((agent) =>
					Array.from({ length: 5 }, (_, i) =>
						insertAuditRow(auth.db, auditRow(`${agent}-${i}`, agent, "u1", i + 1)),
					),
				),
			);
			const result = await verifyAuditChain(auth.db, {}, HMAC_KEY);
			expect(result.success && result.data.ok).toBe(true);
			expect(result.success && result.data.checked).toBe(15);
		});
	});

	describe("GDPR and audit erasure", () => {
		async function populated(boot2: CoreBooter["boot"]) {
			const { auth } = await boot2();
			const user = await auth.user.create({ email: "erase@example.com", name: "Erase" });
			const other = await auth.user.create({ email: "keep@example.com" });
			const sessions = auth.auth.session;
			await sessions?.create(user.id);
			const parent = await auth.agent.create({
				ownerId: user.id,
				name: "p",
				type: "autonomous",
				permissions: [{ resource: "mcp:*", actions: ["execute", "read"] }],
			});
			const child = await auth.agent.create({
				ownerId: user.id,
				name: "c",
				type: "delegated",
				permissions: [],
			});
			await auth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "mcp:x:*", actions: ["read"] }],
				expiresAt: new Date(Date.now() + 3_600_000),
			});
			for (let i = 0; i < 3; i++) {
				await auth.authorize(parent.id, { action: "execute", resource: `mcp:x:t${i}` });
			}
			return { auth, user, other, parent, child };
		}

		it("exports user data and erases it, keeping a verifiable anonymized audit trail", async () => {
			const { auth, user, other, parent } = await populated(boot);
			const gdpr = createGdprModule(auth.db);
			const exported = await gdpr.exportUserData(user.id);
			expect(exported.user.email).toBe("erase@example.com");
			expect(exported.agents).toHaveLength(2);
			expect(exported.auditLogs.length).toBeGreaterThanOrEqual(3);
			expect(exported.delegations).toHaveLength(1);

			const result = await gdpr.deleteUser(user.id, { keepAuditLogs: true });
			expect(result.deletedAgents).toBe(2);
			expect(result.deletedDelegations).toBe(1);
			expect(result.anonymizedAuditLogs).toBeGreaterThanOrEqual(3);

			expect(await auth.user.get(user.id)).toBeNull();
			expect((await auth.user.get(other.id))?.id).toBe(other.id);
			// With keepAuditLogs the agents stay as revoked tombstones owned by a placeholder id.
			const tombstone = await auth.agent.get(parent.id);
			expect(tombstone?.status).toBe("revoked");
			expect(tombstone?.ownerId.startsWith("[deleted-")).toBe(true);
			// Links are revoked, never deleted: the row stays as a record and no link can authorize again.
			const links = await auth.db.select().from(delegationChains);
			expect(links).toHaveLength(1);
			expect(links.every((l) => l.status === "revoked")).toBe(true);
			const kept = await auth.db.select().from(auditLogs);
			expect(kept.length).toBeGreaterThanOrEqual(3);
			expect(kept.some((r) => r.userId === user.id || r.agentId === parent.id)).toBe(false);

			const verified = await verifyAuditChain(auth.db, {}, HMAC_KEY);
			expect(verified.success && verified.data.ok).toBe(true);
		});

		it("deletes audit rows with an erasure record when keepAuditLogs is false", async () => {
			const { auth, user, parent } = await populated(boot);
			const result = await createGdprModule(auth.db).deleteUser(user.id, { keepAuditLogs: false });
			expect(result.deletedAgents).toBe(2);
			expect(await auth.user.get(user.id)).toBeNull();
			const rows = await auth.db.select().from(auditLogs);
			expect(rows.some((r) => r.agentId === parent.id)).toBe(false);
			expect(rows.filter((r) => r.action === ERASURE_ACTION).length).toBeGreaterThanOrEqual(1);
			const verified = await verifyAuditChain(auth.db, {}, HMAC_KEY);
			expect(verified.success && verified.data.ok).toBe(true);
		});

		it("anonymizeUser replaces the email deterministically", async () => {
			const { auth, user } = await populated(boot);
			await createGdprModule(auth.db).anonymizeUser(user.id);
			const row = await auth.user.get(user.id);
			expect(row?.email.endsWith("@anon.invalid")).toBe(true);
		});
	});
}
