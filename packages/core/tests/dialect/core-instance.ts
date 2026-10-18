import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { agents, refreshTokens } from "../../src/db/schema.js";
import { createTokenFamilyStore } from "../../src/session/token-family.js";
import { defineAuditCoreTests } from "./core-audit.js";
import type { CoreBooter } from "./core-boot.js";
import { defineModuleCoreTests } from "./core-modules.js";

const HOUR = 3_600_000;

/**
 * Runs the whole core instance (users, sessions, agents, delegation, audit chain, MCP OAuth stores,
 * approvals, email flows, secondary storage, admin, cost attribution, GDPR) against the dialect database.
 * Called inside the suite's describe, after the suite's beforeEach has emptied the database.
 */
export function defineCoreInstanceTests(booter: CoreBooter): void {
	const { boot } = booter;

	describe("users", () => {
		it("user.create is idempotent, also under 5 way concurrency", async () => {
			const { auth } = await boot();
			const first = await auth.user.create({ email: "Dup@Example.com", name: "Dup" });
			const again = await auth.user.create({ email: "dup@example.com" });
			expect(again.id).toBe(first.id);
			expect(first.createdAt).toBeInstanceOf(Date);
			const burst = await Promise.all(
				Array.from({ length: 5 }, () => auth.user.create({ email: "burst@example.com" })),
			);
			expect(new Set(burst.map((u) => u.id)).size).toBe(1);
			expect((await auth.user.get("burst@example.com"))?.id).toBe(burst[0]?.id);
		});

		it("round trips user metadata JSON and the created_at Date", async () => {
			const { auth } = await boot();
			const before = Date.now();
			const user = await auth.user.create({
				email: "meta@example.com",
				metadata: { plan: "pro", tags: ["a", "b"], nested: { n: 1 } },
			});
			const read = await auth.user.get(user.id);
			expect(read?.metadata).toEqual({ plan: "pro", tags: ["a", "b"], nested: { n: 1 } });
			expect(Math.abs((read?.createdAt.getTime() ?? 0) - before)).toBeLessThan(10_000);
		});
	});

	describe("sessions", () => {
		it("creates, validates, lists and revokes sessions", async () => {
			const { auth } = await boot();
			const sessions = auth.auth.session;
			if (!sessions) throw new Error("session manager missing");
			const user = await auth.user.create({ email: "s@example.com" });
			const a = await sessions.create(user.id, { device: "laptop" });
			const b = await sessions.create(user.id);
			expect((await sessions.validate(a.token))?.userId).toBe(user.id);
			expect((await sessions.list(user.id)).map((s) => s.id).sort()).toEqual(
				[a.session.id, b.session.id].sort(),
			);
			expect(a.session.expiresAt.getTime()).toBeGreaterThan(Date.now());
			await sessions.revoke(a.session.id);
			expect(await sessions.validate(a.token)).toBeNull();
			expect((await sessions.validate(b.token))?.userId).toBe(user.id);
			await sessions.revokeAll(user.id);
			expect(await sessions.validate(b.token)).toBeNull();
		});

		it("rotates refresh tokens in a family and revokes the family on reuse", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "fam@example.com" });
			const store = createTokenFamilyStore(auth.db);
			const family = await store.createFamily(user.id, new Date(Date.now() + 24 * HOUR));
			const t1 = await store.issueToken(family.id, HOUR);
			expect((await store.consumeToken(t1.rawToken)).status).toBe("ok");
			const t2 = await store.issueToken(family.id, HOUR);
			expect((await store.consumeToken(t1.rawToken)).status).toBe("reuse");
			expect((await store.consumeToken(t2.rawToken)).status).toBe("revoked");
			expect((await store.consumeToken("missing")).status).toBe("not_found");
		});

		it("accepts a refresh token replay inside the reuse grace window and stores the consume time", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "grace@example.com" });
			const store = createTokenFamilyStore(auth.db, { reuseGraceMs: 10_000 });
			const family = await store.createFamily(user.id, new Date(Date.now() + 24 * HOUR));
			const t1 = await store.issueToken(family.id, HOUR);
			const before = Math.floor(Date.now() / 1000);
			expect((await store.consumeToken(t1.rawToken)).status).toBe("ok");
			const [row] = await auth.db
				.select()
				.from(refreshTokens)
				.where(eq(refreshTokens.familyId, family.id));
			expect(row?.used).toBeGreaterThanOrEqual(before);
			const replay = await store.consumeToken(t1.rawToken);
			expect(replay.status).toBe("ok");
			expect(replay.graceReplay).toBe(true);
			expect(replay.family?.revoked).toBe(false);
			expect((await store.consumeToken(t1.rawToken, { graceMs: 0 })).status).toBe("reuse");
			expect((await store.consumeToken(t1.rawToken)).status).toBe("revoked");
		});
	});

	describe("agents, permissions, authorize", () => {
		it("creates an agent, validates its token and authorizes by permission", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "ag@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "reader",
				type: "autonomous",
				permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
				expiresAt: new Date(Date.now() + HOUR),
				metadata: { team: "core" },
			});
			expect(agent.token.startsWith("ta_")).toBe(true);
			const read = await auth.agent.get(agent.id);
			expect(read?.permissions).toEqual([{ resource: "mcp:github:*", actions: ["read"] }]);
			const [stored] = await auth.db.select().from(agents).where(eq(agents.id, agent.id));
			expect(stored?.metadata).toEqual({ team: "core" });
			expect(read?.expiresAt?.getTime()).toBeGreaterThan(Date.now());
			expect((await auth.agent.list({ userId: user.id })).map((a) => a.id)).toContain(agent.id);
			expect(await auth.agent.validateToken(agent.token)).toBeTruthy();

			expect(
				(await auth.authorize(agent.id, { action: "read", resource: "mcp:github:repos" })).allowed,
			).toBe(true);
			const denied = await auth.authorize(agent.id, {
				action: "write",
				resource: "mcp:github:repos",
			});
			expect(denied.allowed).toBe(false);
			const updated = await auth.agent.update(agent.id, { name: "renamed" });
			expect(updated.name).toBe("renamed");
		});

		it("enforces maxCallsPerHour from the audit log", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "rl@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "limited",
				type: "autonomous",
				permissions: [
					{ resource: "mcp:x:*", actions: ["execute"], constraints: { maxCallsPerHour: 2 } },
				],
			});
			const call = () => auth.authorize(agent.id, { action: "execute", resource: "mcp:x:t" });
			expect((await call()).allowed).toBe(true);
			expect((await call()).allowed).toBe(true);
			const third = await call();
			expect(third.allowed).toBe(false);
			expect(third.code).toBe("rate_limited");
		});

		it("revoking an agent denies later calls and records it", async () => {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "rv@example.com" });
			const agent = await auth.agent.create({
				ownerId: user.id,
				name: "temp",
				type: "autonomous",
				permissions: [{ resource: "mcp:*", actions: ["execute"] }],
			});
			await auth.agent.revoke(agent.id);
			expect((await auth.agent.get(agent.id))?.status).toBe("revoked");
			expect(
				(await auth.authorize(agent.id, { action: "execute", resource: "mcp:a:b" })).allowed,
			).toBe(false);
		});
	});

	describe("delegation", () => {
		async function trio() {
			const { auth } = await boot();
			const user = await auth.user.create({ email: "del@example.com" });
			const make = (
				name: string,
				type: "autonomous" | "delegated",
				permissions: { resource: string; actions: string[] }[],
			) => auth.agent.create({ ownerId: user.id, name, type, permissions });
			const parent = await make("parent", "autonomous", [
				{ resource: "mcp:github:*", actions: ["read", "write"] },
			]);
			const child = await make("child", "delegated", []);
			const grandchild = await make("grandchild", "delegated", []);
			return { auth, parent, child, grandchild };
		}

		it("creates, verifies through authorize, and revokes a chain", async () => {
			const { auth, parent, child } = await trio();
			const chain = await auth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
				expiresAt: new Date(Date.now() + HOUR),
			});
			expect(chain.depth).toBe(1);
			expect((await auth.delegation.listChains(parent.id)).map((c) => c.id)).toContain(chain.id);
			const effective = await auth.delegation.getEffectivePermissions(child.id);
			expect(effective[0]?.resource).toBe("mcp:github:repos");
			expect(effective[0]?.actions).toEqual(["read"]);
			const allowed = await auth.authorize(child.id, {
				action: "read",
				resource: "mcp:github:repos",
			});
			expect(allowed.allowed).toBe(true);
			expect(
				(await auth.authorize(child.id, { action: "write", resource: "mcp:github:repos" })).allowed,
			).toBe(false);

			await auth.delegation.revoke(chain.id, { revokedBy: "admin-1" });
			expect(await auth.delegation.getEffectivePermissions(child.id)).toEqual([]);
			expect(
				(await auth.authorize(child.id, { action: "read", resource: "mcp:github:repos" })).allowed,
			).toBe(false);
		});

		it("rejects a chain deeper than maxDepth", async () => {
			const { auth, parent, child, grandchild } = await trio();
			const expiresAt = new Date(Date.now() + HOUR);
			const permissions = [{ resource: "mcp:github:repos", actions: ["read"] }];
			await auth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions,
				expiresAt,
				maxDepth: 1,
			});
			await expect(
				auth.delegate({
					fromAgent: child.id,
					toAgent: grandchild.id,
					permissions,
					expiresAt,
					maxDepth: 1,
				}),
			).rejects.toThrow("exceeds maximum allowed depth");
		});
	});

	defineAuditCoreTests(booter);
	defineModuleCoreTests(booter);
}
