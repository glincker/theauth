/** GDPR deleteUser revokes delegation links instead of deleting them, keyed anonymous ids, delete mode erases ids on other rows, admin.deleteUser with agents. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { recordAuditEvent } from "../src/audit/record.js";
import { createAdminModule } from "../src/auth/admin.js";
import { createGdprModule } from "../src/auth/gdpr.js";
import { sha256 } from "../src/crypto/web-crypto.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, delegationChains, users } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { UserError } from "../src/user/user.js";
import { delegateTo, makeTheAuth, newAgent, pause } from "./hook-test-utils.js";

const SECRET = [{ resource: "repo:secret", actions: ["read"] }];
const REQ = { action: "read", resource: "repo:secret" };

/** A booted instance plus the tables sessions and friends need (not created without auth.session). */
async function world(): Promise<TheAuth> {
	const theauth = await makeTheAuth({});
	await createTables(theauth.db, "sqlite");
	return theauth;
}

async function chain(theauth: TheAuth) {
	const a = await newAgent(theauth, "a", SECRET, "user-1");
	const b = await newAgent(theauth, "b", [], "user-2");
	const c = await newAgent(theauth, "c", [], "user-2");
	const ab = await delegateTo(theauth, a.id, b.id, SECRET);
	const bc = await delegateTo(theauth, b.id, c.id, SECRET);
	return { a, b, c, ab, bc };
}

describe("gdpr.deleteUser revokes delegation links", () => {
	for (const keepAuditLogs of [true, false]) {
		it(`kills the downstream grant and keeps revoked link rows (keepAuditLogs ${keepAuditLogs})`, async () => {
			const theauth = await world();
			const { c, ab, bc } = await chain(theauth);
			expect((await theauth.authorizeByToken(c.token, REQ)).allowed).toBe(true);

			const pushedIds = new Set<string>();
			theauth.revocations.subscribe((event) => {
				if (event.kind === "dlg") for (const id of event.ids) pushedIds.add(id);
			});
			const gdpr = createGdprModule(theauth.db, theauth.revocations);
			const result = await gdpr.deleteUser("user-1", { keepAuditLogs });
			expect(result.deletedDelegations).toBe(2);

			expect((await theauth.authorizeByToken(c.token, REQ)).allowed).toBe(false);
			const rows = await theauth.db.select().from(delegationChains);
			const byId = new Map(rows.map((r) => [r.id, r]));
			expect(byId.get(ab.id)?.status).toBe("revoked");
			expect(byId.get(bc.id)?.status).toBe("revoked");

			// The downstream link has an audit row on the receiving agent's chain.
			const audit = await theauth.db.select().from(auditLogs).where(eq(auditLogs.agentId, c.id));
			expect(audit.some((r) => r.event === "delegation.revoke")).toBe(true);

			// Both links went through the revocation bus.
			expect(pushedIds.has(ab.id)).toBe(true);
			expect(pushedIds.has(bc.id)).toBe(true);
		});
	}

	it("liveness alone kills a downstream link whose upstream link is revoked", async () => {
		const theauth = await world();
		const { b, c, ab } = await chain(theauth);
		// Revoke only the upstream row, with no cascade (a crashed or older erasure).
		await theauth.db
			.update(delegationChains)
			.set({ status: "revoked" })
			.where(eq(delegationChains.id, ab.id));
		expect((await theauth.authorizeByToken(c.token, REQ)).allowed).toBe(false);
		expect((await theauth.authorizeByToken(b.token, REQ)).allowed).toBe(false);
	});

	it("liveness keeps a downstream link the delegator holds directly", async () => {
		const theauth = await world();
		const a = await newAgent(theauth, "a", SECRET, "user-1");
		const b = await newAgent(theauth, "b", SECRET, "user-2");
		const c = await newAgent(theauth, "c", [], "user-2");
		const ab = await delegateTo(theauth, a.id, b.id, SECRET);
		await delegateTo(theauth, b.id, c.id, SECRET);
		await theauth.db
			.update(delegationChains)
			.set({ status: "revoked" })
			.where(eq(delegationChains.id, ab.id));
		expect((await theauth.authorizeByToken(c.token, REQ)).allowed).toBe(true);
	});
});

describe("gdpr anonymous ids", () => {
	it("are keyed per instance and not an unsalted hash of the id", async () => {
		const anon: string[] = [];
		for (let i = 0; i < 2; i++) {
			const theauth = await world();
			const a = await newAgent(theauth, "a", SECRET, "user-1");
			await recordAuditEvent(theauth.db, {
				agentId: a.id,
				action: "read",
				resource: "repo:secret",
				result: "allowed",
			});
			await createGdprModule(theauth.db, theauth.revocations).deleteUser("user-1");
			const rows = await theauth.db.select().from(auditLogs);
			const id = rows[0]?.userId ?? "";
			expect(id).toMatch(/^\[deleted-[0-9a-f]{32}\]$/);
			expect(id).not.toBe(`[deleted-${(await sha256("user-1")).slice(0, 12)}]`);
			anon.push(id);
		}
		expect(anon[0]).not.toBe(anon[1]);
	});

	it("are derived from hmacKey when given, so two instances sharing it agree", async () => {
		const ids: string[] = [];
		for (let i = 0; i < 2; i++) {
			const theauth = await world();
			const a = await newAgent(theauth, "a", SECRET, "user-1");
			await recordAuditEvent(theauth.db, {
				agentId: a.id,
				action: "read",
				resource: "repo:secret",
				result: "allowed",
			});
			await createGdprModule(theauth.db, theauth.revocations, { hmacKey: "shared-key" }).deleteUser(
				"user-1",
			);
			ids.push((await theauth.db.select().from(auditLogs))[0]?.userId ?? "");
		}
		expect(ids[0]).toBe(ids[1]);
	});
});

describe("gdpr delete mode erases ids on other users' rows", () => {
	it("nulls subjectId, actorId and approverId that name the deleted user or their agents", async () => {
		const theauth = await world();
		const a = await newAgent(theauth, "a", SECRET, "user-1");
		const other = await newAgent(theauth, "o", SECRET, "user-2");
		await recordAuditEvent(theauth.db, {
			agentId: other.id,
			action: "read",
			resource: "repo:secret",
			result: "allowed",
			subjectId: "user-1",
			approverId: "user-1",
			actorId: a.id,
		});
		await createGdprModule(theauth.db, theauth.revocations).deleteUser("user-1", {
			keepAuditLogs: false,
		});
		const rows = await theauth.db.select().from(auditLogs).where(eq(auditLogs.agentId, other.id));
		expect(rows).toHaveLength(1);
		expect(rows[0]?.subjectId).toBeNull();
		expect(rows[0]?.approverId).toBeNull();
		expect(rows[0]?.actorId).toBeNull();
		expect(rows[0]?.userId).toBe("user-2");
	});
});

describe("admin.deleteUser with agents", () => {
	it("revokes the agents, cascades their links and deletes the user without a foreign key error", async () => {
		const theauth = await world();
		const { a, c } = await chain(theauth);
		const admin = createAdminModule(
			{ adminUserIds: ["root"] },
			theauth.db,
			null,
			theauth.revocations,
		);
		await admin.deleteUser("user-1");
		expect(await theauth.db.select().from(users).where(eq(users.id, "user-1"))).toHaveLength(0);
		const [row] = await theauth.db.select().from(agents).where(eq(agents.id, a.id));
		expect(row?.status).toBe("revoked");
		expect((await theauth.authorizeByToken(c.token, REQ)).allowed).toBe(false);
		await pause();
	});
});

describe("reserved [deleted- id prefix", () => {
	it("is refused for user ids at create time", async () => {
		const theauth = await world();
		await expect(
			theauth.user.create({ id: "[deleted-abc]", email: "x@example.com" }),
		).rejects.toBeInstanceOf(UserError);
	});
});
