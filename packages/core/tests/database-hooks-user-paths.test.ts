/** User create and update hooks on the secondary paths: SCIM, admin, anonymous, username, OTP, fields. */

import { eq } from "drizzle-orm";
import { describe, expect, it, vi } from "vitest";
import { createAdditionalFieldsModule } from "../src/auth/additional-fields.js";
import { createAdminModule } from "../src/auth/admin.js";
import { createAnonymousAuthModule } from "../src/auth/anonymous.js";
import { createEmailOtpModule } from "../src/auth/email-otp.js";
import { createScimModule } from "../src/auth/scim.js";
import { createStripeModule } from "../src/auth/stripe.js";
import { createUsernameAuthModule } from "../src/auth/username.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { sessions, users } from "../src/db/schema.js";
import type { DatabaseHooks } from "../src/hooks/database-hooks.js";
import { createDatabaseHookRunner, DatabaseHookError } from "../src/hooks/database-hooks.js";
import { createSessionManager } from "../src/session/session.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const BEARER = "scim-hook-token";

async function makeDb() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

const runnerOf = (hooks: DatabaseHooks) => createDatabaseHookRunner(hooks);

async function seed(db: Awaited<ReturnType<typeof makeDb>>, id: string, email: string) {
	const now = new Date();
	await db.insert(users).values({ id, email, createdAt: now, updatedAt: now });
}

function scimReq(method: string, path: string, body?: unknown): Request {
	return new Request(`https://api.example.com${path}`, {
		method,
		headers: { "Content-Type": "application/scim+json", Authorization: `Bearer ${BEARER}` },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

describe("additional fields update hook", () => {
	it("replaces metadata and runs after with the stored row", async () => {
		const db = await makeDb();
		await seed(db, "u1", "u1@example.com");
		const after = vi.fn();
		const mod = createAdditionalFieldsModule(
			{ user: { plan: { type: "string", required: false } } },
			db,
			runnerOf({
				user: {
					update: {
						before: (u) => ({ data: { metadata: { ...u.metadata, audited: true } } }),
						after,
					},
				},
			}),
		);
		await mod.setUserFields("u1", { plan: "pro" });
		const [row] = await db.select().from(users).where(eq(users.id, "u1"));
		expect(row?.metadata).toMatchObject({ audited: true, additionalFields: { plan: "pro" } });
		expect(after).toHaveBeenCalledOnce();
		expect(after.mock.calls[0]?.[0]).toMatchObject({ id: "u1", email: "u1@example.com" });
	});

	it("an abort leaves the row unchanged", async () => {
		const db = await makeDb();
		await seed(db, "u1", "u1@example.com");
		const mod = createAdditionalFieldsModule(
			{ user: { plan: { type: "string", required: false } } },
			db,
			runnerOf({ user: { update: { before: () => false } } }),
		);
		await expect(mod.setUserFields("u1", { plan: "pro" })).rejects.toBeInstanceOf(
			DatabaseHookError,
		);
		const [row] = await db.select().from(users).where(eq(users.id, "u1"));
		expect(row?.metadata ?? null).toBeNull();
	});
});

describe("admin ban update hook", () => {
	it("a before abort stops the ban and keeps the sessions", async () => {
		const db = await makeDb();
		await seed(db, "u1", "u1@example.com");
		const sm = createSessionManager({ secret: SECRET }, db);
		await sm.create("u1");
		const admin = createAdminModule(
			{ adminUserIds: ["root"] },
			db,
			sm,
			null,
			runnerOf({ user: { update: { before: () => false } } }),
		);
		await expect(admin.banUser("u1", "spam")).rejects.toBeInstanceOf(DatabaseHookError);
		const [row] = await db.select().from(users).where(eq(users.id, "u1"));
		expect(row?.banned).toBe(0);
		expect(await db.select().from(sessions)).toHaveLength(1);
	});

	it("after fires with the stored row and an unban fires too", async () => {
		const db = await makeDb();
		await seed(db, "u1", "u1@example.com");
		const after = vi.fn();
		const admin = createAdminModule(
			{ adminUserIds: ["root"] },
			db,
			null,
			null,
			runnerOf({ user: { update: { after } } }),
		);
		await admin.banUser("u1");
		await admin.unbanUser("u1");
		expect(after).toHaveBeenCalledTimes(2);
	});

	it("a hook that replaces the name rides along with the ban", async () => {
		const db = await makeDb();
		await seed(db, "u1", "u1@example.com");
		const admin = createAdminModule(
			{ adminUserIds: ["root"] },
			db,
			null,
			null,
			runnerOf({ user: { update: { before: () => ({ data: { name: "Banned" } }) } } }),
		);
		await admin.banUser("u1");
		const [row] = await db.select().from(users).where(eq(users.id, "u1"));
		expect(row).toMatchObject({ banned: 1, name: "Banned" });
	});
});

describe("SCIM hooks", () => {
	const body = {
		userName: "ada@example.com",
		emails: [{ value: "ada@example.com", primary: true }],
	};

	it("create: replace payload, run after", async () => {
		const db = await makeDb();
		const after = vi.fn();
		const scim = createScimModule(
			{ bearerToken: BEARER },
			db,
			null,
			runnerOf({
				user: { create: { before: () => ({ data: { name: "Ada L" } }), after } },
			}),
		);
		const res = await scim.handleRequest(scimReq("POST", "/scim/v2/Users", body));
		expect(res?.status).toBe(201);
		const [row] = await db.select().from(users);
		expect(row?.name).toBe("Ada L");
		expect(after).toHaveBeenCalledOnce();
	});

	it("create: an abort answers 403 and writes nothing", async () => {
		const db = await makeDb();
		const scim = createScimModule(
			{ bearerToken: BEARER },
			db,
			null,
			runnerOf({ user: { create: { before: () => false } } }),
		);
		const res = await scim.handleRequest(scimReq("POST", "/scim/v2/Users", body));
		expect(res?.status).toBe(403);
		expect(await db.select().from(users)).toHaveLength(0);
	});

	it("replace and patch fire update hooks, an abort keeps the row", async () => {
		const db = await makeDb();
		await seed(db, "u1", "ada@example.com");
		const before = vi.fn(() => undefined);
		const scim = createScimModule(
			{ bearerToken: BEARER },
			db,
			null,
			runnerOf({ user: { update: { before } } }),
		);
		const put = await scim.handleRequest(
			scimReq("PUT", "/scim/v2/Users/u1", { ...body, displayName: "Ada" }),
		);
		expect(put?.status).toBe(200);
		const patch = await scim.handleRequest(
			scimReq("PATCH", "/scim/v2/Users/u1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "displayName", value: "Ada 2" }],
			}),
		);
		expect(patch?.status).toBe(200);
		expect(before).toHaveBeenCalledTimes(2);

		const denied = createScimModule(
			{ bearerToken: BEARER },
			db,
			null,
			runnerOf({ user: { update: { before: () => false } } }),
		);
		const res = await denied.handleRequest(
			scimReq("PUT", "/scim/v2/Users/u1", { ...body, displayName: "Nope" }),
		);
		expect(res?.status).toBe(403);
		const [row] = await db.select().from(users).where(eq(users.id, "u1"));
		expect(row?.name).toBe("Ada 2");
	});

	it("deactivating through DELETE fires the update hook", async () => {
		const db = await makeDb();
		await seed(db, "u1", "ada@example.com");
		const after = vi.fn();
		const scim = createScimModule(
			{ bearerToken: BEARER },
			db,
			null,
			runnerOf({ user: { update: { after } } }),
		);
		const res = await scim.handleRequest(scimReq("DELETE", "/scim/v2/Users/u1"));
		expect(res?.status).toBe(204);
		expect(after).toHaveBeenCalledOnce();
	});
});

describe("anonymous hooks", () => {
	it("create: an abort writes no user, a replace cannot drop the anonymous flag", async () => {
		const db = await makeDb();
		const sm = createSessionManager({ secret: SECRET }, db);
		const denied = createAnonymousAuthModule(
			{},
			db,
			sm,
			undefined,
			runnerOf({ user: { create: { before: () => false } } }),
		);
		await expect(denied.createAnonymousUser()).rejects.toBeInstanceOf(DatabaseHookError);
		expect(await db.select().from(users)).toHaveLength(0);

		const after = vi.fn();
		const mod = createAnonymousAuthModule(
			{},
			db,
			sm,
			undefined,
			runnerOf({
				user: { create: { before: () => ({ data: { metadata: { tag: "x" } } }), after } },
			}),
		);
		const { userId } = await mod.createAnonymousUser();
		expect(await mod.isAnonymous(userId)).toBe(true);
		const [row] = await db.select().from(users).where(eq(users.id, userId));
		expect(row?.metadata).toEqual({ tag: "x", anonymous: true });
		expect(after).toHaveBeenCalledOnce();
	});

	it("upgrade fires the update hook and an abort keeps the guest", async () => {
		const db = await makeDb();
		const sm = createSessionManager({ secret: SECRET }, db);
		const plain = createAnonymousAuthModule({}, db, sm);
		const { userId } = await plain.createAnonymousUser();
		const denied = createAnonymousAuthModule(
			{},
			db,
			sm,
			undefined,
			runnerOf({ user: { update: { before: () => false } } }),
		);
		await expect(denied.upgradeUser(userId, { email: "real@example.com" })).rejects.toBeInstanceOf(
			DatabaseHookError,
		);
		expect(await plain.isAnonymous(userId)).toBe(true);
	});
});

describe("username sign up hooks", () => {
	it("abort writes nothing, replace changes the name", async () => {
		const db = await makeDb();
		const sm = createSessionManager({ secret: SECRET }, db);
		const denied = createUsernameAuthModule({}, db, sm, undefined, {
			databaseHooks: runnerOf({ user: { create: { before: () => false } } }),
		});
		await expect(
			denied.signUp({ username: "grace", password: "correct-horse-battery" }),
		).rejects.toBeInstanceOf(DatabaseHookError);
		expect(await db.select().from(users)).toHaveLength(0);

		const after = vi.fn();
		const mod = createUsernameAuthModule({}, db, sm, undefined, {
			databaseHooks: runnerOf({
				user: { create: { before: () => ({ data: { name: "Grace H" } }), after } },
			}),
		});
		await mod.signUp({ username: "grace", password: "correct-horse-battery" });
		const [row] = await db.select().from(users);
		expect(row?.name).toBe("Grace H");
		expect(after).toHaveBeenCalledOnce();
	});
});

describe("email OTP claim race with a before abort", () => {
	async function setup(hooks: DatabaseHooks) {
		const db = await makeDb();
		const runner = runnerOf(hooks);
		let code = "";
		const mod = createEmailOtpModule(
			{
				sendOtp: async (_e, c) => {
					code = c;
				},
			},
			db,
			createSessionManager({ secret: SECRET }, db, runner),
			undefined,
			runner,
		);
		await mod.sendCode("race@example.com");
		return { db, mod, code };
	}

	it("concurrent verifies run the hook once, the abort leaves the code consumed", async () => {
		const before = vi.fn(() => false as const);
		const { db, mod, code } = await setup({ user: { create: { before } } });
		const results = await Promise.all(
			Array.from({ length: 5 }, () =>
				mod.verifyCode("race@example.com", code).then(
					() => "ok",
					(e: unknown) => (e instanceof DatabaseHookError ? e.code : "other"),
				),
			),
		);
		expect(results.filter((r) => r === "DATABASE_HOOK_ABORTED")).toHaveLength(1);
		expect(before).toHaveBeenCalledOnce();
		expect(await db.select().from(users)).toHaveLength(0);
		expect(await db.select().from(sessions)).toHaveLength(0);
		// Decision: the code was claimed before the hook ran, so it cannot be replayed.
		expect(await mod.verifyCode("race@example.com", code)).toBeNull();
	});

	it("a replace and an after hook run once for the single winner", async () => {
		const after = vi.fn();
		const { db, mod, code } = await setup({
			user: { create: { before: () => ({ data: { name: "Raced" } }), after } },
		});
		const results = await Promise.all(
			Array.from({ length: 5 }, () => mod.verifyCode("race@example.com", code)),
		);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		expect(after).toHaveBeenCalledOnce();
		const [row] = await db.select().from(users);
		expect(row?.name).toBe("Raced");
	});
});

describe("billing webhook update hook", () => {
	async function signed(event: unknown): Promise<Request> {
		const payload = JSON.stringify(event);
		const t = String(Math.floor(Date.now() / 1000));
		const enc = new TextEncoder();
		const key = await crypto.subtle.importKey(
			"raw",
			enc.encode("whsec_hook"),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);
		const sig = new Uint8Array(
			await crypto.subtle.sign("HMAC", key, enc.encode(`${t}.${payload}`)),
		);
		const hex = Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
		return new Request("https://example.com/auth/stripe/webhook", {
			method: "POST",
			headers: { "stripe-signature": `t=${t},v1=${hex}` },
			body: payload,
		});
	}

	const failed = {
		type: "invoice.payment_failed",
		data: { object: { id: "in_1", customer: "cus_1", subscription: "sub_1" } },
	};

	async function seedCustomer() {
		const db = await makeDb();
		const now = new Date();
		await db.insert(users).values({
			id: "u1",
			email: "u1@example.com",
			stripeCustomerId: "cus_1",
			createdAt: now,
			updatedAt: now,
		});
		return db;
	}

	it("runs the update hooks around the webhook write", async () => {
		const db = await seedCustomer();
		const after = vi.fn();
		const mod = createStripeModule(
			{ secretKey: "sk_test_1", webhookSecret: "whsec_hook" },
			db,
			runnerOf({ user: { update: { after } } }),
		);
		const res = await mod.handleWebhook(await signed(failed));
		expect(res.status).toBe(200);
		const [row] = await db.select().from(users);
		expect(row?.stripeSubscriptionStatus).toBe("past_due");
		expect(after).toHaveBeenCalledOnce();
	});

	it("a before abort answers 500 so Stripe retries, and the row is untouched", async () => {
		const db = await seedCustomer();
		const mod = createStripeModule(
			{ secretKey: "sk_test_1", webhookSecret: "whsec_hook" },
			db,
			runnerOf({ user: { update: { before: () => false } } }),
		);
		const res = await mod.handleWebhook(await signed(failed));
		expect(res.status).toBe(500);
		const [row] = await db.select().from(users);
		expect(row?.stripeSubscriptionStatus ?? null).toBeNull();
	});
});
