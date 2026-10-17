import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import type { AdminApiConfig } from "../src/admin-api/index.js";
import { adminApi } from "../src/admin-api/index.js";
import { createApprovalModule } from "../src/approval/approval.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, delegationChains, sessions, users } from "../src/db/schema.js";
import type { EndpointContext, PluginEndpoint } from "../src/plugin/types.js";

const ADMIN = "user_admin";
const OTHER_ADMIN = "user_admin2";
const REGULAR = "user_regular";
const TARGET = "user_target";
const SYS = "agent_system";

const tokens: Record<string, string> = {
	"admin-token": ADMIN,
	"admin2-token": OTHER_ADMIN,
	"regular-token": REGULAR,
};

interface Harness {
	db: Database;
	call: (
		method: string,
		path: string,
		opts?: { token?: string; body?: unknown; noBearer?: boolean },
	) => Promise<Response>;
	endpoints: PluginEndpoint[];
}

async function build(config?: Partial<AdminApiConfig>): Promise<Harness> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	for (const id of [ADMIN, OTHER_ADMIN, REGULAR, TARGET]) {
		await db
			.insert(users)
			.values({ id, email: `${id}@example.com`, name: id, createdAt: now, updatedAt: now });
	}
	await db.insert(agents).values({
		id: SYS,
		ownerId: ADMIN,
		name: "system",
		type: "autonomous",
		status: "active",
		tokenHash: "h",
		tokenPrefix: "p",
		createdAt: now,
		updatedAt: now,
	});
	const endpoints: PluginEndpoint[] = [];
	await adminApi({
		enabled: true,
		adminUserIds: [ADMIN, OTHER_ADMIN],
		systemAgentId: SYS,
		...config,
	}).init?.({
		db,
		config: {} as never,
		addEndpoint: (ep) => endpoints.push(ep),
		addMigration: () => undefined,
		sessionManager: null,
	});
	const ctx: EndpointContext = {
		db,
		getSession: async () => null,
		getUser: async (req) => {
			const t = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
			const id = t ? tokens[t] : undefined;
			return id ? { id } : null;
		},
	};
	return {
		db,
		endpoints,
		async call(method, path, opts = {}) {
			const route = endpoints.find((e) => {
				if (e.method !== method) return false;
				const pat = e.path.split("/");
				const act = path.split("?")[0]?.split("/") ?? [];
				return pat.length === act.length && pat.every((s, i) => s.startsWith(":") || s === act[i]);
			});
			if (!route) return new Response("not found", { status: 404 });
			const headers: Record<string, string> = { "Content-Type": "application/json" };
			if (!opts.noBearer && opts.token) headers.authorization = `Bearer ${opts.token}`;
			return route.handler(
				new Request(`http://localhost/api${path}`, {
					method,
					headers,
					body: method === "GET" || opts.body === undefined ? undefined : JSON.stringify(opts.body),
				}),
				ctx,
			);
		},
	};
}

const open = (h: Harness, resource = "agent:abc") =>
	h.call("POST", "/approvals", {
		token: "admin-token",
		body: { agentId: "theauth-mcp", userId: "theauth-mcp", action: "admin:revoke_agent", resource },
	});

describe("admin api: disabled by default", () => {
	it("registers no routes unless enabled is exactly true", async () => {
		for (const enabled of [undefined, false]) {
			const h = await build({ enabled });
			expect(h.endpoints).toHaveLength(0);
			expect((await h.call("GET", "/sessions", { token: "admin-token" })).status).toBe(404);
		}
	});

	it("refuses to start enabled without a system agent", async () => {
		await expect(build({ systemAgentId: "" })).rejects.toThrow(/systemAgentId/);
	});
});

describe("admin api: authentication and authorization", () => {
	let h: Harness;
	beforeEach(async () => {
		h = await build();
	});

	const routes: Array<[string, string]> = [
		["POST", "/approvals"],
		["GET", "/approvals/apr_1"],
		["POST", "/approvals/apr_1/consume"],
		["POST", "/audit/events"],
		["GET", "/delegations"],
		["DELETE", "/delegations/d1"],
		["POST", "/users/user_target/disable"],
		["GET", "/sessions"],
	];

	it("registers every route", () => {
		expect(h.endpoints).toHaveLength(routes.length);
	});

	for (const [method, path] of routes) {
		it(`${method} ${path}: 401 without credentials, 403 for non-admin`, async () => {
			expect((await h.call(method, path, { body: {} })).status).toBe(401);
			expect((await h.call(method, path, { token: "bogus", body: {} })).status).toBe(401);
			expect((await h.call(method, path, { token: "regular-token", body: {} })).status).toBe(403);
		});
	}

	it("denies everyone when adminUserIds is empty", async () => {
		const empty = await build({ adminUserIds: [] });
		expect((await empty.call("GET", "/sessions", { token: "admin-token" })).status).toBe(403);
	});

	it("rate limits per admin", async () => {
		const limited = await build({ rateLimit: { max: 2, window: 60 } });
		const get = () => limited.call("GET", "/sessions", { token: "admin-token" });
		expect((await get()).status).toBe(200);
		expect((await get()).status).toBe(200);
		expect((await get()).status).toBe(429);
	});
});

describe("admin api: approvals", () => {
	let h: Harness;
	beforeEach(async () => {
		h = await build();
	});

	async function approvedId(resource = "agent:abc"): Promise<string> {
		const res = await open(h, resource);
		expect(res.status).toBe(201);
		const { id } = (await res.json()) as { id: string };
		await createApprovalModule({}, h.db).approve(id, "human");
		return id;
	}

	const consume = (id: string, token = "admin-token", resource = "agent:abc") =>
		h.call("POST", `/approvals/${id}/consume`, {
			token,
			body: { agentId: "theauth-mcp", action: "admin:revoke_agent", resource },
		});

	it("opens a pending request owned by the caller, ignoring body ids", async () => {
		const res = await open(h);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.status).toBe("pending");
		expect(typeof body.expiresAt).toBe("string");
		const got = await h.call("GET", `/approvals/${String(body.id)}`, { token: "admin-token" });
		expect(((await got.json()) as { status: string }).status).toBe("pending");
	});

	it("validates input", async () => {
		const bad = [
			{ action: "write", resource: "agent:abc" },
			{ action: "admin:x", resource: "" },
			{ action: "admin:x", resource: "a b" },
			{ action: "admin:x", resource: "r", arguments: "nope" },
		];
		for (const body of bad) {
			expect((await h.call("POST", "/approvals", { token: "admin-token", body })).status).toBe(400);
		}
		expect((await h.call("GET", "/approvals/apr_missing", { token: "admin-token" })).status).toBe(
			404,
		);
	});

	it("consume is single use: the replay is refused", async () => {
		const id = await approvedId();
		expect((await consume(id)).status).toBe(200);
		const replay = await consume(id);
		expect(replay.status).toBe(409);
		expect(((await replay.json()) as { error: { code: string } }).error.code).toBe(
			"APPROVAL_ALREADY_USED",
		);
	});

	it("concurrent consumes: exactly one wins", async () => {
		const id = await approvedId();
		const results = await Promise.all([consume(id), consume(id), consume(id)]);
		expect(results.filter((r) => r.status === 200)).toHaveLength(1);
	});

	it("refuses unapproved, mismatched and foreign consumes", async () => {
		const pending = (await (await open(h)).json()) as { id: string };
		expect((await consume(pending.id)).status).toBe(409);
		const id = await approvedId();
		expect((await consume(id, "admin-token", "agent:other")).status).toBe(409);
		expect((await consume(id, "admin2-token")).status).toBe(403);
		expect((await consume("apr_missing")).status).toBe(404);
		// The mismatch and foreign attempts did not spend it.
		expect((await consume(id)).status).toBe(200);
	});
});

describe("admin api: audit, delegations, users, sessions", () => {
	let h: Harness;
	beforeEach(async () => {
		h = await build();
	});

	it("stores an audit event and scrubs secret-looking params", async () => {
		const res = await h.call("POST", "/audit/events", {
			token: "admin-token",
			body: {
				actor: "ops-bot",
				source: "theauth-mcp",
				action: "admin_mcp.revoke_agent",
				mode: "write",
				result: "executed",
				params: { id: "a1", apiKey: "sk-live-123", nested: { token: "t0k" } },
			},
		});
		expect(res.status).toBe(201);
		const rows = await h.db
			.select()
			.from(auditLogs)
			.where(eq(auditLogs.action, "admin_mcp.revoke_agent"));
		expect(rows).toHaveLength(1);
		const text = JSON.stringify(rows[0]?.parameters);
		expect(text).not.toContain("sk-live-123");
		expect(text).not.toContain("t0k");
		expect(rows[0]?.userId).toBe(ADMIN);
	});

	it("rejects malformed audit events", async () => {
		const base = {
			actor: "a",
			action: "admin_mcp.x",
			mode: "read",
			result: "ok",
			params: {},
		};
		for (const patch of [
			{ action: "other.x" },
			{ mode: "root" },
			{ result: "weird" },
			{ actor: "" },
			{ params: "x" },
		]) {
			const res = await h.call("POST", "/audit/events", {
				token: "admin-token",
				body: { ...base, ...patch },
			});
			expect(res.status).toBe(400);
		}
	});

	it("lists and revokes delegations", async () => {
		const now = new Date();
		const future = new Date(now.getTime() + 3_600_000);
		await h.db.insert(delegationChains).values({
			id: "d1",
			fromAgentId: SYS,
			toAgentId: SYS,
			permissions: [{ resource: "mcp:*", actions: ["read"] }],
			depth: 1,
			maxDepth: 3,
			status: "active",
			expiresAt: future,
			createdAt: now,
		});
		const list = (await (
			await h.call("GET", "/delegations?status=active", { token: "admin-token" })
		).json()) as Array<{ id: string }>;
		expect(list.map((d) => d.id)).toEqual(["d1"]);
		expect(
			(await h.call("GET", "/delegations?status=bogus", { token: "admin-token" })).status,
		).toBe(400);
		expect((await h.call("DELETE", "/delegations/nope", { token: "admin-token" })).status).toBe(
			404,
		);
		expect((await h.call("DELETE", "/delegations/d1", { token: "admin-token" })).status).toBe(200);
		const [row] = await h.db.select().from(delegationChains).where(eq(delegationChains.id, "d1"));
		expect(row?.status).toBe("revoked");
	});

	it("disables a user and ends sessions, but not self or admins", async () => {
		const now = new Date();
		await h.db.insert(sessions).values({
			id: "sess_secret_id",
			userId: TARGET,
			expiresAt: new Date(now.getTime() + 3_600_000),
			createdAt: now,
		});
		const listed = await h.call("GET", `/sessions?userId=${TARGET}`, { token: "admin-token" });
		const text = await listed.text();
		expect(text).not.toContain("sess_secret_id");
		expect(JSON.parse(text)).toHaveLength(1);

		expect((await h.call("POST", `/users/${ADMIN}/disable`, { token: "admin-token" })).status).toBe(
			400,
		);
		expect(
			(await h.call("POST", `/users/${OTHER_ADMIN}/disable`, { token: "admin-token" })).status,
		).toBe(403);
		expect((await h.call("POST", "/users/ghost/disable", { token: "admin-token" })).status).toBe(
			404,
		);
		const ok = await h.call("POST", `/users/${TARGET}/disable`, {
			token: "admin-token",
			body: { reason: "mcp" },
		});
		expect(ok.status).toBe(200);
		const [u] = await h.db.select().from(users).where(eq(users.id, TARGET));
		expect(u?.banned).toBe(1);
		expect(await h.db.select().from(sessions).where(eq(sessions.userId, TARGET))).toHaveLength(0);
	});
});
