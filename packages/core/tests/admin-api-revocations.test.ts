import { describe, expect, it } from "vitest";
import { adminApi } from "../src/admin-api/index.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, auditLogs, delegationChains, users } from "../src/db/schema.js";
import { createRevocationBus } from "../src/mcp/revocation-bus.js";
import { createDbRevocationStore } from "../src/mcp/stores-db-revocation.js";
import type { EndpointContext, PluginEndpoint } from "../src/plugin/types.js";

const ADMIN = "user_admin";
const SYS = "agent_system";

async function build(withBus = true) {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	await db
		.insert(users)
		.values({ id: ADMIN, email: "a@example.com", name: "a", createdAt: now, updatedAt: now });
	for (const id of [SYS, "agent_b", "agent_c"]) {
		await db.insert(agents).values({
			id,
			ownerId: ADMIN,
			name: id,
			type: "autonomous",
			status: "active",
			tokenHash: `h_${id}`,
			tokenPrefix: id.slice(0, 8),
			createdAt: now,
			updatedAt: now,
		});
	}
	const future = new Date(now.getTime() + 3_600_000);
	const link = (id: string, from: string, to: string) =>
		db.insert(delegationChains).values({
			id,
			fromAgentId: from,
			toAgentId: to,
			permissions: [{ resource: "mcp:*", actions: ["read"] }],
			depth: 1,
			maxDepth: 3,
			status: "active",
			expiresAt: future,
			createdAt: now,
		});
	await link("d1", SYS, "agent_b");
	await link("d2", "agent_b", "agent_c");

	const bus = createRevocationBus({ store: createDbRevocationStore(db) });
	const endpoints: PluginEndpoint[] = [];
	await adminApi({ enabled: true, adminUserIds: [ADMIN], systemAgentId: SYS }).init?.({
		db,
		config: {} as never,
		addEndpoint: (ep) => endpoints.push(ep),
		addMigration: () => undefined,
		sessionManager: null,
		...(withBus ? { revocations: bus } : {}),
	});
	const ctx: EndpointContext = {
		db,
		getSession: async () => null,
		getUser: async (req) => (req.headers.get("authorization") ? { id: ADMIN } : null),
	};
	const call = (method: string, path: string, body?: unknown) => {
		const route = endpoints.find((e) => e.method === method && e.path === path.split("?")[0]);
		if (!route) throw new Error(`no route ${method} ${path}`);
		return route.handler(
			new Request(`http://localhost/api${path}`, {
				method,
				headers: { authorization: "Bearer t", "Content-Type": "application/json" },
				body: body === undefined ? undefined : JSON.stringify(body),
			}),
			ctx,
		);
	};
	return { db, call };
}

describe("admin api: revocations", () => {
	it("previews the cascade of each live link", async () => {
		const { call } = await build();
		const res = await call("GET", "/revocations/delegations");
		const links = (await res.json()) as Array<{ id: string; cascade: string[]; agents: string[] }>;
		const d1 = links.find((l) => l.id === "d1");
		expect(d1?.cascade).toEqual(["d1", "d2"]);
		expect(d1?.agents).toEqual(["agent_b", "agent_c"]);
		expect(links.find((l) => l.id === "d2")?.cascade).toEqual(["d2"]);
	});

	it("revokes a delegation through the bus, audits it, and lists the denylist rows with stats", async () => {
		const { call, db } = await build();
		const res = await call("POST", "/revocations", { kind: "dlg", id: "d1", reason: "leaked" });
		expect(res.status).toBe(201);
		expect(((await res.json()) as { revoked: string[] }).revoked).toEqual(["d1", "d2"]);

		const list = (await (await call("GET", "/revocations?kind=dlg")).json()) as {
			rows: Array<{ kind: string; id: string }>;
			stats: { published: number; rowsPushed: number } | null;
		};
		expect(list.rows.map((r) => r.id).sort()).toEqual(["d1", "d2"]);
		expect(list.stats?.rowsPushed).toBe(2);

		const rows = await db.select().from(auditLogs);
		expect(rows.some((r) => r.resource === "revocation:dlg:d1")).toBe(true);
	});

	it("revokes an agent id and refuses without a bus", async () => {
		const { call } = await build();
		expect((await call("POST", "/revocations", { kind: "agent", id: "agent_b" })).status).toBe(201);
		const rows = (await (await call("GET", "/revocations?kind=agent")).json()) as {
			rows: Array<{ id: string }>;
		};
		expect(rows.rows.map((r) => r.id)).toEqual(["agent_b"]);

		const bare = await build(false);
		const res = await bare.call("POST", "/revocations", { kind: "sub", id: "u1" });
		expect(res.status).toBe(503);
		const stats = (await (await bare.call("GET", "/revocations")).json()) as { stats: unknown };
		expect(stats.stats).toBeNull();
	});

	it("rejects bad input and unknown delegations", async () => {
		const { call } = await build();
		expect((await call("POST", "/revocations", { kind: "nope", id: "x" })).status).toBe(400);
		expect((await call("POST", "/revocations", { kind: "dlg", id: "missing" })).status).toBe(404);
		expect((await call("GET", "/revocations?kind=nope")).status).toBe(400);
	});
});
