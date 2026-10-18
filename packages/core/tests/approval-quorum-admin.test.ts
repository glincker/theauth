/** Quorum approvals over the admin API: open with a quorum, vote, progress, refusals. */
import { describe, expect, it } from "vitest";
import { adminApi } from "../src/admin-api/index.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { agents, users } from "../src/db/schema.js";
import type { EndpointContext, PluginEndpoint } from "../src/plugin/types.js";

const IDS = ["admin1", "admin2", "admin3"];
const SYS = "agent_system";

async function build() {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	for (const id of IDS) {
		await db
			.insert(users)
			.values({ id, email: `${id}@example.com`, name: id, createdAt: now, updatedAt: now });
	}
	await db.insert(agents).values({
		id: SYS,
		ownerId: "admin1",
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
		adminUserIds: IDS,
		systemAgentId: SYS,
		allowSelfApproval: true,
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
			return t && IDS.includes(t) ? { id: t } : null;
		},
	};
	async function call(method: string, path: string, as: string, body?: unknown) {
		const route = endpoints.find((e) => {
			if (e.method !== method) return false;
			const pat = e.path.split("/");
			const act = path.split("/");
			return pat.length === act.length && pat.every((s, i) => s.startsWith(":") || s === act[i]);
		});
		if (!route) throw new Error(`no route ${method} ${path}`);
		const res = await route.handler(
			new Request(`http://localhost/api${path}`, {
				method,
				headers: { "Content-Type": "application/json", authorization: `Bearer ${as}` },
				body: body === undefined ? undefined : JSON.stringify(body),
			}),
			ctx,
		);
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	}
	return { call };
}

const OPEN = { action: "admin:revoke_agent", resource: "agent:abc" };

describe("admin api quorum approvals", () => {
	it("needs two other admins and reports progress", async () => {
		const { call } = await build();
		const opened = await call("POST", "/approvals", "admin1", { ...OPEN, requiredApprovals: 2 });
		expect(opened.status).toBe(201);
		expect(opened.body.requiredApprovals).toBe(2);
		const id = String(opened.body.id);

		const self = await call("POST", `/approvals/${id}/approve`, "admin1");
		expect(self.status).toBe(403);
		expect(self.body).toMatchObject({ error: { code: "SELF_APPROVAL" } });

		const first = await call("POST", `/approvals/${id}/approve`, "admin2");
		expect(first.status).toBe(200);
		expect(first.body).toMatchObject({
			status: "pending",
			approvalsReceived: 1,
			requiredApprovals: 2,
		});

		const repeat = await call("POST", `/approvals/${id}/approve`, "admin2");
		expect(repeat.status).toBe(409);
		expect(repeat.body).toMatchObject({ error: { code: "DUPLICATE_APPROVER" } });

		const pendingList = await call("GET", "/approvals", "admin3");
		expect(pendingList.status).toBe(200);

		const second = await call("POST", `/approvals/${id}/approve`, "admin3");
		expect(second.body).toMatchObject({ status: "approved", approvalsReceived: 2 });

		const got = await call("GET", `/approvals/${id}`, "admin3");
		expect(got.body).toMatchObject({
			status: "approved",
			requiredApprovals: 2,
			approvalsReceived: 2,
			approvers: ["admin2", "admin3"],
		});

		const spent = await call("POST", `/approvals/${id}/consume`, "admin1", OPEN);
		expect(spent.status).toBe(200);
		expect((await call("POST", `/approvals/${id}/consume`, "admin1", OPEN)).status).toBe(409);
	});

	it("rejects a bad quorum and keeps one approver as the default", async () => {
		const { call } = await build();
		for (const requiredApprovals of [0, 11, 2.5, "2"]) {
			const res = await call("POST", "/approvals", "admin1", { ...OPEN, requiredApprovals });
			expect(res.status).toBe(400);
			expect(res.body).toMatchObject({ error: { code: "INVALID_QUORUM" } });
		}
		const plain = await call("POST", "/approvals", "admin1", OPEN);
		expect(plain.body.requiredApprovals).toBe(1);
		const done = await call("POST", `/approvals/${String(plain.body.id)}/approve`, "admin1");
		expect(done.body).toMatchObject({ status: "approved", approvalsReceived: 1 });
	});

	it("lets one denial end a quorum request", async () => {
		const { call } = await build();
		const opened = await call("POST", "/approvals", "admin1", { ...OPEN, requiredApprovals: 2 });
		const id = String(opened.body.id);
		await call("POST", `/approvals/${id}/approve`, "admin2");
		const denied = await call("POST", `/approvals/${id}/deny`, "admin3");
		expect(denied.body).toMatchObject({ status: "denied" });
		expect((await call("POST", `/approvals/${id}/approve`, "admin3")).status).toBe(409);
	});
});
