/** Self service API keys can never exceed the creating user's own permissions. */
import { beforeEach, describe, expect, it } from "vitest";
import { createApiKeyManagerModule } from "../src/auth/api-key-manager.js";
import { apiKeys } from "../src/auth/api-key-plugin.js";
import { permissionCovers } from "../src/auth/api-key-scope.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import type { PluginEndpoint } from "../src/plugin/types.js";

async function makeDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	for (const id of ["alice", "root"]) {
		await db
			.insert(users)
			.values({ id, email: `${id}@example.com`, createdAt: now, updatedAt: now });
	}
	return db;
}

const post = (body: unknown) =>
	new Request("http://localhost/auth/api-keys", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});

describe("permissionCovers", () => {
	it.each([
		["*", "anything:at:all", true],
		["agents:read", "agents:read", true],
		["agents:read", "agents:write", false],
		["agents:*", "agents:read", true],
		["agents:*", "agents:read:own", true],
		["agents:*", "agentsx:read", false],
		["agents:*", "*", false],
		["agents:read", "agents:*", false],
		["agents:*", "agents:*", true],
		["agents:*", "agents:x:*", true],
		["agents:x:*", "agents:*", false],
	])("grant %s covers %s: %s", (granted, requested, expected) => {
		expect(permissionCovers(granted, requested)).toBe(expected);
	});
});

describe("api key handleRequest scoping", () => {
	let db: Database;
	beforeEach(async () => {
		db = await makeDb();
	});
	const as = (id: string) => async () => ({ id });

	it("denies a wildcard key when no resolver is configured (fail closed)", async () => {
		const mod = createApiKeyManagerModule({}, db, { resolveUser: as("alice") });
		const res = await mod.handleRequest(post({ userId: "alice", name: "n", permissions: ["*"] }));
		expect(res?.status).toBe(403);
		expect(((await res?.json()) as { error: string }).error).toBe("permissions_not_grantable");
		expect(await mod.list("alice")).toHaveLength(0);
	});

	it("allows an empty permission list without a resolver", async () => {
		const mod = createApiKeyManagerModule({}, db, { resolveUser: as("alice") });
		const res = await mod.handleRequest(post({ userId: "alice", name: "n", permissions: [] }));
		expect(res?.status).toBe(201);
	});

	it("caps keys to the caller's grants", async () => {
		const mod = createApiKeyManagerModule(
			{ grantablePermissions: () => ["agents:read", "tools:*"] },
			db,
			{ resolveUser: as("alice") },
		);
		const ok = await mod.handleRequest(
			post({ userId: "alice", name: "n", permissions: ["agents:read", "tools:run"] }),
		);
		expect(ok?.status).toBe(201);
		const bad = await mod.handleRequest(
			post({ userId: "alice", name: "n", permissions: ["agents:read", "agents:write", "*"] }),
		);
		expect(bad?.status).toBe(403);
		expect(((await bad?.json()) as { denied: string[] }).denied).toEqual(["agents:write", "*"]);
	});

	it("rejects malformed permission lists", async () => {
		const mod = createApiKeyManagerModule({ grantablePermissions: () => ["*"] }, db, {
			resolveUser: as("alice"),
		});
		for (const permissions of [[1], [""], "agents:read", [null]]) {
			const res = await mod.handleRequest(post({ userId: "alice", name: "n", permissions }));
			expect(res?.status).toBe(400);
		}
	});

	it("adminOverride lifts the cap for that user only", async () => {
		const config = { adminOverride: (id: string) => id === "root" };
		const root = createApiKeyManagerModule(config, db, { resolveUser: as("root") });
		const alice = createApiKeyManagerModule(config, db, { resolveUser: as("alice") });
		expect(
			(await root.handleRequest(post({ userId: "root", name: "n", permissions: ["*"] })))?.status,
		).toBe(201);
		expect(
			(await alice.handleRequest(post({ userId: "alice", name: "n", permissions: ["*"] })))?.status,
		).toBe(403);
	});

	it("trusted server use and direct create() are not capped", async () => {
		const trusted = createApiKeyManagerModule({ trustedServerUse: true }, db);
		expect(
			(await trusted.handleRequest(post({ userId: "alice", name: "n", permissions: ["*"] })))
				?.status,
		).toBe(201);
		const direct = await trusted.create({ userId: "alice", name: "d", permissions: ["*"] });
		expect(direct.apiKey.permissions).toEqual(["*"]);
	});
});

describe("api key plugin scoping", () => {
	async function endpoint(config: Parameters<typeof apiKeys>[0]) {
		const db = await makeDb();
		const endpoints: PluginEndpoint[] = [];
		const plugin = apiKeys(config);
		await plugin.init?.({
			db,
			addEndpoint: (e: PluginEndpoint) => endpoints.push(e),
		} as unknown as Parameters<NonNullable<typeof plugin.init>>[0]);
		const create = endpoints.find((e) => e.method === "POST" && e.path === "/auth/api-keys");
		if (!create) throw new Error("create endpoint missing");
		const call = (body: unknown) =>
			create.handler(post(body), {
				getUser: async () => ({ id: "alice" }),
			} as unknown as Parameters<PluginEndpoint["handler"]>[1]);
		return call;
	}

	it("denies a wildcard key by default and allows a covered one", async () => {
		const call = await endpoint(undefined);
		expect((await call({ name: "n", permissions: ["*"] })).status).toBe(403);
		const scoped = await endpoint({ grantablePermissions: () => ["agents:read"] });
		expect((await scoped({ name: "n", permissions: ["agents:read"] })).status).toBe(201);
		expect((await scoped({ name: "n", permissions: ["agents:write"] })).status).toBe(403);
	});
});
