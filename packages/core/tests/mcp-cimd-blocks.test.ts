/** CIMD admin state: blocks by URL or host, refresh never undoes admin decisions, token revocation. One table runs against the memory and database stores. */
import { describe, expect, it } from "vitest";
import { oauthAccessTokens } from "../src/db/schema.js";
import { createInMemoryBlockStore, createInMemoryClientStore } from "../src/mcp/memory-stores.js";
import { createMcpStores } from "../src/mcp/stores-db.js";
import { createDbBlockStore } from "../src/mcp/stores-db-blocks.js";
import type { McpClientStore } from "../src/mcp/stores-db-clients.js";
import { createDbClientStore } from "../src/mcp/stores-db-clients.js";
import type { McpClient } from "../src/mcp/types.js";
import type { McpClientBlockStore } from "../src/mcp/types-cimd.js";
import { bootDb } from "./mcp-db-harness.js";

const CLIENT_URL = "https://app.example.com/oauth/client.json";

interface Backend {
	name: string;
	make: () => Promise<{
		blocks: McpClientBlockStore;
		clients: McpClientStore;
		agentId: () => Promise<string>;
	}>;
}

const backends: Backend[] = [
	{
		name: "memory",
		make: async () => ({
			blocks: createInMemoryBlockStore(),
			clients: createInMemoryClientStore(),
			agentId: async () => "agent-mem",
		}),
	},
	{
		name: "database",
		make: async () => {
			const d = await bootDb();
			return {
				blocks: createDbBlockStore(d.auth.db),
				clients: createDbClientStore(d.auth.db),
				agentId: async () =>
					(
						await d.auth.agent.create({
							ownerId: d.userId,
							name: "bound",
							type: "autonomous",
							permissions: [],
						})
					).id,
			};
		},
	},
];

function cimdClient(overrides: Partial<McpClient> = {}): McpClient {
	const now = new Date();
	return {
		clientId: CLIENT_URL,
		clientSecret: null,
		clientName: "Example",
		clientUri: null,
		logoUri: null,
		redirectUris: ["https://app.example.com/cb"],
		grantTypes: ["authorization_code"],
		responseTypes: ["code"],
		tokenEndpointAuthMethod: "none",
		scope: "mcp:read",
		contacts: null,
		tosUri: null,
		policyUri: null,
		softwareId: null,
		softwareVersion: null,
		clientType: "public",
		disabled: false,
		userId: null,
		source: "cimd",
		createdAt: now,
		updatedAt: now,
		...overrides,
	};
}

describe.each(backends)("CIMD admin state ($name store)", (backend) => {
	it("blocks and unblocks by exact url", async () => {
		const { blocks } = await backend.make();
		expect(await blocks.findBlock(CLIENT_URL, ["app.example.com", "example.com"])).toBeNull();
		const rule = await blocks.addBlock({ kind: "url", value: CLIENT_URL, reason: "abuse" });
		expect(rule).toMatchObject({
			kind: "url",
			value: CLIENT_URL,
			reason: "abuse",
			createdBy: null,
		});
		expect((await blocks.findBlock(CLIENT_URL, []))?.id).toBe(rule.id);
		expect(await blocks.findBlock(`${CLIENT_URL}x`, [])).toBeNull();
		await blocks.removeBlock(rule.id);
		expect(await blocks.findBlock(CLIENT_URL, [])).toBeNull();
		expect(await blocks.listBlocks()).toEqual([]);
	});

	it("blocks by host, covers parent domains through the hosts list, ignores case", async () => {
		const { blocks } = await backend.make();
		const rule = await blocks.addBlock({ kind: "host", value: "Example.COM.", createdBy: "admin" });
		expect(rule.value).toBe("example.com");
		expect(await blocks.findBlock(CLIENT_URL, ["app.example.com", "example.com"])).toMatchObject({
			id: rule.id,
			createdBy: "admin",
		});
		expect(await blocks.findBlock(CLIENT_URL, ["app.example.com"])).toBeNull();
		expect(await blocks.findBlock("https://other.test/c", ["other.test"])).toBeNull();
		await blocks.removeBlock(rule.id);
		expect(await blocks.findBlock(CLIENT_URL, ["example.com"])).toBeNull();
	});

	it("check hits both kinds and list returns every rule", async () => {
		const { blocks } = await backend.make();
		const u = await blocks.addBlock({ kind: "url", value: "https://a.test/c" });
		const h = await blocks.addBlock({ kind: "host", value: "b.test" });
		expect((await blocks.findBlock("https://a.test/c", ["a.test"]))?.id).toBe(u.id);
		expect((await blocks.findBlock("https://x.b.test/c", ["x.b.test", "b.test"]))?.id).toBe(h.id);
		expect((await blocks.listBlocks()).map((b) => b.id).sort()).toEqual([u.id, h.id].sort());
	});

	it("concurrent identical block upserts leave one rule", async () => {
		const { blocks } = await backend.make();
		const results = await Promise.all(
			Array.from({ length: 8 }, () => blocks.addBlock({ kind: "host", value: "race.test" })),
		);
		expect(new Set(results.map((r) => r.id)).size).toBe(1);
		expect(await blocks.listBlocks()).toHaveLength(1);
	});

	it("a refresh with preserveAdminState keeps disabled, reason and agentId", async () => {
		const { clients, agentId } = await backend.make();
		await clients.storeClient(cimdClient());
		const agent = await agentId();
		await clients.setClientAgent(CLIENT_URL, agent);
		await clients.setClientDisabled(CLIENT_URL, true, "blocked");

		const fetched = new Date(1_800_000_000_000);
		await clients.storeClient(
			cimdClient({
				clientName: "Renamed",
				disabled: false,
				disabledReason: null,
				agentId: null,
				cimd: {
					digest: "d1",
					fetchedAt: fetched,
					expiresAt: new Date(fetched.getTime() + 3_600_000),
					document: { client_id: CLIENT_URL },
				},
			}),
			{ preserveAdminState: true },
		);
		const stored = await clients.findClient(CLIENT_URL);
		expect(stored).toMatchObject({
			clientName: "Renamed",
			disabled: true,
			disabledReason: "blocked",
			agentId: agent,
		});
		expect(stored?.cimd?.digest).toBe("d1");
		expect(stored?.cimd?.expiresAt.getTime()).toBe(fetched.getTime() + 3_600_000);
		expect(stored?.cimd?.document).toEqual({ client_id: CLIENT_URL });

		// Without the flag the caller owns the state (enable clears the reason).
		await clients.setClientDisabled(CLIENT_URL, false);
		expect(await clients.findClient(CLIENT_URL)).toMatchObject({ disabled: false });
		expect((await clients.findClient(CLIENT_URL))?.disabledReason ?? null).toBeNull();
	});

	it("an unflagged store keeps a binding when agentId is undefined", async () => {
		const { clients, agentId } = await backend.make();
		await clients.storeClient(cimdClient());
		const agent = await agentId();
		await clients.setClientAgent(CLIENT_URL, agent);
		await clients.storeClient(cimdClient({ clientName: "Again" }));
		expect(await clients.findClient(CLIENT_URL)).toMatchObject({
			agentId: agent,
			clientName: "Again",
		});
	});

	it("setClientDisabled rejects an unknown client", async () => {
		const { clients } = await backend.make();
		await expect(clients.setClientDisabled("https://nope.test/c", true)).rejects.toThrow(/Unknown/);
	});
});

describe("revokeClientTokens (database)", () => {
	it("deletes the client's token rows and returns their jtis", async () => {
		const d = await bootDb();
		const stores = createMcpStores(d.auth.db);
		await stores.storeClient(cimdClient());
		await stores.storeClient(cimdClient({ clientId: "https://other.example.com/c.json" }));
		const expiresAt = new Date(Date.now() + 3_600_000);
		const token = (clientId: string, n: string, refresh: string | null) =>
			stores.storeToken({
				accessToken: `at-${n}`,
				refreshToken: refresh,
				clientId,
				userId: d.userId,
				scope: ["mcp:read"],
				resource: null,
				tokenType: "Bearer",
				expiresIn: 3600,
				expiresAt,
				jti: `jti-${n}`,
				createdAt: new Date(),
			});
		await token(CLIENT_URL, "1", "rt-1");
		await token(CLIENT_URL, "2", null);
		await token("https://other.example.com/c.json", "3", "rt-3");

		const { jtis } = await stores.revokeClientTokens(CLIENT_URL);
		expect(jtis.map((j) => j.jti).sort()).toEqual(["jti-1", "jti-2"]);
		expect(jtis[0]?.expiresAt.getTime()).toBe(Math.floor(expiresAt.getTime() / 1000) * 1000);
		const left = await d.auth.db.select().from(oauthAccessTokens);
		expect(left).toHaveLength(1);
		expect(left[0]?.clientId).toBe("https://other.example.com/c.json");
		expect((await stores.revokeClientTokens(CLIENT_URL)).jtis).toEqual([]);
	});

	it("createMcpStores wires blocks", async () => {
		const d = await bootDb();
		const stores = createMcpStores(d.auth.db);
		const rule = await stores.blocks.addBlock({ kind: "host", value: "wired.test" });
		expect((await stores.blocks.findBlock("https://wired.test/c", ["wired.test"]))?.id).toBe(
			rule.id,
		);
	});
});
