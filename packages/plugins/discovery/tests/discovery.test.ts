import type { Kavach } from "@glinr/theauth";
import { createKavach, users } from "@glinr/theauth";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DiscoveryModule } from "../src/cards.js";
import { createDiscoveryModule } from "../src/cards.js";

async function createTestKavach(): Promise<Kavach> {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	// Seed a test user
	kavach.db
		.insert(users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

describe("discovery – agent capability cards", () => {
	let kavach: Kavach;
	let discovery: DiscoveryModule;
	let agentId: string;

	beforeEach(async () => {
		kavach = await createTestKavach();
		discovery = createDiscoveryModule(kavach.db);

		const agent = await kavach.agent.create({
			ownerId: "user-1",
			name: "Test Agent",
			type: "autonomous",
			permissions: [],
		});
		agentId = agent.id;
	});

	afterEach(() => {
		// In-memory SQLite — no teardown needed
	});

	it("registers a capability card", async () => {
		const card = await discovery.registerCard(agentId, {
			name: "Code Reviewer",
			description: "Reviews pull requests and suggests improvements",
			version: "1.0.0",
			protocols: ["mcp", "a2a"],
			capabilities: [
				{
					name: "code_review",
					description: "Review code for correctness, style, and security",
					inputSchema: { type: "object", properties: { pr_url: { type: "string" } } },
				},
			],
			authRequirements: { type: "bearer" },
		});

		expect(card.id).toBeDefined();
		expect(card.name).toBe("Code Reviewer");
		expect(card.version).toBe("1.0.0");
		expect(card.protocols).toEqual(["mcp", "a2a"]);
		expect(card.capabilities).toHaveLength(1);
		expect(card.capabilities[0]?.name).toBe("code_review");
		expect(card.authRequirements.type).toBe("bearer");
		expect(card.createdAt).toBeDefined();
		expect(card.updatedAt).toBeDefined();
	});

	it("retrieves a card by agentId", async () => {
		await discovery.registerCard(agentId, {
			name: "Search Agent",
			description: "Searches the web",
			version: "2.0.0",
			protocols: ["rest"],
			capabilities: [{ name: "web_search", description: "Search the internet" }],
			authRequirements: { type: "api-key" },
		});

		const card = await discovery.getCard(agentId);
		expect(card).not.toBeNull();
		expect(card?.name).toBe("Search Agent");
	});

	it("returns null for unknown agentId", async () => {
		const card = await discovery.getCard("non-existent-agent");
		expect(card).toBeNull();
	});

	it("updates a card", async () => {
		await discovery.registerCard(agentId, {
			name: "Old Name",
			description: "Old description",
			version: "1.0.0",
			protocols: ["mcp"],
			capabilities: [],
			authRequirements: { type: "none" },
		});

		const updated = await discovery.updateCard(agentId, {
			name: "New Name",
			version: "1.1.0",
		});

		expect(updated.name).toBe("New Name");
		expect(updated.version).toBe("1.1.0");
		expect(updated.description).toBe("Old description");
	});

	it("throws when updating a non-existent card", async () => {
		await expect(discovery.updateCard("ghost-agent", { name: "x" })).rejects.toThrow("ghost-agent");
	});

	it("removes a card", async () => {
		await discovery.registerCard(agentId, {
			name: "Temp",
			description: "",
			version: "0.1.0",
			protocols: [],
			capabilities: [],
			authRequirements: { type: "none" },
		});

		await discovery.removeCard(agentId);
		const card = await discovery.getCard(agentId);
		expect(card).toBeNull();
	});

	describe("searchCards", () => {
		let agent2Id: string;

		beforeEach(async () => {
			const agent2 = await kavach.agent.create({
				ownerId: "user-1",
				name: "Agent Two",
				type: "service",
				permissions: [],
			});
			agent2Id = agent2.id;

			await discovery.registerCard(agentId, {
				name: "MCP File Agent",
				description: "Reads and writes files",
				version: "1.0.0",
				protocols: ["mcp"],
				capabilities: [{ name: "file_read", description: "Read files" }],
				authRequirements: { type: "bearer" },
			});

			await discovery.registerCard(agent2Id, {
				name: "REST Search Agent",
				description: "Web search",
				version: "1.0.0",
				protocols: ["rest", "a2a"],
				capabilities: [{ name: "web_search", description: "Search" }],
				authRequirements: { type: "api-key" },
			});
		});

		it("returns all cards with empty query", async () => {
			const results = await discovery.searchCards({});
			expect(results).toHaveLength(2);
		});

		it("filters by protocol", async () => {
			const results = await discovery.searchCards({ protocols: ["mcp"] });
			expect(results).toHaveLength(1);
			expect(results[0]?.name).toBe("MCP File Agent");
		});

		it("filters by capability name", async () => {
			const results = await discovery.searchCards({ capabilities: ["web_search"] });
			expect(results).toHaveLength(1);
			expect(results[0]?.name).toBe("REST Search Agent");
		});

		it("filters by name substring", async () => {
			const results = await discovery.searchCards({ name: "File" });
			expect(results).toHaveLength(1);
			expect(results[0]?.name).toBe("MCP File Agent");
		});

		it("combines protocol and name filters", async () => {
			const results = await discovery.searchCards({
				protocols: ["rest"],
				name: "Search",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.name).toBe("REST Search Agent");
		});

		it("returns empty when no match", async () => {
			const results = await discovery.searchCards({ protocols: ["grpc"] });
			expect(results).toHaveLength(0);
		});
	});
});
