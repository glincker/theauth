/** Wiring of the CIMD review fixes through `createMcpModule({ auth })`: DB store capabilities, the cap and sweep, and the operator logger. */
import { afterEach, describe, expect, it, vi } from "vitest";
import { oauthClients } from "../src/db/schema.js";
import { setNodeDnsForTests } from "../src/mcp/safe-fetch-dns.js";
import { createMcpModule } from "../src/mcp/server.js";
import { createMcpStores } from "../src/mcp/stores-db.js";
import type { McpClient } from "../src/mcp/types.js";
import { createTheAuth } from "../src/theauth.js";
import { mcpConfig } from "./mcp-db-harness.js";
import { REDIRECT } from "./mcp-test-harness.js";

afterEach(() => setNodeDnsForTests(undefined));

function row(clientId: string): McpClient {
	const now = new Date();
	return {
		clientId,
		clientSecret: null,
		clientName: "App",
		clientUri: null,
		logoUri: null,
		redirectUris: [REDIRECT],
		grantTypes: ["authorization_code"],
		responseTypes: ["code"],
		tokenEndpointAuthMethod: "none",
		scope: null,
		contacts: null,
		tosUri: null,
		policyUri: null,
		softwareId: null,
		softwareVersion: null,
		clientType: "public",
		disabled: false,
		userId: null,
		agentId: null,
		source: "cimd",
		createdAt: now,
		updatedAt: now,
	} as McpClient;
}

const idOf = (i: number) => `https://h${i}.example.com/c.json`;

async function boot(config: ReturnType<typeof mcpConfig>, logger?: unknown) {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		mcp: mcpConfig(),
		...(logger ? { logger: logger as never } : {}),
	});
	const user = await auth.user.create({ email: "o@example.com" });
	const mcp = createMcpModule({ auth, config, resolveUserId: async () => user.id });
	return { auth, mcp, userId: user.id };
}

describe("McpStores exposes the CIMD store functions", () => {
	it("createMcpStores provides all three", async () => {
		const { auth } = await boot(mcpConfig());
		const stores = createMcpStores(auth.db);
		expect(typeof stores.listCimdClientIds).toBe("function");
		expect(typeof stores.countUnconsentedCimdClients).toBe("function");
		expect(typeof stores.deleteStaleUnconsentedCimdClients).toBe("function");
	});
});

describe("cap and stale sweep on the database path", () => {
	it("enforces the 1000 row cap, sweeps stale rows, spares consented ones", async () => {
		const doc = (id: string) => ({ client_id: id, redirect_uris: [REDIRECT], client_name: "New" });
		const fetchImpl = (async (url: string) =>
			new Response(JSON.stringify(doc(url)), {
				status: 200,
				headers: { "content-type": "application/json" },
			})) as unknown as typeof fetch;
		const { auth, mcp, userId } = await boot(
			mcpConfig({
				consentPage: "https://auth.example.com/consent",
				clientIdMetadataDocuments: {
					enabled: true,
					resolver: async () => ["93.184.216.34"],
					fetchImpl,
				},
			}),
		);
		const stores = createMcpStores(auth.db);
		for (let i = 0; i < 1005; i++) await stores.storeClient(row(idOf(i)));
		// One row holds a token, one is disabled by an admin: both count as consented.
		await stores.storeToken({
			accessToken: "a".repeat(64),
			refreshToken: null,
			tokenType: "Bearer",
			expiresIn: 3600,
			scope: ["mcp:read"],
			clientId: idOf(0),
			userId,
			resource: null,
			expiresAt: new Date(Date.now() + 3_600_000),
			createdAt: new Date(),
		});
		await stores.setClientDisabled(idOf(1), true, "blocked");
		expect(await stores.countUnconsentedCimdClients()).toBe(1003);
		expect(await stores.listCimdClientIds()).toHaveLength(1005);

		// At the cap and nothing is stale: a new client is refused and nothing is deleted.
		const fresh = "https://brand-new.example.com/c.json";
		const refused = await mcp.describeClient(fresh, REDIRECT);
		expect(refused.success).toBe(false);
		expect(await stores.countUnconsentedCimdClients()).toBe(1003);

		// Everything ages past the retention: the sweep runs and the new client fits.
		await auth.db.update(oauthClients).set({ updatedAt: new Date(0) });
		const accepted = await mcp.describeClient(fresh, REDIRECT);
		expect(accepted.success).toBe(true);
		expect(await stores.findClient(idOf(0))).not.toBeNull();
		expect(await stores.findClient(idOf(1))).not.toBeNull();
		expect(await stores.findClient(idOf(2))).toBeNull();
		expect(await stores.countUnconsentedCimdClients()).toBe(1);
	}, 120_000);
});

describe("no DNS resolver on the runtime", () => {
	const fetchImpl = (async (url: string) =>
		new Response(JSON.stringify({ client_id: url, redirect_uris: [REDIRECT], client_name: "A" }), {
			status: 200,
			headers: { "content-type": "application/json" },
		})) as unknown as typeof fetch;
	const logger = () => ({ debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() });
	const cfg = (extra: Record<string, unknown> = {}) =>
		mcpConfig({
			consentPage: "https://auth.example.com/consent",
			clientIdMetadataDocuments: { enabled: true, fetchImpl, ...extra },
		});

	it("fails closed and warns once through the auth logger without allowedHosts", async () => {
		setNodeDnsForTests(null);
		const log = logger();
		const { mcp } = await boot(cfg(), log);
		const a = await mcp.describeClient("https://a.example.com/c.json", REDIRECT);
		const b = await mcp.describeClient("https://b.example.com/c.json", REDIRECT);
		expect(a.success).toBe(false);
		expect(b.success).toBe(false);
		await new Promise((r) => setTimeout(r, 10));
		const cimdWarnings = log.warn.mock.calls.filter((c) => String(c[0]).includes("[mcp-cimd]"));
		expect(cimdWarnings).toHaveLength(1);
	});

	it("proceeds on name rules with allowedHosts and warns once", async () => {
		setNodeDnsForTests(null);
		const log = logger();
		const { mcp } = await boot(cfg({ allowedHosts: ["a.example.com", "b.example.com"] }), log);
		const a = await mcp.describeClient("https://a.example.com/c.json", REDIRECT);
		const b = await mcp.describeClient("https://b.example.com/c.json", REDIRECT);
		expect(a.success).toBe(true);
		expect(b.success).toBe(true);
		await new Promise((r) => setTimeout(r, 10));
		const cimdWarnings = log.warn.mock.calls.filter((c) => String(c[0]).includes("[mcp-cimd]"));
		expect(cimdWarnings).toHaveLength(1);
	});
});
