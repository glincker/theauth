/** First class binding of an OAuth client to an agent: the token carries agent_id, the delegation check resolves the client without a hand written mapper, and the binding goes away with the agent. */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { agents, oauthClients } from "../src/db/schema.js";
import { createDbDelegationStore } from "../src/mcp/delegation-check.js";
import { createInMemoryJtiDenylist } from "../src/mcp/memory-stores.js";
import { createMcpModule } from "../src/mcp/server.js";
import { bootDb, finishBoot, mcpConfig } from "./mcp-db-harness.js";
import {
	basicAuth,
	codeFlow,
	decodePayload,
	REDIRECT,
	RESOURCE,
	tokenRequest,
} from "./mcp-test-harness.js";

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";

async function newAgent(
	d: Awaited<ReturnType<typeof bootDb>>,
	name: string,
	permissions: Array<{ resource: string; actions: string[] }> = [],
) {
	return d.auth.agent.create({ ownerId: d.userId, name, type: "autonomous", permissions });
}

async function registerPublic(d: Awaited<ReturnType<typeof bootDb>>): Promise<string> {
	const reg = await d.mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
		scope: "mcp:read mcp:write",
	});
	if (!reg.success) throw new Error(reg.error.message);
	return reg.data.client_id;
}

describe("client to agent binding", () => {
	it("stamps agent_id on tokens issued to a bound client, and on none else", async () => {
		const d = await bootDb();
		const agent = await newAgent(d, "bot");
		const bound = await registerPublic(d);
		const unbound = await registerPublic(d);
		await d.mcp.clients.bindAgent(bound, agent.id);

		const token = await codeFlow(d.h, bound);
		expect(decodePayload(token.access_token).agent_id).toBe(agent.id);
		const session = await d.mcp.validateToken(token.access_token, ["mcp:read"]);
		expect(session.success && session.data.agent?.id).toBe(agent.id);

		const other = await codeFlow(d.h, unbound);
		expect(decodePayload(other.access_token).agent_id).toBeUndefined();
	});

	it("binds, reads, replaces and clears the binding", async () => {
		const d = await bootDb();
		const one = await newAgent(d, "one");
		const two = await newAgent(d, "two");
		const clientId = await registerPublic(d);
		expect(await d.mcp.clients.agentFor(clientId)).toBeNull();
		await d.mcp.clients.bindAgent(clientId, one.id);
		expect(await d.mcp.clients.agentFor(clientId)).toBe(one.id);
		await d.mcp.clients.bindAgent(clientId, two.id);
		expect(await d.mcp.clients.agentFor(clientId)).toBe(two.id);
		await d.mcp.clients.unbindAgent(clientId);
		expect(await d.mcp.clients.agentFor(clientId)).toBeNull();
		expect(await d.mcp.clients.agentFor("no-such-client")).toBeNull();
	});

	it("refuses an unknown agent or client", async () => {
		const d = await bootDb();
		const clientId = await registerPublic(d);
		await expect(d.mcp.clients.bindAgent(clientId, "ta_missing")).rejects.toThrow(/does not exist/);
		const agent = await newAgent(d, "bot");
		await expect(d.mcp.clients.bindAgent("no-such-client", agent.id)).rejects.toThrow(
			/Unknown client/,
		);
	});

	it("clears the binding when the agent row is deleted", async () => {
		const d = await bootDb();
		const agent = await newAgent(d, "short-lived");
		const clientId = await registerPublic(d);
		await d.mcp.clients.bindAgent(clientId, agent.id);
		await d.auth.db.delete(agents).where(eq(agents.id, agent.id));
		expect(await d.mcp.clients.agentFor(clientId)).toBeNull();
		const [row] = await d.auth.db
			.select()
			.from(oauthClients)
			.where(eq(oauthClients.clientId, clientId));
		expect(row?.agentId).toBeNull();
	});

	it("binds at registration through registration.agentForClient, never from the request body", async () => {
		const d = await bootDb();
		const agent = await newAgent(d, "registered");
		const intruder = await newAgent(d, "intruder");
		const mcp = createMcpModule({
			auth: d.auth,
			config: mcpConfig({
				registration: {
					agentForClient: async (client, request) =>
						request.headers.get("x-agent") === "yes" && client.clientName === "agent app"
							? agent.id
							: undefined,
				},
			}),
			resolveUserId: async () => d.userId,
		});
		const body = {
			redirect_uris: [REDIRECT],
			token_endpoint_auth_method: "none",
			client_name: "agent app",
			// Not part of RFC 7591 and ignored: a client can never choose its own agent.
			agent_id: intruder.id,
		};
		const request = new Request("https://auth.theauth.test/api/auth/mcp/register", {
			method: "POST",
			headers: { "x-agent": "yes" },
		});
		const reg = await mcp.registerClient(body, request);
		if (!reg.success) throw new Error(reg.error.message);
		expect(await mcp.clients.agentFor(reg.data.client_id)).toBe(agent.id);

		const plain = await mcp.registerClient({ ...body, client_name: "other" });
		if (!plain.success) throw new Error(plain.error.message);
		expect(await mcp.clients.agentFor(plain.data.client_id)).toBeNull();
	});

	it("binds pre registered clients and keeps the binding across boots", async () => {
		const d = await bootDb();
		const agent = await newAgent(d, "pre");
		const config = {
			preRegisteredClients: [
				{ clientId: "pre-bound", redirectUris: [REDIRECT], agentId: agent.id },
				{ clientId: "pre-plain", redirectUris: [REDIRECT] },
			],
		};
		const first = finishBoot(d.auth, d.userId, config);
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(await first.mcp.clients.agentFor("pre-bound")).toBe(agent.id);
		// A binding made at runtime survives the next boot storing "pre-plain" again.
		await first.mcp.clients.bindAgent("pre-plain", agent.id);
		const second = finishBoot(d.auth, d.userId, config);
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(await second.mcp.clients.agentFor("pre-plain")).toBe(agent.id);
	});

	it("rejects binding when the store cannot", async () => {
		const mcp = createMcpModule({
			config: mcpConfig(),
			storeClient: async () => {},
			findClient: async () => null,
			storeAuthorizationCode: async () => {},
			consumeAuthorizationCode: async () => null,
			storeToken: async () => {},
			findTokenByRefreshToken: async () => null,
			revokeToken: async () => {},
			resolveUserId: async () => null,
		});
		await expect(mcp.clients.bindAgent("c", "a")).rejects.toThrow(/cannot bind/);
	});
});

describe("delegation check with the built-in client mapping", () => {
	async function setup() {
		const d = await bootDb();
		const assistant = await newAgent(d, "assistant", [
			{ resource: "mcp:reports:*", actions: ["read"] },
		]);
		const bot = await newAgent(d, "bot");
		const chain = await d.auth.delegate({
			fromAgent: assistant.id,
			toAgent: bot.id,
			permissions: [{ resource: "mcp:reports:*", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 3_600_000),
			maxDepth: 1,
		});
		return { d, assistant, bot, chain };
	}

	async function mint(
		d: Awaited<ReturnType<typeof bootDb>>,
		botId: string,
		config: Parameters<typeof mcpConfig>[0],
	) {
		const mcp = createMcpModule({
			auth: d.auth,
			config: mcpConfig({
				tokenExchange: { enabled: true },
				jtiDenylist: createInMemoryJtiDenylist(),
				delegationStore: createDbDelegationStore(d.auth.db),
				...config,
			}),
			resolveUserId: async () => d.userId,
		});
		const reg = await mcp.registerClient({
			redirect_uris: [REDIRECT],
			grant_types: ["authorization_code", TE],
			token_endpoint_auth_method: "client_secret_basic",
			scope: "mcp:read",
		});
		if (!reg.success || !reg.data.client_secret) throw new Error("registration failed");
		const { client_id: clientId, client_secret: secret } = reg.data;
		await mcp.clients.bindAgent(clientId, botId);
		const granted = await codeFlow({ ...d.h, mcp }, clientId, { scope: "mcp:read", secret });
		const exchanged = await mcp.token(
			tokenRequest(
				{
					grant_type: TE,
					subject_token: granted.access_token,
					subject_token_type: AT,
					scope: "mcp:read",
					resource: RESOURCE,
				},
				basicAuth(clientId, secret),
			),
		);
		if (!exchanged.success) throw new Error(exchanged.error.message);
		return { mcp, token: exchanged.data.access_token };
	}

	it("resolves the client to its bound agent, so only the user arm needs mapping", async () => {
		const { d, assistant, bot, chain } = await setup();
		const { mcp, token } = await mint(d, bot.id, {
			// Token subjects are users, not agents: map the owner to the root agent. Clients need no mapper.
			resolveActorAgentId: ({ sub }) => (sub === d.userId ? assistant.id : undefined),
		});
		expect((await mcp.validateToken(token, ["mcp:read"])).success).toBe(true);

		await d.auth.delegation.revoke(chain.id, { revokedBy: d.userId });
		const after = await mcp.validateToken(token, ["mcp:read"]);
		expect(after.success).toBe(false);
		if (!after.success) expect(after.error.message).toMatch(/revoked/);
	});

	it("fails closed when the client is not bound", async () => {
		const { d, assistant, bot } = await setup();
		const { mcp, token } = await mint(d, bot.id, {
			resolveActorAgentId: ({ sub }) => (sub === d.userId ? assistant.id : undefined),
		});
		const [client] = await d.auth.db.select().from(oauthClients);
		await d.mcp.clients.unbindAgent(client?.clientId ?? "");
		const res = await mcp.validateToken(token, ["mcp:read"]);
		expect(res.success).toBe(false);
		if (!res.success) expect(res.error.message).toMatch(/missing/);
	});
});
