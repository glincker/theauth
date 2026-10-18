/** A client an admin bound to an agent can only be authorized by that agent's owner (decision code owner_mismatch). */
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { oauthAuthorizationCodes } from "../src/db/schema.js";
import { createMcpModule } from "../src/mcp/server.js";
import type { McpAuthModule } from "../src/mcp/types.js";
import { computeS256Challenge, generateSecureToken } from "../src/mcp/utils.js";
import { bootDb, mcpConfig } from "./mcp-db-harness.js";
import { BASE_URL, basicAuth, REDIRECT, RESOURCE, tokenRequest } from "./mcp-test-harness.js";

const SECRET = "client-secret";
const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];

async function world() {
	const d = await bootDb();
	const other = await d.auth.user.create({ email: "other@example.com" });
	const agent = await d.auth.agent.create({
		ownerId: d.userId,
		name: "bound",
		type: "autonomous",
		permissions: PERMS,
	});
	const config = {
		preRegisteredClients: [
			{
				clientId: "bound-client",
				clientSecret: SECRET,
				redirectUris: [REDIRECT],
				scope: "mcp:read",
				grantTypes: ["authorization_code"],
				agentId: agent.id,
			},
		],
	};
	const as = (userId: string): McpAuthModule =>
		createMcpModule({ auth: d.auth, config: mcpConfig(config), resolveUserId: async () => userId });
	await new Promise((r) => setTimeout(r, 30));
	return { d, otherId: other.id, as };
}

async function authorize(mcp: McpAuthModule) {
	const verifier = generateSecureToken(43);
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	const params = {
		response_type: "code",
		client_id: "bound-client",
		redirect_uri: REDIRECT,
		scope: "mcp:read",
		code_challenge: await computeS256Challenge(verifier),
		code_challenge_method: "S256",
		resource: RESOURCE,
	};
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
	return { verifier, result: await mcp.authorize(new Request(url)) };
}

function redeem(mcp: McpAuthModule, code: string, verifier: string) {
	return mcp.token(
		tokenRequest(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				client_id: "bound-client",
				code_verifier: verifier,
				resource: RESOURCE,
			},
			basicAuth("bound-client", SECRET),
		),
	);
}

describe("authorization code grant and a client bound to another user's agent", () => {
	it("lets the agent's owner authorize and redeem", async () => {
		const w = await world();
		const mcp = w.as(w.d.userId);
		const { result, verifier } = await authorize(mcp);
		expect(result.success).toBe(true);
		if (!result.success) return;
		const code = new URL(result.data.redirectUri).searchParams.get("code") ?? "";
		expect((await redeem(mcp, code, verifier)).success).toBe(true);
	});

	it("refuses another user at the authorization endpoint and issues no code", async () => {
		const w = await world();
		const { result } = await authorize(w.as(w.otherId));
		expect(result.success).toBe(false);
		if (result.success) return;
		expect(result.error.code).toBe("ACCESS_DENIED");
		expect(result.error.details?.decisionCode).toBe("owner_mismatch");
		expect(await w.d.auth.db.select().from(oauthAuthorizationCodes)).toHaveLength(0);
	});

	it("refuses at the token endpoint when a code names a user who does not own the agent", async () => {
		const w = await world();
		const mcp = w.as(w.d.userId);
		const { result, verifier } = await authorize(mcp);
		if (!result.success) throw new Error(result.error.message);
		const code = new URL(result.data.redirectUri).searchParams.get("code") ?? "";
		await w.d.auth.db
			.update(oauthAuthorizationCodes)
			.set({ userId: w.otherId })
			.where(eq(oauthAuthorizationCodes.code, code));
		const redeemed = await redeem(mcp, code, verifier);
		expect(redeemed.success).toBe(false);
		if (redeemed.success) return;
		expect(redeemed.error.code).toBe("INVALID_GRANT");
		expect(redeemed.error.details?.decisionCode).toBe("owner_mismatch");
	});
});
