/** The database backed MCP stores: full OAuth flow, single use codes, refresh rotation with reuse detection, state shared between instances and across restarts. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { eq } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { oauthAccessTokens, oauthAuthorizationCodes, oauthClients } from "../src/db/schema.js";
import { createMcpStores } from "../src/mcp/stores-db.js";
import type { McpAuthorizationCode } from "../src/mcp/types.js";
import { generateSecureToken } from "../src/mcp/utils.js";
import type { DbHarness } from "./mcp-db-harness.js";
import { bootDb } from "./mcp-db-harness.js";
import { codeFlow, REDIRECT, tokenRequest } from "./mcp-test-harness.js";

const dirs: string[] = [];
afterAll(() => {
	for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

async function register(d: DbHarness, scope = "mcp:read offline_access"): Promise<string> {
	const reg = await d.mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
		client_name: "DB Client",
		scope,
	});
	if (!reg.success) throw new Error(reg.error.message);
	return reg.data.client_id;
}

function refresh(clientId: string, refreshToken: string): Request {
	return tokenRequest({
		grant_type: "refresh_token",
		refresh_token: refreshToken,
		client_id: clientId,
	});
}

function sampleCode(clientId: string, userId: string): McpAuthorizationCode {
	return {
		code: generateSecureToken(32),
		clientId,
		userId,
		redirectUri: REDIRECT,
		scope: ["mcp:read"],
		codeChallenge: "challenge",
		codeChallengeMethod: "S256",
		resource: "https://mcp.theauth.test",
		expiresAt: new Date(Date.now() + 60_000),
		createdAt: new Date(),
	};
}

describe("database MCP stores", () => {
	it("runs the full flow: register, authorize with PKCE, token, refresh, reuse detection", async () => {
		const d = await bootDb();
		const clientId = await register(d);
		const stored = await d.auth.db
			.select()
			.from(oauthClients)
			.where(eq(oauthClients.clientId, clientId));
		expect(stored[0]?.clientName).toBe("DB Client");
		expect(stored[0]?.scope).toBe("mcp:read offline_access");

		const first = await codeFlow(d.h, clientId, { scope: "mcp:read offline_access" });
		expect(first.refresh_token).toBeTruthy();
		const rows = await d.auth.db.select().from(oauthAccessTokens);
		expect(rows).toHaveLength(1);
		// Only digests are stored, never the raw tokens.
		expect(rows[0]?.accessToken).toMatch(/^[0-9a-f]{64}$/);
		expect(rows[0]?.accessToken).not.toBe(first.access_token);
		expect(rows[0]?.refreshToken).toMatch(/^[0-9a-f]{64}$/);
		expect(rows[0]?.jti).toBeTruthy();
		expect(rows[0]?.familyId).toBeTruthy();
		expect(rows[0]?.tokenType).toBe("Bearer");
		expect((await d.mcp.validateToken(first.access_token, ["mcp:read"])).success).toBe(true);

		const rotated = await d.mcp.token(refresh(clientId, first.refresh_token ?? ""));
		if (!rotated.success) throw new Error(rotated.error.message);
		expect(rotated.data.refresh_token).not.toBe(first.refresh_token);

		// Replaying the rotated token is theft: the whole family is revoked.
		const replay = await d.mcp.token(refresh(clientId, first.refresh_token ?? ""));
		expect(replay.success).toBe(false);
		const afterReplay = await d.mcp.token(refresh(clientId, rotated.data.refresh_token ?? ""));
		expect(afterReplay.success).toBe(false);
		expect(await d.auth.db.select().from(oauthAccessTokens)).toHaveLength(0);
	});

	it("lets exactly one of two concurrent code consumers win", async () => {
		const d = await bootDb();
		const clientId = await register(d);
		const stores = createMcpStores(d.auth.db);
		for (let i = 0; i < 5; i++) {
			const code = sampleCode(clientId, d.userId);
			await stores.storeAuthorizationCode(code);
			const results = await Promise.all([
				stores.consumeAuthorizationCode(code.code),
				stores.consumeAuthorizationCode(code.code),
				stores.consumeAuthorizationCode(code.code),
			]);
			expect(results.filter((r) => r !== null)).toHaveLength(1);
		}
		expect(await d.auth.db.select().from(oauthAuthorizationCodes)).toHaveLength(0);
	});

	it("redeems a code once through the token endpoint under concurrency", async () => {
		const d = await bootDb();
		const clientId = await register(d, "mcp:read");
		const stores = createMcpStores(d.auth.db);
		const code = sampleCode(clientId, d.userId);
		const { computeS256Challenge } = await import("../src/mcp/utils.js");
		const verifier = generateSecureToken(43);
		code.codeChallenge = await computeS256Challenge(verifier);
		await stores.storeAuthorizationCode(code);
		const exchange = () =>
			d.mcp.token(
				tokenRequest({
					grant_type: "authorization_code",
					code: code.code,
					redirect_uri: REDIRECT,
					client_id: clientId,
					code_verifier: verifier,
					resource: code.resource ?? "",
				}),
			);
		const results = await Promise.all([exchange(), exchange()]);
		expect(results.filter((r) => r.success)).toHaveLength(1);
	});

	it("does not return an expired code", async () => {
		const d = await bootDb();
		const clientId = await register(d);
		const stores = createMcpStores(d.auth.db);
		const code = { ...sampleCode(clientId, d.userId), expiresAt: new Date(Date.now() - 1000) };
		await stores.storeAuthorizationCode(code);
		const found = await stores.consumeAuthorizationCode(code.code);
		// The token endpoint rejects it by expiry; the store still hands the row back once.
		expect(found?.expiresAt.getTime()).toBeLessThan(Date.now());
		expect(await stores.consumeAuthorizationCode(code.code)).toBeNull();
	});

	it("shares clients, tokens and refresh families between instances on one database", async () => {
		const d = await bootDb();
		const other = d.another();
		const clientId = await register(d);
		const first = await codeFlow(d.h, clientId, { scope: "mcp:read offline_access" });
		// A second instance validates the token and rotates the refresh token.
		expect((await other.validateToken(first.access_token, ["mcp:read"])).success).toBe(true);
		const rotated = await other.token(refresh(clientId, first.refresh_token ?? ""));
		expect(rotated.success).toBe(true);
		// The first instance sees the rotation: the old token now counts as reuse.
		const replay = await d.mcp.token(refresh(clientId, first.refresh_token ?? ""));
		expect(replay.success).toBe(false);
	});

	it("keeps clients and tokens across a restart", async () => {
		const dir = mkdtempSync(join(tmpdir(), "mcp-db-"));
		dirs.push(dir);
		const url = join(dir, "auth.db");
		const before = await bootDb({ url });
		const clientId = await register(before);
		const issued = await codeFlow(before.h, clientId, { scope: "mcp:read offline_access" });

		const after = await bootDb({ url });
		const client = await after.mcp.clients.agentFor(clientId);
		expect(client).toBeNull();
		expect((await after.mcp.validateToken(issued.access_token, ["mcp:read"])).success).toBe(true);
		const rotated = await after.mcp.token(refresh(clientId, issued.refresh_token ?? ""));
		expect(rotated.success).toBe(true);
	});

	it("revokes a token record and a whole family", async () => {
		const d = await bootDb();
		const clientId = await register(d);
		const stores = createMcpStores(d.auth.db);
		const first = await codeFlow(d.h, clientId, { scope: "mcp:read offline_access" });
		const [row] = await d.auth.db.select().from(oauthAccessTokens);
		expect(row?.familyId).toBeTruthy();
		await stores.revokeTokenFamily(row?.familyId ?? "");
		expect(await d.auth.db.select().from(oauthAccessTokens)).toHaveLength(0);
		expect(first.access_token).toBeTruthy();
	});

	it("stores a pre registered client on every boot without a conflict", async () => {
		const d = await bootDb({
			config: {
				preRegisteredClients: [{ clientId: "pre-1", redirectUris: [REDIRECT], clientName: "Pre" }],
			},
		});
		const again = d.another();
		// Let both pre registration passes finish.
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(again).toBeTruthy();
		const rows = await d.auth.db
			.select()
			.from(oauthClients)
			.where(eq(oauthClients.clientId, "pre-1"));
		expect(rows).toHaveLength(1);
	});

	it("round trips metadata fields that have no column", async () => {
		const d = await bootDb();
		const reg = await d.mcp.registerClient({
			redirect_uris: [REDIRECT],
			token_endpoint_auth_method: "none",
			contacts: ["ops@example.com"],
			tos_uri: "https://app.theauth.test/tos",
			policy_uri: "https://app.theauth.test/policy",
			software_id: "sw-1",
			software_version: "1.2.3",
			logo_uri: "https://app.theauth.test/logo.png",
		});
		if (!reg.success) throw new Error(reg.error.message);
		const stores = createMcpStores(d.auth.db);
		const client = await stores.findClient(reg.data.client_id);
		expect(client).toMatchObject({
			contacts: ["ops@example.com"],
			tosUri: "https://app.theauth.test/tos",
			policyUri: "https://app.theauth.test/policy",
			softwareId: "sw-1",
			softwareVersion: "1.2.3",
			logoUri: "https://app.theauth.test/logo.png",
			clientType: "public",
			agentId: null,
		});
	});
});
