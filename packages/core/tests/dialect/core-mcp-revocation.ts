import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../../src/db/database.js";
import { runMigrations } from "../../src/db/migrate/index.js";
import type { SqlExecutor } from "../../src/db/migrate/types.js";
import { createMcpModule } from "../../src/mcp/server.js";
import { createDbRevocationStore } from "../../src/mcp/stores-db-revocation.js";
import type { McpAuthModule } from "../../src/mcp/types.js";
import { mcpConfig } from "../mcp-db-harness.js";
import { basicAuth, codeFlow, REDIRECT, RESOURCE, tokenRequest } from "../mcp-test-harness.js";
import type { CoreBooter } from "./core-boot.js";

interface Handle {
	db: Database;
	exec: SqlExecutor;
}

const IN_AN_HOUR = new Date(Date.now() + 3_600_000);

async function indexNames(exec: SqlExecutor, table: string): Promise<string[]> {
	const sql =
		exec.dialect === "postgres"
			? `SELECT indexname AS name FROM pg_indexes WHERE schemaname = current_schema() AND tablename = '${table}'`
			: `SELECT DISTINCT index_name AS name FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = '${table}'`;
	return (await exec.all(sql)).map((r) => String(r.name));
}

/** Migration 0007 and the DB backed revocation store on a real Postgres or MySQL. */
export function defineMcpRevocationTests(getHandle: () => Handle): void {
	describe("MCP revocation (migration 0007)", () => {
		beforeEach(async () => {
			const h = getHandle();
			await runMigrations(h.db, h.exec.dialect);
		});

		it("creates the table and every index", async () => {
			const { exec } = getHandle();
			expect(await indexNames(exec, "theauth_mcp_revocations")).toEqual(
				expect.arrayContaining(["theauth_mcp_revocations_exp", "theauth_mcp_revocations_ms"]),
			);
			expect(await indexNames(exec, "theauth_delegation_chains")).toEqual(
				expect.arrayContaining(["theauth_delegation_chains_to", "theauth_delegation_chains_from"]),
			);
		});

		it("revokeMany twice on the same key upserts without aborting", async () => {
			const { db, exec } = getHandle();
			const store = createDbRevocationStore(db);
			const entries = [
				{ kind: "dlg" as const, id: "d1", expiresAt: IN_AN_HOUR, reason: "delegation.revoke" },
				{ kind: "sub" as const, id: "u1", expiresAt: IN_AN_HOUR, reason: "session.revokeAll" },
			];
			await store.revokeMany(entries, new Date(1_700_000_100_000));
			await store.revokeMany(entries, new Date(1_700_000_200_000));
			await store.revokeMany(entries, new Date(1_700_000_150_000));
			const rows = await exec.all(
				"SELECT kind AS k, revoked_at_ms AS ms FROM theauth_mcp_revocations ORDER BY kind",
			);
			expect(rows).toHaveLength(2);
			for (const row of rows) expect(Number(row.ms)).toBe(1_700_000_200_000);
			expect(await store.isRevoked("nope")).toBe(false);
		});

		it("applies the watermark rule on BIGINT values that arrive as strings", async () => {
			const { db } = getHandle();
			const store = createDbRevocationStore(db);
			await store.revokeMany(
				[{ kind: "client", id: "c1", expiresAt: IN_AN_HOUR, reason: "client.disable" }],
				new Date(1_700_000_100_000),
			);
			const base = { jti: "j", sub: "u", clientId: "c1", dlg: [], agents: [] };
			expect(await store.check({ ...base, iat: 1_700_000_099 })).toEqual({
				kind: "client",
				id: "c1",
			});
			expect(await store.check({ ...base, iat: 1_700_000_100 })).toEqual({
				kind: "client",
				id: "c1",
			});
			expect(await store.check({ ...base, iat: 1_700_000_101 })).toBeNull();
		});

		it("fingerprint changes on insert and prune removes expired rows", async () => {
			const { db } = getHandle();
			const store = createDbRevocationStore(db);
			const before = await store.fingerprint();
			await store.revoke("j1", new Date(Date.now() - 5_000));
			const after = await store.fingerprint();
			expect(after).not.toBe(before);
			expect(await store.isRevoked("j1")).toBe(true);
			expect(await store.prune(new Date())).toBe(1);
			expect(await store.isRevoked("j1")).toBe(false);
		});
	});
}

const TE = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT = "urn:ietf:params:oauth:token-type:access_token";
const PERMS = [{ resource: "mcp:tools:*", actions: ["read"] }];

/** The live revoke scenario end to end on the dialect: two modules, one database, an exchanged delegated token. */
export function defineMcpRevocationE2eTests(booter: CoreBooter): void {
	describe("MCP revocation end to end", () => {
		it("a delegation revoke kills the exchanged token on both instances at the next call", async () => {
			const { auth } = await booter.boot();
			const user = await auth.user.create({ email: "mcp-revoke-e2e@example.com" });
			const mk = (name: string) =>
				auth.agent.create({ ownerId: user.id, name, type: "autonomous", permissions: PERMS });
			const a = (await mk("a")).id;
			const b = (await mk("b")).id;
			const link = (
				await auth.delegate({
					fromAgent: a,
					toAgent: b,
					permissions: PERMS,
					expiresAt: new Date(Date.now() + 3_600_000),
				})
			).id;
			const client = (id: string, agentId: string) => ({
				clientId: id,
				clientSecret: `${id}-secret`,
				redirectUris: [REDIRECT],
				scope: "mcp:read mcp:write",
				grantTypes: ["authorization_code", "refresh_token", TE],
				agentId,
			});
			const build = (): McpAuthModule =>
				createMcpModule({
					auth,
					config: mcpConfig({
						tokenExchange: { enabled: true },
						preRegisteredClients: [client("app", a), client("xb", b)],
					}),
					resolveUserId: async () => user.id,
				});
			const one = build();
			const two = build();
			await new Promise((r) => setTimeout(r, 100));

			const subject = await codeFlow(
				{ mcp: one, clients: new Map(), codes: new Map(), tokens: new Map() },
				"app",
				{ secret: "app-secret" },
			);
			const exchanged = await one.token(
				tokenRequest(
					{
						grant_type: TE,
						subject_token: subject.access_token,
						subject_token_type: AT,
						client_id: "xb",
					},
					basicAuth("xb", "xb-secret"),
				),
			);
			if (!exchanged.success) throw new Error(exchanged.error.message);
			const token = exchanged.data.access_token;
			const call = async (mcp: McpAuthModule): Promise<number> =>
				(
					await mcp.requireMcpAuth(async () => new Response("ok"))(
						new Request(`${RESOURCE}/tools`, { headers: { Authorization: `Bearer ${token}` } }),
					)
				).status;

			expect(await call(one)).toBe(200);
			expect(await call(two)).toBe(200);
			await auth.delegation.revoke(link);
			expect(await call(one)).toBe(401);
			expect(await call(two)).toBe(401);
		});
	});
}
