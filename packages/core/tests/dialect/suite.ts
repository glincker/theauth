import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../../src/db/database.js";
import { createDatabase } from "../../src/db/database.js";
import { createExecutor } from "../../src/db/migrate/executor.js";
import {
	getSchemaStatus,
	migrationSql,
	runMigrations,
	SchemaChecksumError,
} from "../../src/db/migrate/index.js";
import type { SqlExecutor } from "../../src/db/migrate/types.js";
import { createTheAuth } from "../../src/theauth.js";
import { schemaV120 } from "../helpers-schema-db.js";

type Provider = "postgres" | "mysql";

const ALL_IDS = ["0000", "0001", "0002", "0003"];

interface Handle {
	db: Database;
	exec: SqlExecutor;
	close: () => Promise<void>;
}

async function openHandle(provider: Provider, url: string): Promise<Handle> {
	const db = await createDatabase({ provider, url });
	const exec = createExecutor(db, provider);
	// biome-ignore lint/suspicious/noExplicitAny: reaching the driver pool to close it
	const client = (db as any).$client as { end?: () => Promise<void> } | undefined;
	return { db, exec, close: async () => void (await client?.end?.()) };
}

/** Drops every theauth_ table. Foreign keys make order matter, so retry in passes. */
async function dropAll(exec: SqlExecutor): Promise<void> {
	const list =
		exec.dialect === "postgres"
			? "SELECT table_name AS name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name LIKE 'theauth\\_%'"
			: "SELECT table_name AS name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name LIKE 'theauth\\_%'";
	for (let pass = 0; pass < 12; pass++) {
		const names = (await exec.all(list)).map((r) => String(r.name));
		if (names.length === 0) return;
		for (const name of names) {
			try {
				await exec.run(
					exec.dialect === "postgres"
						? `DROP TABLE IF EXISTS ${name} CASCADE`
						: `DROP TABLE IF EXISTS ${name}`,
				);
			} catch {
				// A table another one still references: the next pass gets it.
			}
		}
	}
	throw new Error("dialect suite: could not drop all theauth_ tables");
}

async function indexNames(exec: SqlExecutor, table: string): Promise<string[]> {
	const sql =
		exec.dialect === "postgres"
			? `SELECT indexname AS name FROM pg_indexes WHERE schemaname = current_schema() AND tablename = '${table}'`
			: `SELECT DISTINCT index_name AS name FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = '${table}'`;
	return (await exec.all(sql)).map((r) => String(r.name));
}

async function columnNames(exec: SqlExecutor, table: string): Promise<string[]> {
	const where =
		exec.dialect === "postgres" ? "table_schema = current_schema()" : "table_schema = DATABASE()";
	const rows = await exec.all(
		`SELECT column_name AS name FROM information_schema.columns WHERE ${where} AND table_name = '${table}'`,
	);
	return rows.map((r) => String(r.name));
}

async function ledgerIds(exec: SqlExecutor): Promise<string[]> {
	return (await exec.all("SELECT id AS id FROM theauth_schema_migrations ORDER BY id")).map((r) =>
		String(r.id),
	);
}

const truthy = (v: unknown): boolean => v === true || v === 1 || v === "1" || v === "t";

/** Literal helpers per dialect. */
function literals(provider: Provider) {
	const pg = provider === "postgres";
	return {
		now: pg ? "NOW()" : "NOW(3)",
		// 2026-10-01 12:34:56.789 UTC on Postgres; the same wall clock text on MySQL (DATETIME has no zone).
		at: pg ? "'2026-10-01 12:34:56.789+00'" : "'2026-10-01 12:34:56.789'",
		yes: pg ? "TRUE" : "1",
		json: (value: unknown) => `'${JSON.stringify(value)}'`,
	};
}

/** Wall clock parts of a Date as the driver reports them (UTC on Postgres, local on MySQL). */
function parts(provider: Provider, d: Date): number[] {
	return provider === "postgres"
		? [d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours(), d.getUTCMilliseconds()]
		: [d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMilliseconds()];
}

export function defineDialectSuite(
	label: string,
	provider: Provider,
	url: string | undefined,
): void {
	describe.skipIf(!url)(`dialect suite: ${label}`, () => {
		let h: Handle;

		beforeEach(async () => {
			h = await openHandle(provider, url as string);
			await dropAll(h.exec);
		});
		afterEach(async () => {
			await h.close();
		});

		describe("schema", () => {
			it("creates every table on an empty database and records the ledger", async () => {
				const result = await runMigrations(h.db, provider);
				expect(result.applied).toEqual(ALL_IDS);
				expect(await ledgerIds(h.exec)).toEqual(ALL_IDS);
				const status = await getSchemaStatus(h.db, provider);
				expect(status.pending).toEqual([]);
				expect(status.mismatched).toEqual([]);
				const audit = await columnNames(h.exec, "theauth_audit_logs");
				expect(audit).toEqual(
					expect.arrayContaining(["decision_code", "recorded_at_ms", "cache_hit"]),
				);
				expect(await columnNames(h.exec, "theauth_permissions")).toContain("relation");
			});

			it("is idempotent on rerun", async () => {
				await runMigrations(h.db, provider);
				const again = await runMigrations(h.db, provider);
				expect(again.applied).toEqual([]);
				expect(await ledgerIds(h.exec)).toEqual(ALL_IDS);
			});

			it("creates the audit indexes, including the decision_code index", async () => {
				await runMigrations(h.db, provider);
				expect(await indexNames(h.exec, "theauth_audit_logs")).toEqual(
					expect.arrayContaining([
						"theauth_audit_logs_chain",
						"theauth_audit_logs_code",
						"theauth_audit_logs_order",
					]),
				);
			});

			it("upgrades a 1.2.0 database: stamps the baseline, runs 0002 and 0003, keeps rows", async () => {
				const l = literals(provider);
				for (const sql of schemaV120(provider)) await h.exec.run(sql);
				await h.exec.run(
					`INSERT INTO theauth_users (id, email, name, created_at, updated_at) VALUES ('u1', 'u1@example.com', 'U1', ${l.at}, ${l.at})`,
				);
				await h.exec.run(
					`INSERT INTO theauth_agents (id, owner_id, name, type, status, token_hash, token_prefix, created_at, updated_at) VALUES ('a1', 'u1', 'a1', 'autonomous', 'active', 'h', 'p', ${l.at}, ${l.at})`,
				);
				await h.exec.run(
					`INSERT INTO theauth_audit_logs (id, agent_id, user_id, action, resource, result, duration_ms, timestamp, chain_seq, hash_version) VALUES ('r1', 'a1', 'u1', 'execute', 'mcp:x:y', 'allowed', 1, ${l.at}, 1, 2)`,
				);

				const before = await getSchemaStatus(h.db, provider);
				expect(before.baselineStamped).toBe(true);
				expect(before.pending.map((p) => p.id)).toEqual(["0002", "0003"]);

				const result = await runMigrations(h.db, provider);
				expect(result.applied).toEqual(ALL_IDS);
				expect(await ledgerIds(h.exec)).toEqual(ALL_IDS);

				const [row] = await h.exec.all(
					"SELECT decision_code AS code, recorded_at_ms AS ms FROM theauth_audit_logs WHERE id = 'r1'",
				);
				expect(row?.code).toBeNull();
				// The backfill keeps the millisecond part. Postgres is UTC, MySQL reads the text in the server zone.
				expect(Number(row?.ms)).toBeGreaterThan(1.7e12);
				if (provider === "postgres") expect(Number(row?.ms)).toBe(1790858096789);
				expect(await indexNames(h.exec, "theauth_audit_logs")).toEqual(
					expect.arrayContaining(["theauth_audit_logs_code", "theauth_audit_logs_order"]),
				);
				expect((await h.exec.all("SELECT email AS email FROM theauth_users"))[0]?.email).toBe(
					"u1@example.com",
				);
			});

			it("hand applied `--from` SQL leaves a consistent ledger", async () => {
				for (const sql of schemaV120(provider)) await h.exec.run(sql);
				// Statement by statement: the MySQL driver does not run multi statement scripts.
				const script = migrationSql(provider, { from: "0002" });
				for (const statement of script
					.split(/;\n/)
					.map((s) => s.replace(/\/\*[\s\S]*?\*\//g, "").trim())
					.filter(Boolean)) {
					await h.exec.run(statement);
				}
				expect(await ledgerIds(h.exec)).toEqual(ALL_IDS);
				const status = await getSchemaStatus(h.db, provider);
				expect(status.pending).toEqual([]);
				expect(status.mismatched).toEqual([]);
			});

			it("rejects a tampered ledger checksum", async () => {
				await runMigrations(h.db, provider);
				await h.exec.run(
					"UPDATE theauth_schema_migrations SET checksum = 'tampered' WHERE id = '0002'",
				);
				await expect(runMigrations(h.db, provider)).rejects.toBeInstanceOf(SchemaChecksumError);
			});
		});

		describe("types round trip (raw SQL, every core table)", () => {
			beforeEach(async () => {
				await runMigrations(h.db, provider);
			});

			it("stores and reads back Date, JSON and boolean columns", async () => {
				const l = literals(provider);
				const run = (sql: string) => h.exec.run(sql);
				await run(
					`INSERT INTO theauth_users (id, email, metadata, banned, ban_expires_at, created_at, updated_at) VALUES ('u1', 'u1@example.com', ${l.json({ plan: "pro", n: [1, 2] })}, ${l.yes}, ${l.at}, ${l.now}, ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_agents (id, owner_id, name, type, token_hash, token_prefix, expires_at, metadata, created_at, updated_at) VALUES ('a1', 'u1', 'a1', 'autonomous', 'h', 'p', ${l.at}, ${l.json({ k: "v" })}, ${l.now}, ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_agents (id, owner_id, name, type, token_hash, token_prefix, created_at, updated_at) VALUES ('a2', 'u1', 'a2', 'autonomous', 'h2', 'p2', ${l.now}, ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_permissions (id, agent_id, resource, actions, constraints, relation, created_at) VALUES ('p1', 'a1', 'mcp:*', ${l.json(["execute", "read"])}, ${l.json({ maxCalls: 3 })}, 'viewer', ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_delegation_chains (id, from_agent_id, to_agent_id, permissions, expires_at, created_at) VALUES ('d1', 'a1', 'a2', ${l.json([{ resource: "mcp:x", actions: ["read"] }])}, ${l.at}, ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_audit_logs (id, agent_id, user_id, action, resource, parameters, result, decision_code, duration_ms, cache_hit, timestamp, recorded_at_ms, delegation_chain) VALUES ('l1', 'a1', 'u1', 'execute', 'mcp:x:y', ${l.json({ q: 1 })}, 'allowed', 'allowed', 5, ${l.yes}, ${l.at}, 1790858096789, ${l.json(["a1", "a2"])})`,
				);
				await run(
					`INSERT INTO theauth_oauth_clients (id, client_id, redirect_uris, grant_types, response_types, disabled, metadata, created_at, updated_at) VALUES ('c1', 'client-1', ${l.json(["https://x.test/cb"])}, ${l.json(["authorization_code"])}, ${l.json(["code"])}, ${l.yes}, ${l.json({ a: true })}, ${l.now}, ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_oauth_access_tokens (id, access_token, refresh_token, client_id, user_id, scopes, access_token_expires_at, refresh_token_expires_at, created_at) VALUES ('t1', 'at-1', 'rt-1', 'client-1', 'u1', 'read', ${l.at}, ${l.at}, ${l.now})`,
				);
				await run(
					`INSERT INTO theauth_oauth_authorization_codes (id, code, client_id, user_id, redirect_uri, scopes, expires_at, created_at) VALUES ('ac1', 'code-1', 'client-1', 'u1', 'https://x.test/cb', 'read', ${l.at}, ${l.now})`,
				);

				const [user] = await h.exec.all(
					"SELECT metadata AS m, banned AS b, ban_expires_at AS e FROM theauth_users",
				);
				expect(asJson(user?.m)).toEqual({ plan: "pro", n: [1, 2] });
				expect(truthy(user?.b)).toBe(true);
				expect(parts(provider, user?.e as Date)).toEqual([2026, 9, 1, 12, 789]);

				const [agent] = await h.exec.all(
					"SELECT metadata AS m, expires_at AS e FROM theauth_agents WHERE id = 'a1'",
				);
				expect(asJson(agent?.m)).toEqual({ k: "v" });
				expect(parts(provider, agent?.e as Date)).toEqual([2026, 9, 1, 12, 789]);

				const [perm] = await h.exec.all(
					"SELECT actions AS a, constraints AS c, relation AS r FROM theauth_permissions",
				);
				expect(asJson(perm?.a)).toEqual(["execute", "read"]);
				expect(asJson(perm?.c)).toEqual({ maxCalls: 3 });
				expect(perm?.r).toBe("viewer");

				const [chain] = await h.exec.all(
					"SELECT permissions AS p, expires_at AS e FROM theauth_delegation_chains",
				);
				expect(asJson(chain?.p)).toEqual([{ resource: "mcp:x", actions: ["read"] }]);
				expect(parts(provider, chain?.e as Date)).toEqual([2026, 9, 1, 12, 789]);

				const [log] = await h.exec.all(
					"SELECT parameters AS p, cache_hit AS c, decision_code AS code, recorded_at_ms AS ms, delegation_chain AS d, timestamp AS t FROM theauth_audit_logs",
				);
				expect(asJson(log?.p)).toEqual({ q: 1 });
				expect(truthy(log?.c)).toBe(true);
				expect(log?.code).toBe("allowed");
				expect(Number(log?.ms)).toBe(1790858096789);
				expect(asJson(log?.d)).toEqual(["a1", "a2"]);
				expect(parts(provider, log?.t as Date)).toEqual([2026, 9, 1, 12, 789]);

				const [client] = await h.exec.all(
					"SELECT redirect_uris AS r, disabled AS d, metadata AS m FROM theauth_oauth_clients",
				);
				expect(asJson(client?.r)).toEqual(["https://x.test/cb"]);
				expect(truthy(client?.d)).toBe(true);
				expect(asJson(client?.m)).toEqual({ a: true });

				const [token] = await h.exec.all(
					"SELECT access_token_expires_at AS a, refresh_token_expires_at AS r FROM theauth_oauth_access_tokens",
				);
				expect(parts(provider, token?.a as Date)).toEqual([2026, 9, 1, 12, 789]);
				expect(parts(provider, token?.r as Date)).toEqual([2026, 9, 1, 12, 789]);
				const [code] = await h.exec.all(
					"SELECT expires_at AS e FROM theauth_oauth_authorization_codes",
				);
				expect(parts(provider, code?.e as Date)).toEqual([2026, 9, 1, 12, 789]);
			});

			it("orders audit rows by recorded_at_ms, not by id or timestamp", async () => {
				const l = literals(provider);
				await h.exec.run(
					`INSERT INTO theauth_users (id, email, created_at, updated_at) VALUES ('u1', 'u1@example.com', ${l.now}, ${l.now})`,
				);
				await h.exec.run(
					`INSERT INTO theauth_agents (id, owner_id, name, type, token_hash, token_prefix, created_at, updated_at) VALUES ('a1', 'u1', 'a1', 'autonomous', 'h', 'p', ${l.now}, ${l.now})`,
				);
				// Same second, ids in the opposite order of the writes.
				for (const [id, ms] of [
					["z", 1],
					["y", 2],
					["x", 3],
					["w", 4],
				] as const) {
					await h.exec.run(
						`INSERT INTO theauth_audit_logs (id, agent_id, user_id, action, resource, result, duration_ms, timestamp, recorded_at_ms) VALUES ('${id}', 'a1', 'u1', 'execute', 'r', 'allowed', 1, ${l.at}, ${1790858096000 + ms})`,
					);
				}
				const rows = await h.exec.all(
					"SELECT id AS id FROM theauth_audit_logs ORDER BY recorded_at_ms ASC",
				);
				expect(rows.map((r) => r.id)).toEqual(["z", "y", "x", "w"]);
			});
		});

		// The core modules query through Drizzle tables declared for SQLite (timestamps as epoch
		// seconds, integer booleans). Postgres and MySQL reject those parameters, so these
		// tests fail today. They stay behind THEAUTH_TEST_DIALECT_CORE=1 until the per dialect
		// Drizzle schema work lands; run them to see the current gap.
		describe.skipIf(process.env.THEAUTH_TEST_DIALECT_CORE !== "1")("core instance", () => {
			async function boot() {
				return createTheAuth({
					database: { provider, url: url as string },
					agents: { enabled: true },
				});
			}

			it("user.create is idempotent, also under concurrency", async () => {
				const auth = await boot();
				const first = await auth.user.create({ email: "Dup@Example.com", name: "Dup" });
				const again = await auth.user.create({ email: "dup@example.com" });
				expect(again.id).toBe(first.id);
				const burst = await Promise.all(
					Array.from({ length: 5 }, () => auth.user.create({ email: "burst@example.com" })),
				);
				expect(new Set(burst.map((u) => u.id)).size).toBe(1);
			});

			it("writes audit rows that read back in write order", async () => {
				const auth = await boot();
				const user = await auth.user.create({ email: "o@example.com" });
				const agent = await auth.agent.create({
					ownerId: user.id,
					name: "w",
					type: "autonomous",
					permissions: [{ resource: "mcp:*", actions: ["execute"] }],
					expiresAt: new Date(Date.now() + 60_000),
				});
				for (let i = 0; i < 8; i++) {
					await auth.authorize(agent.id, { action: "execute", resource: `mcp:x:t${i}` });
				}
				const rows = await auth.audit.query({ agentId: agent.id });
				expect(rows.map((r) => r.resource)).toEqual(
					Array.from({ length: 8 }, (_, i) => `mcp:x:t${i}`),
				);
				expect((await auth.schema.status()).pending).toEqual([]);
			});
		});
	});
}

/** JSON columns come back parsed (pg jsonb, mysql JSON) or as text; normalise. */
function asJson(value: unknown): unknown {
	return typeof value === "string" ? JSON.parse(value) : value;
}
