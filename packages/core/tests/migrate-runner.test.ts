import { describe, expect, it } from "vitest";
import { sha256 } from "../src/crypto/web-crypto.js";
import { sha256Hex } from "../src/db/migrate/checksum.js";
import { isAlreadyExistsError } from "../src/db/migrate/executor.js";
import {
	getSchemaStatus,
	MIGRATIONS,
	migrationChecksum,
	migrationSql,
	runMigrations,
	SchemaChecksumError,
	SchemaOutdatedError,
} from "../src/db/migrate/index.js";
import { createTables, ensureSchema } from "../src/db/migrations.js";
import { createTheAuthWith } from "../src/theauth-core.js";
import { columnsOf, indexNames, ledgerIds, memoryDb, memoryDbV120 } from "./helpers-schema-db.js";

const ALL_IDS = MIGRATIONS.map((m) => m.id);
/** Migrations a config without the oauth feature applies (0006, 0007, 0008 and 0011 need oauth, 0012 needs the OIDC provider). */
const CORE_IDS = ALL_IDS.filter(
	(id) => id !== "0006" && id !== "0007" && id !== "0008" && id !== "0011" && id !== "0012",
);

describe("migration ledger: fresh SQLite database", () => {
	it("creates every table, records every migration and reports nothing pending", async () => {
		const { db, exec } = await memoryDb();
		const result = await runMigrations(db, "sqlite");
		expect(result.applied).toEqual(ALL_IDS);
		expect(result.baselineStamped).toBe(false);
		expect(await ledgerIds(exec)).toEqual(ALL_IDS);

		const status = await getSchemaStatus(db, "sqlite");
		expect(status.pending).toEqual([]);
		expect(status.applied.map((a) => a.id)).toEqual(ALL_IDS);
		expect(status.applied.map((a) => a.name)).toEqual(MIGRATIONS.map((m) => m.name));
		expect(status.applied[0]?.appliedAt.getFullYear()).toBeGreaterThanOrEqual(2026);
		expect(status.mismatched).toEqual([]);
		expect(status.unknown).toEqual([]);

		const audit = await columnsOf(exec, "theauth_audit_logs");
		expect(audit).toContain("decision_code");
		expect(audit).toContain("recorded_at_ms");
		expect(await indexNames(exec, "theauth_audit_logs")).toEqual(
			expect.arrayContaining([
				"theauth_audit_logs_chain",
				"theauth_audit_logs_code",
				"theauth_audit_logs_order",
			]),
		);
	});

	it("stores the checksum of each migration", async () => {
		const { db, exec } = await memoryDb();
		await createTables(db, "sqlite");
		const rows = await exec.all(
			"SELECT id AS id, checksum AS checksum FROM theauth_schema_migrations",
		);
		for (const row of rows) {
			const migration = MIGRATIONS.find((m) => m.id === row.id);
			expect(row.checksum).toBe(migrationChecksum(migration as never, "sqlite"));
		}
	});

	it("is idempotent: a rerun applies nothing and keeps the ledger rows", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		const before = await exec.all(
			"SELECT id AS id, applied_at AS at FROM theauth_schema_migrations ORDER BY id",
		);
		const again = await runMigrations(db, "sqlite");
		expect(again.applied).toEqual([]);
		await createTables(db, "sqlite");
		const after = await exec.all(
			"SELECT id AS id, applied_at AS at FROM theauth_schema_migrations ORDER BY id",
		);
		expect(after).toEqual(before);
	});

	it("dry run reports the work and touches nothing", async () => {
		const { db, exec } = await memoryDb();
		const result = await runMigrations(db, "sqlite", { dryRun: true });
		expect(result.applied).toEqual(ALL_IDS);
		expect(result.sql.length).toBeGreaterThan(50);
		expect(await exec.all("SELECT name AS name FROM sqlite_master WHERE type = 'table'")).toEqual(
			[],
		);
	});

	it("`to` stops after the given migration and rejects unknown ids", async () => {
		const { db, exec } = await memoryDb();
		const result = await runMigrations(db, "sqlite", { to: "0001" });
		expect(result.applied).toEqual(["0000", "0001"]);
		expect(await ledgerIds(exec)).toEqual(["0000", "0001"]);
		expect((await getSchemaStatus(db, "sqlite")).pending.map((p) => p.id)).toEqual(
			ALL_IDS.slice(2),
		);
		await expect(runMigrations(db, "sqlite", { to: "9999" })).rejects.toThrow(
			/unknown migration id/,
		);
	});
});

describe("migration ledger: upgrade from a 1.2.0 database", () => {
	it("stamps the baseline, runs 0001 to the latest and keeps the data", async () => {
		const { db, exec } = await memoryDbV120({ withData: true });
		expect(await columnsOf(exec, "theauth_audit_logs")).not.toContain("decision_code");
		expect(await columnsOf(exec, "theauth_audit_logs")).not.toContain("recorded_at_ms");

		const before = await getSchemaStatus(db, "sqlite");
		expect(before.baselineStamped).toBe(true);
		expect(before.applied).toEqual([]);
		expect(before.pending.map((p) => p.id)).toEqual(ALL_IDS.slice(2));

		const result = await runMigrations(db, "sqlite");
		expect(result.applied).toEqual(ALL_IDS);
		expect(result.baselineStamped).toBe(true);
		expect(await ledgerIds(exec)).toEqual(ALL_IDS);

		const rows = await exec.all(
			"SELECT id AS id, decision_code AS code, recorded_at_ms AS ms, chain_seq AS seq FROM theauth_audit_logs ORDER BY id",
		);
		expect(rows).toEqual([
			{ id: "r1", code: null, ms: 1700000100000, seq: 1 },
			{ id: "r2", code: null, ms: 1700000200000, seq: 2 },
		]);
		const users = await exec.all("SELECT email AS email FROM theauth_users");
		expect(users).toEqual([{ email: "u1@example.com" }]);

		const after = await getSchemaStatus(db, "sqlite");
		expect(after.pending).toEqual([]);
		expect(after.baselineStamped).toBe(false);
	});

	it("adds the audit chain and consumed_at columns to a database older than 1.2.0", async () => {
		const { db, exec } = await memoryDb();
		const chain =
			/^\s*(chain_seq|prev_hash|hash|hash_version|subject_id|actor_id|policy_version|approver_id|delegation_chain|input_provenance|id_pseudonyms)\b/;
		const { schemaV120 } = await import("./helpers-schema-db.js");
		for (let sql of schemaV120("sqlite")) {
			if (sql.includes("theauth_audit_logs_chain")) continue;
			if (sql.startsWith("CREATE TABLE IF NOT EXISTS theauth_audit_logs")) {
				sql = sql
					.split("\n")
					.filter((line) => !chain.test(line))
					.join("\n")
					.replace(/,\s*\n\)$/, "\n)");
			}
			if (sql.startsWith("CREATE TABLE IF NOT EXISTS theauth_approval_requests")) {
				sql = sql.replace(/^\s*consumed_at.*\n/m, "").replace(/,\s*\n\)$/, "\n)");
			}
			await exec.run(sql);
		}
		expect(await columnsOf(exec, "theauth_audit_logs")).not.toContain("chain_seq");
		expect((await getSchemaStatus(db, "sqlite")).baselineStamped).toBe(false);

		await runMigrations(db, "sqlite");
		expect(await columnsOf(exec, "theauth_audit_logs")).toEqual(
			expect.arrayContaining([
				"chain_seq",
				"hash",
				"id_pseudonyms",
				"decision_code",
				"recorded_at_ms",
			]),
		);
		expect(await columnsOf(exec, "theauth_approval_requests")).toContain("consumed_at");
		expect(await ledgerIds(exec)).toEqual(ALL_IDS);
	});

	it("keeps user.create and audit ordering working after the upgrade", async () => {
		const { db } = await memoryDbV120({ withData: true });
		const auth = await createTheAuthWith(
			{ database: { provider: "sqlite", url: ":memory:" }, agents: { enabled: true } },
			async () => db,
		);
		expect((await auth.schema.status()).pending).toEqual([]);

		const first = await auth.user.create({ email: "New@Example.com", name: "New" });
		const again = await auth.user.create({ email: "new@example.com" });
		expect(again.id).toBe(first.id);

		const agent = await auth.agent.create({
			ownerId: first.id,
			name: "worker",
			type: "autonomous",
			permissions: [{ resource: "mcp:*", actions: ["execute"] }],
		});
		for (let i = 0; i < 5; i++) {
			await auth.authorize(agent.id, { action: "execute", resource: `mcp:x:t${i}` });
		}
		const rows = await auth.audit.query({ agentId: agent.id });
		expect(rows).toHaveLength(5);
		const resources = rows.map((r) => r.resource).sort();
		expect(resources).toEqual(["mcp:x:t0", "mcp:x:t1", "mcp:x:t2", "mcp:x:t3", "mcp:x:t4"]);
		// The pre-upgrade rows are still readable, with no decision code.
		const old = await auth.audit.query({ agentId: "a1" });
		expect(old.map((r) => r.id).sort()).toEqual(["r1", "r2"]);
	});
});

describe("migration ledger: checksums", () => {
	it("refuses to run when an applied migration was edited", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		await exec.run("UPDATE theauth_schema_migrations SET checksum = 'tampered' WHERE id = '0002'");

		const status = await getSchemaStatus(db, "sqlite");
		expect(status.mismatched.map((m) => m.id)).toEqual(["0002"]);
		const error = await runMigrations(db, "sqlite").catch((e: unknown) => e);
		expect(error).toBeInstanceOf(SchemaChecksumError);
		expect((error as SchemaChecksumError).mismatched[0]?.actual).toBe("tampered");
		await expect(createTables(db, "sqlite")).rejects.toBeInstanceOf(SchemaChecksumError);
	});

	it("reports ledger ids this version does not know", async () => {
		const { db, exec } = await memoryDb();
		await runMigrations(db, "sqlite");
		await exec.run(
			"INSERT INTO theauth_schema_migrations (id, name, checksum, applied_at) VALUES ('0042', 'from-the-future', 'x', 1)",
		);
		expect((await getSchemaStatus(db, "sqlite")).unknown).toEqual(["0042"]);
		await expect(runMigrations(db, "sqlite")).resolves.toMatchObject({ applied: [] });
	});

	it("sha256Hex matches Web Crypto", async () => {
		for (const input of [
			"",
			"abc",
			"x".repeat(55),
			"x".repeat(56),
			"x".repeat(64),
			"ALTER TABLE t ADD COLUMN c TEXT;".repeat(20),
		]) {
			expect(sha256Hex(input)).toBe(await sha256(input));
		}
	});
});

describe("skipMigrations", () => {
	const config = {
		database: { provider: "sqlite" as const, url: ":memory:", skipMigrations: true },
		agents: { enabled: true },
	};

	it("throws SchemaOutdatedError listing the pending ids on an empty database", async () => {
		const { db } = await memoryDb();
		const error = await ensureSchema(db, config).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(SchemaOutdatedError);
		expect((error as SchemaOutdatedError).pending).toEqual(CORE_IDS);
		expect((error as SchemaOutdatedError).message).toContain("theauth db sql");
	});

	it("throws on a 1.2.0 database and lists every migration after the baseline and 0001", async () => {
		const { db } = await memoryDbV120();
		const error = await createTheAuthWith(config, async () => db).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(SchemaOutdatedError);
		expect((error as SchemaOutdatedError).pending).toEqual(CORE_IDS.slice(2));
	});

	it("boots once the generated SQL has been applied by hand", async () => {
		const { db, exec } = await memoryDb();
		await exec.run(migrationSql("sqlite"));
		await expect(ensureSchema(db, config)).resolves.toBeUndefined();
		expect(await ledgerIds(exec)).toEqual(ALL_IDS);
		expect((await getSchemaStatus(db, "sqlite")).mismatched).toEqual([]);
		const auth = await createTheAuthWith(config, async () => db);
		expect((await auth.schema.status()).pending).toEqual([]);
	});

	it("`--from` SQL upgrades a 1.2.0 database and leaves a consistent ledger", async () => {
		const { db, exec } = await memoryDbV120({ withData: true });
		await exec.run(migrationSql("sqlite", { from: "0002" }));
		expect(await ledgerIds(exec)).toEqual(ALL_IDS);
		await expect(ensureSchema(db, config)).resolves.toBeUndefined();
		const rows = await exec.all("SELECT recorded_at_ms AS ms FROM theauth_audit_logs ORDER BY id");
		expect(rows).toEqual([{ ms: 1700000100000 }, { ms: 1700000200000 }]);
	});

	it("rejects an unknown --from id", () => {
		expect(() => migrationSql("sqlite", { from: "0099" })).toThrow(/unknown migration id/);
	});
});

describe("feature scoped migrations", () => {
	it("skips the audit migrations until agents are enabled, then applies them", async () => {
		const { db, exec } = await memoryDb();
		const base = { database: { provider: "sqlite" as const, url: ":memory:" } };
		await createTables(db, "sqlite", base);
		expect(await ledgerIds(exec)).toEqual(["0000", "0003"]);
		expect(await columnsOf(exec, "theauth_audit_logs")).toEqual([]);
		expect((await getSchemaStatus(db, "sqlite", base)).pending).toEqual([]);

		const withAgents = { ...base, agents: { enabled: true } };
		expect((await getSchemaStatus(db, "sqlite", withAgents)).pending.map((p) => p.id)).toEqual([
			"0001",
			"0002",
			"0004",
			"0005",
			"0009",
			"0010",
			"0013",
			"0014",
			"0015",
		]);
		await createTables(db, "sqlite", withAgents);
		expect(await ledgerIds(exec)).toEqual(CORE_IDS);
		expect(await columnsOf(exec, "theauth_audit_logs")).toContain("recorded_at_ms");
		expect(await indexNames(exec, "theauth_audit_logs")).toContain("theauth_audit_logs_order");
	});
});

describe("isAlreadyExistsError", () => {
	it("recognises duplicate column and index errors from each driver", () => {
		expect(isAlreadyExistsError(new Error("duplicate column name: relation"))).toBe(true);
		expect(isAlreadyExistsError(new Error("index theauth_x already exists"))).toBe(true);
		expect(isAlreadyExistsError(new Error("Duplicate column name 'relation'"))).toBe(true);
		expect(isAlreadyExistsError(new Error("Duplicate key name 'theauth_x'"))).toBe(true);
		expect(isAlreadyExistsError({ code: "42701", message: "" })).toBe(true);
		expect(isAlreadyExistsError({ errno: 1061, message: "" })).toBe(true);
		expect(
			isAlreadyExistsError(new Error("q", { cause: new Error("column x already exists") })),
		).toBe(true);
	});

	it("does not swallow real failures", () => {
		expect(isAlreadyExistsError(new Error("no such table: theauth_audit_logs"))).toBe(false);
		expect(isAlreadyExistsError(new Error("syntax error near X"))).toBe(false);
		expect(isAlreadyExistsError("boom")).toBe(false);
	});
});
