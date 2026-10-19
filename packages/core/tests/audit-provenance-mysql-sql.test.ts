/**
 * Wave 8 review probe: the audit provenance filter must emit SQL MySQL accepts. MySQL has no
 * `CAST(... AS TEXT)` (its CAST targets are CHAR, BINARY, JSON and the numeric and date types), so the
 * filter casts to CHAR there and to TEXT on SQLite and Postgres. The proxy driver captures the SQL
 * without a server.
 */
import { drizzle as mysqlProxy } from "drizzle-orm/mysql-proxy";
import { drizzle as pgProxy } from "drizzle-orm/pg-proxy";
import { describe, expect, it } from "vitest";
import { queryAuditEntries } from "../src/audit/query.js";
import type { Database } from "../src/db/database.js";

const HASH = "a".repeat(64);

describe("audit provenance filter SQL per dialect", () => {
	it("casts to CHAR on MySQL", async () => {
		const seen: string[] = [];
		const db = mysqlProxy(async (sql) => {
			seen.push(sql);
			return { rows: [] };
		}) as unknown as Database;
		await queryAuditEntries(db, { provenance: { kind: "tool_output", hash: HASH } });
		const query = seen.find((s) => s.includes("LIKE")) ?? "";
		expect(query).toContain("AS CHAR)");
		expect(query).not.toContain("AS TEXT)");
	});

	it("casts to TEXT on Postgres", async () => {
		const seen: string[] = [];
		const db = pgProxy(async (sql) => {
			seen.push(sql);
			return { rows: [] };
		}) as unknown as Database;
		await queryAuditEntries(db, { provenance: { kind: "tool_output", hash: HASH } });
		expect(seen.find((s) => s.includes("LIKE")) ?? "").toContain("AS TEXT)");
	});
});
