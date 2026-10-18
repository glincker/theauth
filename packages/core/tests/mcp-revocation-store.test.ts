import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrate/index.js";
import type { McpRevocationQuery } from "../src/mcp/revocation-types.js";
import { createDbRevocationStore } from "../src/mcp/stores-db-revocation.js";
import { memoryDb } from "./helpers-schema-db.js";

const IN_AN_HOUR = new Date(Date.now() + 3_600_000);

async function store() {
	const { db, exec } = await memoryDb();
	await runMigrations(db, "sqlite");
	return { s: createDbRevocationStore(db), exec };
}

const query = (over: Partial<McpRevocationQuery> = {}): McpRevocationQuery => ({
	jti: "j1",
	sub: "u1",
	clientId: "c1",
	iat: 1_700_000_000,
	dlg: [],
	agents: [],
	...over,
});

describe("DB revocation store (SQLite)", () => {
	it("returns null when nothing is revoked, including for empty lists", async () => {
		const { s } = await store();
		expect(await s.check(query())).toBeNull();
		expect(await s.isRevoked("j1")).toBe(false);
	});

	it("denies a jti, a delegation link and an agent outright", async () => {
		const { s } = await store();
		await s.revoke("j1", IN_AN_HOUR);
		expect(await s.isRevoked("j1")).toBe(true);
		expect(await s.check(query())).toEqual({ kind: "jti", id: "j1" });

		await s.revokeMany([
			{ kind: "dlg", id: "d2", expiresAt: IN_AN_HOUR, reason: "delegation.revoke", sourceId: "d1" },
			{ kind: "agent", id: "a9", expiresAt: IN_AN_HOUR, reason: "agent.revoke" },
		]);
		expect(await s.check(query({ jti: "other", dlg: ["d1", "d2"] }))).toEqual({
			kind: "dlg",
			id: "d2",
		});
		expect(await s.check(query({ jti: "other", agents: ["a1", "a9"] }))).toEqual({
			kind: "agent",
			id: "a9",
		});
		expect(await s.check(query({ jti: "other", dlg: ["d1"], agents: ["a1"] }))).toBeNull();
	});

	it("applies the watermark rule to sub and client rows (iat <= revoked_at_ms is dead)", async () => {
		const { s } = await store();
		const revokedAt = new Date(1_700_000_100_000);
		await s.revokeMany(
			[
				{ kind: "sub", id: "u1", expiresAt: IN_AN_HOUR, reason: "session.revokeAll" },
				{ kind: "client", id: "c1", expiresAt: IN_AN_HOUR, reason: "client.disable" },
			],
			revokedAt,
		);
		expect(await s.check(query({ iat: 1_700_000_099 }))).toEqual({ kind: "sub", id: "u1" });
		// Same second as the revoke: fail closed.
		expect(await s.check(query({ iat: 1_700_000_100 }))).toEqual({ kind: "sub", id: "u1" });
		// Minted after the watermark: alive.
		expect(await s.check(query({ iat: 1_700_000_101 }))).toBeNull();
		// The client row alone also kills older tokens.
		expect(await s.check(query({ sub: "nobody", iat: 1_700_000_099 }))).toEqual({
			kind: "client",
			id: "c1",
		});
	});

	it("reports hits by precedence jti, sub, client, dlg, agent", async () => {
		const { s } = await store();
		const at = new Date(1_700_000_100_000);
		await s.revokeMany(
			(["agent", "dlg", "client", "sub", "jti"] as const).map((kind) => ({
				kind,
				id: kind === "jti" ? "j1" : kind === "sub" ? "u1" : kind === "client" ? "c1" : `${kind}1`,
				expiresAt: IN_AN_HOUR,
				reason: "test",
			})),
			at,
		);
		const q = query({ iat: 1_700_000_000, dlg: ["dlg1"], agents: ["agent1"] });
		expect((await s.check(q))?.kind).toBe("jti");
		expect((await s.check({ ...q, jti: "x" }))?.kind).toBe("sub");
		expect((await s.check({ ...q, jti: "x", sub: "x" }))?.kind).toBe("client");
		expect((await s.check({ ...q, jti: "x", sub: "x", clientId: "x" }))?.kind).toBe("dlg");
		expect((await s.check({ ...q, jti: "x", sub: "x", clientId: "x", dlg: [] }))?.kind).toBe(
			"agent",
		);
	});

	it("revokeMany is an idempotent upsert and re-revoking a sub raises the watermark", async () => {
		const { s, exec } = await store();
		const entry = { kind: "sub" as const, id: "u1", expiresAt: IN_AN_HOUR, reason: "first" };
		await s.revokeMany([entry], new Date(1_700_000_100_000));
		await s.revokeMany([entry], new Date(1_700_000_100_000));
		await s.revokeMany([{ ...entry, reason: "second" }], new Date(1_700_000_200_000));
		// An older late revoke never lowers the watermark.
		await s.revokeMany([entry], new Date(1_700_000_050_000));
		const rows = await exec.all(
			"SELECT kind AS k, revoked_at_ms AS ms, reason AS r FROM theauth_mcp_revocations",
		);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.ms).toBe(1_700_000_200_000);
		expect(await s.check(query({ iat: 1_700_000_150 }))).toEqual({ kind: "sub", id: "u1" });
	});

	it("revoking the same jti twice does not throw", async () => {
		const { s } = await store();
		await s.revoke("j1", IN_AN_HOUR);
		await expect(s.revoke("j1", IN_AN_HOUR)).resolves.toBeUndefined();
	});

	it("fingerprint changes on insert and on a watermark raise, not on a no-op", async () => {
		const { s } = await store();
		const sub = { kind: "sub" as const, id: "u1", expiresAt: IN_AN_HOUR, reason: "r" };
		const far = Date.now() + 100_000;
		const empty = await s.fingerprint();
		await s.revoke("j1", IN_AN_HOUR);
		const one = await s.fingerprint();
		expect(one).not.toBe(empty);
		await s.revokeMany([sub], new Date(far));
		const two = await s.fingerprint();
		expect(two).not.toBe(one);
		await s.revokeMany([sub], new Date(far));
		expect(await s.fingerprint()).toBe(two);
		await s.revokeMany([sub], new Date(far + 1000));
		expect(await s.fingerprint()).not.toBe(two);
	});

	it("prunes only expired rows, honouring the limit", async () => {
		const { s, exec } = await store();
		const past = new Date(Date.now() - 10_000);
		for (const id of ["a", "b", "c"]) {
			await s.revokeMany([{ kind: "jti", id, expiresAt: past, reason: "t" }]);
		}
		await s.revokeMany([{ kind: "jti", id: "live", expiresAt: IN_AN_HOUR, reason: "t" }]);
		expect(await s.prune(new Date(), 2)).toBe(2);
		expect(await s.prune(new Date())).toBe(1);
		expect(await s.prune(new Date())).toBe(0);
		const rows = await exec.all("SELECT id AS id FROM theauth_mcp_revocations");
		expect(rows.map((r) => r.id)).toEqual(["live"]);
	});

	it("stores ids and reasons only (no token column exists)", async () => {
		const { exec } = await store();
		const cols = await exec.all(
			"SELECT name AS name FROM pragma_table_info('theauth_mcp_revocations')",
		);
		expect(cols.map((c) => c.name)).toEqual([
			"kind",
			"id",
			"revoked_at_ms",
			"expires_at",
			"reason",
			"source_id",
		]);
	});
});
