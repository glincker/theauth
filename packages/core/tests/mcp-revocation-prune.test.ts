/** Denylist pruning, the cheap cached-mode fingerprint and the cross-instance clock skew allowance (SQLite). */
import { describe, expect, it, vi } from "vitest";
import { runMigrations } from "../src/db/migrate/index.js";
import { createRevocationBus } from "../src/mcp/revocation-bus.js";
import { pruneIfDue, pruneStore } from "../src/mcp/revocation-prune.js";
import type { McpRevocationEntry, McpRevocationQuery } from "../src/mcp/revocation-types.js";
import { createDbRevocationStore } from "../src/mcp/stores-db-revocation.js";
import { memoryDb } from "./helpers-schema-db.js";

async function setup(options: Parameters<typeof createDbRevocationStore>[1] = {}) {
	const { db } = await memoryDb();
	await runMigrations(db, "sqlite");
	return createDbRevocationStore(db, options);
}

const past = new Date(Date.now() - 3_600_000);
const future = new Date(Date.now() + 3_600_000);
const jtis = (n: number, expiresAt: Date, prefix = "j"): McpRevocationEntry[] =>
	Array.from({ length: n }, (_, i) => ({
		kind: "jti" as const,
		id: `${prefix}${i}`,
		expiresAt,
		reason: "t",
	}));
const count = async (s: Awaited<ReturnType<typeof setup>>, n: number, prefix = "j") => {
	let live = 0;
	for (let i = 0; i < n; i++) if (await s.isRevoked(`${prefix}${i}`)) live++;
	return live;
};

describe("pruning", () => {
	it("a manual prune deletes expired rows in LIMITed batches and keeps live ones", async () => {
		const s = await setup();
		await s.revokeMany(jtis(30, past, "old"));
		await s.revokeMany(jtis(5, future, "new"));
		const bus = createRevocationBus({ store: s, prune: { batchSize: 10 } });
		expect(await bus.prune()).toBe(30);
		expect(await count(s, 30, "old")).toBe(0);
		expect(await count(s, 5, "new")).toBe(5);
		expect(bus.stats().pruned).toBe(30);
	});

	it("one run deletes a bounded number of rows, never everything", async () => {
		const s = await setup();
		await s.revokeMany(jtis(60, past));
		const deleted = await pruneStore(s, new Date(), 5);
		expect(deleted).toBeLessThanOrEqual(20);
		expect(deleted).toBeGreaterThan(0);
		expect(await count(s, 60)).toBeGreaterThan(0);
	});

	it("opportunistic pruning is throttled per instance and runs after a push", async () => {
		const s = await setup();
		await s.revokeMany(jtis(3, past, "old"));
		const spy = vi.spyOn(s, "prune");
		const now = new Date();
		expect(await pruneIfDue(s, { intervalMs: 60_000 }, now)).toBe(3);
		expect(await pruneIfDue(s, { intervalMs: 60_000 }, new Date(now.getTime() + 1000))).toBe(0);
		expect(spy).toHaveBeenCalledTimes(1);

		await s.revokeMany(jtis(2, past, "older"));
		const bus = createRevocationBus({ store: s, prune: { intervalMs: 0 } });
		await bus.publish(
			{ kind: "jti", id: "x", ids: ["x"], revokedAt: new Date(), reason: "t" } as never,
			jtis(1, future, "fresh"),
		);
		await vi.waitFor(async () => expect(await count(s, 2, "older")).toBe(0));
	});

	it("a prune failure never reaches the writer", async () => {
		const s = await setup();
		vi.spyOn(s, "prune").mockRejectedValue(new Error("db down"));
		expect(await pruneIfDue(s, { intervalMs: 0 })).toBe(0);
	});
});

describe("fingerprint", () => {
	it("changes on a new row, a raised watermark and a row from a lagging clock; is stable otherwise", async () => {
		const s = await setup();
		const empty = await s.fingerprint();
		const at = new Date(1_700_000_100_000);
		await s.revokeMany([{ kind: "sub", id: "u1", expiresAt: future, reason: "t" }], at);
		const one = await s.fingerprint();
		expect(one).not.toBe(empty);
		expect(await s.fingerprint()).toBe(one);
		// An instance whose clock lags 10 s writes an OLDER revoked_at_ms: still a change.
		await s.revokeMany(
			[{ kind: "sub", id: "u2", expiresAt: future, reason: "t" }],
			new Date(at.getTime() - 10_000),
		);
		const two = await s.fingerprint();
		expect(two).not.toBe(one);
		await s.revokeMany(
			[{ kind: "sub", id: "u1", expiresAt: future, reason: "t" }],
			new Date(at.getTime() + 5),
		);
		expect(await s.fingerprint()).not.toBe(two);
	});
});

describe("clock skew between instances", () => {
	const q = (iatMs: number): McpRevocationQuery => ({
		jti: "j",
		sub: "u1",
		clientId: "c",
		iat: Math.floor(iatMs / 1000),
		dlg: [],
		agents: [],
	});

	it("a revoker whose clock lags still kills tokens minted just before the revoke", async () => {
		const real = 1_700_000_100_000;
		const lagging = real - 4000; // written by an instance 4 s behind
		const s = await setup({ skewAllowanceMs: 5000 });
		await s.revokeMany(
			[{ kind: "sub", id: "u1", expiresAt: future, reason: "t" }],
			new Date(lagging),
		);
		// Minted 2 s before the real revoke time, so after the lagging watermark: dead because of the allowance.
		expect(await s.check(q(real - 2000))).toEqual({ kind: "sub", id: "u1" });
		// Well after the allowance: alive.
		expect(await s.check(q(real + 10_000))).toBeNull();
	});

	it("without an allowance the same token escapes (documents the bound)", async () => {
		const real = 1_700_000_100_000;
		const s = await setup({ skewAllowanceMs: 0 });
		await s.revokeMany(
			[{ kind: "sub", id: "u1", expiresAt: future, reason: "t" }],
			new Date(real - 4000),
		);
		expect(await s.check(q(real - 2000))).toBeNull();
	});
});
