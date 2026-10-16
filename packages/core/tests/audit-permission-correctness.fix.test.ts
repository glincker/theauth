/**
 * Audit write failures never throw out of authorize; delegated fallback
 * leaves one audit row; canonicalJson guards cycles and BigInt; the secret
 * is read once per db handle.
 */

import { eq } from "drizzle-orm";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson } from "../src/audit/chain.js";
import { auditLogs, users } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

async function setup(extra: { tamperEvident?: boolean } = {}): Promise<TheAuth> {
	const t = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { auditAll: true },
		...(extra.tamperEvident ? { audit: { tamperEvident: true } } : {}),
	});
	await t.db.insert(users).values({
		id: "user-1",
		email: "a@example.com",
		name: "A",
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	return t;
}

const rows = (t: TheAuth) => t.db.select().from(auditLogs).where(eq(auditLogs.resource, "r:x"));

describe("audit write failure does not break authorize", () => {
	it("allowed and denied results still return when the audit insert throws", async () => {
		const t = await setup();
		const a = await t.agent.create({
			ownerId: "user-1",
			name: "a",
			type: "service",
			permissions: [{ resource: "r:x", actions: ["read"] }],
		});
		const spy = vi.spyOn(t.db, "insert").mockImplementation(() => {
			throw new Error("audit down");
		});
		const ok = await t.authorize(a.id, { action: "read", resource: "r:x" });
		const no = await t.authorize(a.id, { action: "write", resource: "r:x" });
		spy.mockRestore();
		expect(ok.allowed).toBe(true);
		expect(no.allowed).toBe(false);
	});
});

describe("delegated fallback audit", () => {
	it("writes one row, whose id is the returned auditId, for a plain denial", async () => {
		const t = await setup();
		const a = await t.agent.create({
			ownerId: "user-1",
			name: "p",
			type: "service",
			permissions: [],
		});
		const r = await t.authorize(a.id, { action: "read", resource: "r:x" });
		const all = await rows(t);
		expect(all).toHaveLength(1);
		expect(all[0]?.id).toBe(r.auditId);
	});

	async function withDelegation(t: TheAuth) {
		const parent = await t.agent.create({
			ownerId: "user-1",
			name: "parent",
			type: "autonomous",
			permissions: [{ resource: "r:x", actions: ["read"] }],
		});
		const child = await t.agent.create({
			ownerId: "user-1",
			name: "child",
			type: "delegated",
			permissions: [],
		});
		await t.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "r:x", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 3_600_000),
		});
		return child;
	}

	it("delegated allow leaves one allowed row and no orphan denial", async () => {
		const t = await setup();
		const child = await withDelegation(t);
		const r = await t.authorize(child.id, { action: "read", resource: "r:x" });
		expect(r.allowed).toBe(true);
		const all = await rows(t);
		expect(all).toHaveLength(1);
		expect(all[0]).toMatchObject({ id: r.auditId, result: "allowed" });
	});

	it("both denied leaves one denied row matching the returned auditId", async () => {
		const t = await setup();
		const child = await withDelegation(t);
		const r = await t.authorize(child.id, { action: "write", resource: "r:x" });
		expect(r.allowed).toBe(false);
		const all = await rows(t);
		expect(all).toHaveLength(1);
		expect(all[0]).toMatchObject({ id: r.auditId, result: "denied" });
	});
});

describe("canonicalJson", () => {
	it("throws a TypeError on a cycle instead of overflowing", () => {
		const o: Record<string, unknown> = { a: 1 };
		o.self = o;
		expect(() => canonicalJson(o)).toThrow(TypeError);
	});
	it("allows a value shared by two siblings", () => {
		const shared = { z: 1 };
		expect(canonicalJson({ a: shared, b: shared })).toBe('{"a":{"z":1},"b":{"z":1}}');
	});
	it("serializes BigInt as a decimal string", () => {
		expect(canonicalJson({ n: 12345678901234567890n })).toBe('{"n":"12345678901234567890"}');
	});
});

describe("audit secret memoization", () => {
	it("reads audit_secrets once across many appends", async () => {
		const t = await setup({ tamperEvident: true });
		const a = await t.agent.create({
			ownerId: "user-1",
			name: "m",
			type: "service",
			permissions: [],
		});
		await t.authorize(a.id, { action: "read", resource: "r:x" });
		const spy = vi.spyOn(t.db, "select");
		for (let i = 0; i < 3; i++) await t.authorize(a.id, { action: "read", resource: "r:x" });
		const secretReads = spy.mock.calls.filter(([cols]) => cols !== undefined && "secret" in cols);
		spy.mockRestore();
		expect(secretReads).toHaveLength(0);
		expect((await rows(t)).length).toBe(4);
	});
});
