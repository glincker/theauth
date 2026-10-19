import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { DatabaseConfig } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { runMigrations } from "../src/db/migrate/index.js";
import type { StoreKernel } from "../src/db/store/index.js";
import { createDrizzleKernel } from "../src/db/store/index.js";
import { StoreConflictError } from "../src/db/store-conflict.js";

const dir = mkdtempSync(join(tmpdir(), "theauth-kernel-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const PARALLEL = 24;
let seq = 0;
const id = (tag: string) => `${tag}-${++seq}`;
const future = () => new Date(Date.now() + 3_600_000);

async function open(config: DatabaseConfig): Promise<StoreKernel> {
	const db = await createDatabase(config);
	await runMigrations(db, "sqlite");
	return createDrizzleKernel(db, "sqlite");
}

const backends: Array<[string, () => Promise<StoreKernel>]> = [
	["sql.js", () => open({ provider: "sqlite", url: ":memory:" })],
	["better-sqlite3", () => open({ provider: "sqlite-native", url: join(dir, `k${++seq}.db`) })],
];

function link(token: string, over: Record<string, unknown> = {}) {
	return {
		id: id("ml"),
		email: "a@kernel.test",
		token,
		expiresAt: future(),
		used: false,
		createdAt: new Date(),
		...over,
	};
}

function otp(over: Record<string, unknown> = {}) {
	return {
		id: id("otp"),
		email: "o@kernel.test",
		codeHash: "h",
		expiresAt: future(),
		attempts: 0,
		createdAt: new Date(),
		...over,
	};
}

describe.each(backends)("store kernel on %s", (_name, make) => {
	it("reports capabilities", async () => {
		const k = await make();
		expect(k.capabilities.atomicBatch).toBe(true);
		expect(k.capabilities.interactiveTx).toBe(false);
		expect(k.transaction).toBeUndefined();
	});

	it("throws a typed conflict on a duplicate key", async () => {
		const k = await make();
		const row = link("dup-token");
		await k.insert("magicLinks", row);
		await expect(k.insert("magicLinks", { ...row, id: id("ml") })).rejects.toBeInstanceOf(
			StoreConflictError,
		);
	});

	it("rejects an unknown model or field", async () => {
		const k = await make();
		await expect(k.findOne("nope" as never, [])).rejects.toThrow(/unknown model/);
		await expect(k.findOne("magicLinks", [{ field: "nope", op: "eq", value: 1 }])).rejects.toThrow(
			/no field/,
		);
	});

	it("filters with every operator", async () => {
		const k = await make();
		const a = otp({ email: "ops@kernel.test", attempts: 1 });
		const b = otp({ email: "ops@kernel.test", attempts: 3 });
		const c = otp({ email: "other@kernel.test", attempts: 5 });
		for (const r of [a, b, c]) await k.insert("emailOtps", r);
		const ids = async (w: Parameters<StoreKernel["count"]>[1]) =>
			(await k.findMany("emailOtps", { where: w, orderBy: [{ field: "attempts" }] })).map(
				(r) => r.id,
			);
		const email = { field: "email", op: "eq", value: "ops@kernel.test" } as const;
		expect(await ids([email, { field: "attempts", op: "lt", value: 3 }])).toEqual([a.id]);
		expect(await ids([email, { field: "attempts", op: "lte", value: 3 }])).toEqual([a.id, b.id]);
		expect(await ids([email, { field: "attempts", op: "gt", value: 1 }])).toEqual([b.id]);
		expect(await ids([email, { field: "attempts", op: "gte", value: 1 }])).toEqual([a.id, b.id]);
		expect(await ids([email, { field: "attempts", op: "ne", value: 1 }])).toEqual([b.id]);
		expect(await ids([{ field: "id", op: "in", value: [a.id, c.id] }])).toEqual([a.id, c.id]);
		expect(await ids([email, { field: "id", op: "notNull" }])).toHaveLength(2);
		expect(await ids([email, { field: "id", op: "isNull" }])).toEqual([]);
		expect(await k.count("emailOtps", [email])).toBe(2);
	});

	it("orders by a list, honors limit and offset", async () => {
		const k = await make();
		const email = "order@kernel.test";
		const rows = [
			otp({ email, attempts: 2 }),
			otp({ email, attempts: 2 }),
			otp({ email, attempts: 1 }),
		];
		for (const r of rows) await k.insert("emailOtps", r);
		const where = [{ field: "email", op: "eq", value: email }] as const;
		const sorted = await k.findMany("emailOtps", {
			where,
			orderBy: [
				{ field: "attempts", dir: "desc" },
				{ field: "id", dir: "asc" },
			],
		});
		const twos = [rows[0]?.id, rows[1]?.id].sort();
		expect(sorted.map((r) => r.id)).toEqual([...twos, rows[2]?.id]);
		const page = await k.findMany("emailOtps", {
			where,
			orderBy: [
				{ field: "attempts", dir: "desc" },
				{ field: "id", dir: "asc" },
			],
			limit: 1,
			offset: 1,
		});
		expect(page.map((r) => r.id)).toEqual([twos[1]]);
		const tail = await k.findMany("emailOtps", {
			where,
			orderBy: [{ field: "attempts", dir: "asc" }],
			offset: 2,
		});
		expect(tail).toHaveLength(1);
	});

	it("treats LIKE wildcards in a prefix as literal text", async () => {
		const k = await make();
		const tag = id("pfx");
		const plain = otp({ email: `${tag}-100%@kernel.test` });
		const wild = otp({ email: `${tag}-1000@kernel.test` });
		const under = otp({ email: `${tag}_x@kernel.test` });
		const other = otp({ email: `${tag}Zx@kernel.test` });
		const bang = otp({ email: `${tag}!x@kernel.test` });
		for (const r of [plain, wild, under, other, bang]) await k.insert("emailOtps", r);
		const match = async (prefix: string) =>
			(
				await k.findMany("emailOtps", { where: [{ field: "email", op: "prefix", value: prefix }] })
			).map((r) => r.id);
		expect(await match(`${tag}-100%`)).toEqual([plain.id]);
		expect(await match(`${tag}_`)).toEqual([under.id]);
		expect(await match(`${tag}!`)).toEqual([bang.id]);
		expect((await match(tag)).length).toBe(5);
	});

	it("updateMany and deleteMany return counts and refuse an empty filter", async () => {
		const k = await make();
		const email = "bulk@kernel.test";
		for (let i = 0; i < 3; i++) await k.insert("emailOtps", otp({ email }));
		const where = [{ field: "email", op: "eq", value: email }] as const;
		expect(await k.updateMany("emailOtps", where, { attempts: 4 })).toBe(3);
		expect(await k.count("emailOtps", [...where, { field: "attempts", op: "eq", value: 4 }])).toBe(
			3,
		);
		await expect(k.updateMany("emailOtps", [], { attempts: 1 })).rejects.toThrow(
			/at least one filter/,
		);
		await expect(k.deleteMany("emailOtps", [])).rejects.toThrow(/at least one filter/);
		expect(await k.deleteMany("emailOtps", where)).toBe(3);
		expect(await k.deleteMany("emailOtps", where)).toBe(0);
	});

	it("claim by update lets one of many parallel callers win and returns the pre-image", async () => {
		const k = await make();
		const row = link("claim-update");
		await k.insert("magicLinks", row);
		const where = [
			{ field: "token", op: "eq", value: "claim-update" },
			{ field: "used", op: "eq", value: false },
			{ field: "expiresAt", op: "gt", value: new Date() },
		] as const;
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => k.claim("magicLinks", where, { set: { used: true } })),
		);
		const winners = results.filter((r) => r !== null);
		expect(winners).toHaveLength(1);
		expect(winners[0]?.used).toBe(false);
		expect((await k.findOne("magicLinks", [{ field: "id", op: "eq", value: row.id }]))?.used).toBe(
			true,
		);
		expect(await k.claim("magicLinks", where, { set: { used: true } })).toBeNull();
	});

	it("claim by delete lets one of many parallel callers win", async () => {
		const k = await make();
		const row = otp();
		await k.insert("emailOtps", row);
		const where = [{ field: "id", op: "eq", value: row.id }] as const;
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => k.claim("emailOtps", where, "delete")),
		);
		expect(results.filter((r) => r !== null)).toHaveLength(1);
		expect(await k.count("emailOtps", where)).toBe(0);
	});

	it("claim on several matching rows hands each row to one caller", async () => {
		const k = await make();
		const email = "multi@kernel.test";
		for (let i = 0; i < 3; i++) await k.insert("emailOtps", otp({ email }));
		const where = [{ field: "email", op: "eq", value: email }] as const;
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => k.claim("emailOtps", where, "delete")),
		);
		const ids = results.filter((r) => r !== null).map((r) => r?.id);
		expect(ids).toHaveLength(3);
		expect(new Set(ids).size).toBe(3);
	});

	it("claim refuses an empty filter", async () => {
		const k = await make();
		await expect(k.claim("emailOtps", [], "delete")).rejects.toThrow(/at least one filter/);
	});

	it("guarded increment spends exactly the budget under parallel callers", async () => {
		const k = await make();
		const row = otp();
		await k.insert("emailOtps", row);
		const where = [{ field: "id", op: "eq", value: row.id }] as const;
		const guard = { field: "attempts", op: "lt", value: 5 } as const;
		const results = await Promise.all(
			Array.from({ length: PARALLEL }, () => k.increment("emailOtps", where, "attempts", 1, guard)),
		);
		const granted = results.filter((r) => r !== null);
		expect(granted).toHaveLength(5);
		expect(granted.slice().sort()).toEqual([1, 2, 3, 4, 5]);
		expect((await k.findOne("emailOtps", where))?.attempts).toBe(5);
		expect(
			await k.increment("emailOtps", [{ field: "id", op: "eq", value: "missing" }], "attempts", 1),
		).toBeNull();
	});

	it("batch applies every write, or none when one conflicts", async () => {
		const k = await make();
		const first = link("batch-a");
		const second = link("batch-b");
		await k.batch([
			{ op: "insert", model: "magicLinks", row: first },
			{ op: "insert", model: "magicLinks", row: second },
			{
				op: "update",
				model: "magicLinks",
				where: [{ field: "id", op: "eq", value: first.id }],
				set: { used: true },
			},
		]);
		expect(
			(await k.findOne("magicLinks", [{ field: "id", op: "eq", value: first.id }]))?.used,
		).toBe(true);
		await k.batch([
			{ op: "delete", model: "magicLinks", where: [{ field: "id", op: "eq", value: second.id }] },
		]);
		expect(await k.count("magicLinks", [{ field: "id", op: "eq", value: second.id }])).toBe(0);

		const fresh = link("batch-c");
		await expect(
			k.batch([
				{ op: "insert", model: "magicLinks", row: fresh },
				{ op: "insert", model: "magicLinks", row: { ...fresh, id: id("ml") } },
			]),
		).rejects.toBeInstanceOf(StoreConflictError);
		expect(await k.count("magicLinks", [{ field: "id", op: "eq", value: fresh.id }])).toBe(0);
	});
});
