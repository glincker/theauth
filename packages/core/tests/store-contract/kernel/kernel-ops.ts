import { describe, expect, it } from "vitest";
import type { StoreKernel } from "../../../src/db/store/index.js";
import { StoreConflictError } from "../../../src/db/store-conflict.js";
import type { MakeTarget, SuiteOptions } from "./target.js";
import { future, uid } from "./target.js";

function link(token: string, over: Record<string, unknown> = {}) {
	return {
		id: uid("ml"),
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
		id: uid("otp"),
		email: "o@kernel.test",
		codeHash: "h",
		expiresAt: future(),
		attempts: 0,
		createdAt: new Date(),
		...over,
	};
}

/** Kernel primitives: conflicts, filters, ordering, claims, guarded increments, batches, value round trips. */
export function defineKernelOps(make: MakeTarget, options: SuiteOptions): void {
	const parallel = options.parallel ?? 24;
	const open = async (): Promise<{ k: StoreKernel; close: () => Promise<void> }> => {
		const t = await make();
		return { k: t.stores.kernel, close: () => t.close() };
	};

	describe("kernel", () => {
		it("throws a typed conflict on a duplicate key", async () => {
			const { k, close } = await open();
			try {
				const row = link(uid("dup"));
				await k.insert("magicLinks", row);
				await expect(k.insert("magicLinks", { ...row, id: uid("ml") })).rejects.toBeInstanceOf(
					StoreConflictError,
				);
				await expect(k.insert("magicLinks", { ...row, token: uid("t") })).rejects.toBeInstanceOf(
					StoreConflictError,
				);
			} finally {
				await close();
			}
		});

		it("rejects an unknown model or field", async () => {
			const { k, close } = await open();
			try {
				await expect(k.findOne("nope" as never, [])).rejects.toThrow(/unknown model/);
				await expect(
					k.findOne("magicLinks", [{ field: "nope", op: "eq", value: 1 }]),
				).rejects.toThrow(/no field/);
			} finally {
				await close();
			}
		});

		it("filters with every operator", async () => {
			const { k, close } = await open();
			try {
				const email = `${uid("ops")}@kernel.test`;
				const a = otp({ email, attempts: 1 });
				const b = otp({ email, attempts: 3 });
				const c = otp({ email: `x-${email}`, attempts: 5 });
				for (const r of [a, b, c]) await k.insert("emailOtps", r);
				const ids = async (w: Parameters<StoreKernel["count"]>[1]) =>
					(await k.findMany("emailOtps", { where: w, orderBy: [{ field: "attempts" }] })).map(
						(r) => r.id,
					);
				const eq = { field: "email", op: "eq", value: email } as const;
				expect(await ids([eq, { field: "attempts", op: "lt", value: 3 }])).toEqual([a.id]);
				expect(await ids([eq, { field: "attempts", op: "lte", value: 3 }])).toEqual([a.id, b.id]);
				expect(await ids([eq, { field: "attempts", op: "gt", value: 1 }])).toEqual([b.id]);
				expect(await ids([eq, { field: "attempts", op: "gte", value: 1 }])).toEqual([a.id, b.id]);
				expect(await ids([eq, { field: "attempts", op: "ne", value: 1 }])).toEqual([b.id]);
				expect(await ids([{ field: "id", op: "in", value: [a.id, c.id] }])).toEqual([a.id, c.id]);
				expect(await ids([{ field: "id", op: "in", value: [] }])).toEqual([]);
				expect(await ids([eq, { field: "id", op: "notNull" }])).toHaveLength(2);
				expect(await ids([eq, { field: "id", op: "isNull" }])).toEqual([]);
				expect(await ids([eq, { field: "email", op: "ne", value: null }])).toHaveLength(2);
				expect(await k.count("emailOtps", [eq])).toBe(2);
				expect(await k.count("emailOtps", [{ field: "id", op: "eq", value: uid("none") }])).toBe(0);
			} finally {
				await close();
			}
		});

		it("orders by a list, honors limit, offset and column projection", async () => {
			const { k, close } = await open();
			try {
				const email = `${uid("order")}@kernel.test`;
				const rows = [
					otp({ email, attempts: 2 }),
					otp({ email, attempts: 2 }),
					otp({ email, attempts: 1 }),
				];
				for (const r of rows) await k.insert("emailOtps", r);
				const where = [{ field: "email", op: "eq", value: email }] as const;
				const orderBy = [
					{ field: "attempts", dir: "desc" },
					{ field: "id", dir: "asc" },
				] as const;
				const sorted = await k.findMany("emailOtps", { where, orderBy });
				const twos = [rows[0]?.id, rows[1]?.id].sort();
				expect(sorted.map((r) => r.id)).toEqual([...twos, rows[2]?.id]);
				const page = await k.findMany("emailOtps", { where, orderBy, limit: 1, offset: 1 });
				expect(page.map((r) => r.id)).toEqual([twos[1]]);
				const tail = await k.findMany("emailOtps", {
					where,
					orderBy: [{ field: "attempts", dir: "asc" }],
					offset: 2,
				});
				expect(tail).toHaveLength(1);
				const noOrder = await k.findMany("emailOtps", { where, limit: 2 });
				expect(noOrder).toHaveLength(2);
				const slim = await k.findMany("emailOtps", {
					where,
					columns: ["id", "attempts"],
					limit: 1,
				});
				expect(Object.keys(slim[0] ?? {}).sort()).toEqual(["attempts", "id"]);
			} finally {
				await close();
			}
		});

		it("treats LIKE wildcards in a prefix as literal text", async () => {
			const { k, close } = await open();
			try {
				const tag = uid("pfx");
				const plain = otp({ email: `${tag}-100%@kernel.test` });
				const wild = otp({ email: `${tag}-1000@kernel.test` });
				const under = otp({ email: `${tag}_x@kernel.test` });
				const other = otp({ email: `${tag}Zx@kernel.test` });
				const bang = otp({ email: `${tag}!x@kernel.test` });
				const bracket = otp({ email: `${tag}[a]@kernel.test` });
				const letter = otp({ email: `${tag}a@kernel.test` });
				const all = [plain, wild, under, other, bang, bracket, letter];
				for (const r of all) await k.insert("emailOtps", r);
				const match = async (prefix: string) =>
					(
						await k.findMany("emailOtps", {
							where: [{ field: "email", op: "prefix", value: prefix }],
						})
					).map((r) => r.id);
				expect(await match(`${tag}-100%`)).toEqual([plain.id]);
				expect(await match(`${tag}_`)).toEqual([under.id]);
				expect(await match(`${tag}!`)).toEqual([bang.id]);
				// `[a]` is a character class in SQL Server LIKE. It must match the literal text only.
				expect(await match(`${tag}[a]`)).toEqual([bracket.id]);
				expect((await match(tag)).length).toBe(all.length);
			} finally {
				await close();
			}
		});

		it("updateMany and deleteMany return counts and refuse an empty filter", async () => {
			const { k, close } = await open();
			try {
				const email = `${uid("bulk")}@kernel.test`;
				for (let i = 0; i < 3; i++) await k.insert("emailOtps", otp({ email }));
				const where = [{ field: "email", op: "eq", value: email }] as const;
				expect(await k.updateMany("emailOtps", where, { attempts: 4 })).toBe(3);
				expect(
					await k.count("emailOtps", [...where, { field: "attempts", op: "eq", value: 4 }]),
				).toBe(3);
				await expect(k.updateMany("emailOtps", [], { attempts: 1 })).rejects.toThrow(
					/at least one filter/,
				);
				await expect(k.deleteMany("emailOtps", [])).rejects.toThrow(/at least one filter/);
				expect(await k.deleteMany("emailOtps", where)).toBe(3);
				expect(await k.deleteMany("emailOtps", where)).toBe(0);
			} finally {
				await close();
			}
		});

		it("claim by update lets one of many parallel callers win and returns the pre-image", async () => {
			const { k, close } = await open();
			try {
				const token = uid("claim-update");
				const row = link(token);
				await k.insert("magicLinks", row);
				const where = [
					{ field: "token", op: "eq", value: token },
					{ field: "used", op: "eq", value: false },
					{ field: "expiresAt", op: "gt", value: new Date() },
				] as const;
				const results = await Promise.all(
					Array.from({ length: parallel }, () =>
						k.claim("magicLinks", where, { set: { used: true } }),
					),
				);
				const winners = results.filter((r) => r !== null);
				expect(winners).toHaveLength(1);
				expect(winners[0]?.used).toBe(false);
				expect(
					(await k.findOne("magicLinks", [{ field: "id", op: "eq", value: row.id }]))?.used,
				).toBe(true);
				expect(await k.claim("magicLinks", where, { set: { used: true } })).toBeNull();
			} finally {
				await close();
			}
		});

		it("claim by delete lets one of many parallel callers win", async () => {
			const { k, close } = await open();
			try {
				const row = otp();
				await k.insert("emailOtps", row);
				const where = [{ field: "id", op: "eq", value: row.id }] as const;
				const results = await Promise.all(
					Array.from({ length: parallel }, () => k.claim("emailOtps", where, "delete")),
				);
				expect(results.filter((r) => r !== null)).toHaveLength(1);
				expect(await k.count("emailOtps", where)).toBe(0);
			} finally {
				await close();
			}
		});

		it("claim on several matching rows hands each row to one caller", async () => {
			const { k, close } = await open();
			try {
				const email = `${uid("multi")}@kernel.test`;
				for (let i = 0; i < 3; i++) await k.insert("emailOtps", otp({ email }));
				const where = [{ field: "email", op: "eq", value: email }] as const;
				const results = await Promise.all(
					Array.from({ length: parallel }, () => k.claim("emailOtps", where, "delete")),
				);
				const ids = results.filter((r) => r !== null).map((r) => r?.id);
				expect(ids).toHaveLength(3);
				expect(new Set(ids).size).toBe(3);
			} finally {
				await close();
			}
		});

		it("claim refuses an empty filter", async () => {
			const { k, close } = await open();
			try {
				await expect(k.claim("emailOtps", [], "delete")).rejects.toThrow(/at least one filter/);
			} finally {
				await close();
			}
		});

		it("guarded increment spends exactly the budget under parallel callers", async () => {
			const { k, close } = await open();
			try {
				const row = otp();
				await k.insert("emailOtps", row);
				const where = [{ field: "id", op: "eq", value: row.id }] as const;
				const guard = { field: "attempts", op: "lt", value: 5 } as const;
				const results = await Promise.all(
					Array.from({ length: parallel }, () =>
						k.increment("emailOtps", where, "attempts", 1, guard),
					),
				);
				const granted = results.filter((r) => r !== null);
				expect(granted).toHaveLength(5);
				expect(granted.slice().sort()).toEqual([1, 2, 3, 4, 5]);
				expect((await k.findOne("emailOtps", where))?.attempts).toBe(5);
				expect(
					await k.increment(
						"emailOtps",
						[{ field: "id", op: "eq", value: "missing" }],
						"attempts",
						1,
					),
				).toBeNull();
				expect(await k.increment("emailOtps", where, "attempts", -2)).toBe(3);
			} finally {
				await close();
			}
		});

		it("batch applies every write, or none when one conflicts", async () => {
			const { k, close } = await open();
			try {
				expect(k.capabilities.atomicBatch).toBe(true);
				const first = link(uid("batch-a"));
				const second = link(uid("batch-b"));
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
					{
						op: "delete",
						model: "magicLinks",
						where: [{ field: "id", op: "eq", value: second.id }],
					},
				]);
				expect(await k.count("magicLinks", [{ field: "id", op: "eq", value: second.id }])).toBe(0);
				const fresh = link(uid("batch-c"));
				await expect(
					k.batch([
						{ op: "insert", model: "magicLinks", row: fresh },
						{ op: "insert", model: "magicLinks", row: { ...fresh, id: uid("ml") } },
					]),
				).rejects.toBeInstanceOf(StoreConflictError);
				expect(await k.count("magicLinks", [{ field: "id", op: "eq", value: fresh.id }])).toBe(0);
			} finally {
				await close();
			}
		});

		it("ltField compares one column with another on the same row", async () => {
			const { k, close } = await open();
			try {
				const nowSec = Math.floor(Date.now() / 1000);
				const owner = uid("u");
				const now = new Date();
				await k.insert("users", {
					id: owner,
					email: `${owner}@kernel.test`,
					name: null,
					metadata: null,
					createdAt: now,
					updatedAt: now,
				});
				const mk = (uses: number) => ({
					id: uid("enr"),
					kind: "claim",
					tokenHash: uid("h"),
					ownerId: owner,
					maxUses: 2,
					uses,
					expiresAt: nowSec + 3600,
					createdAt: nowSec,
					template: { groups: [], permissions: [] },
				});
				const open1 = mk(1);
				await k.insert("deviceEnrollments", open1);
				await k.insert("deviceEnrollments", mk(2));
				const rows = await k.findMany("deviceEnrollments", {
					where: [
						{ field: "ownerId", op: "eq", value: owner },
						{ field: "uses", op: "ltField", other: "maxUses" },
					],
				});
				expect(rows.map((r) => r.id)).toEqual([open1.id]);
			} finally {
				await close();
			}
		});

		it("rolls a transaction back when the callback throws, where the backend has one", async () => {
			const { k, close } = await open();
			try {
				if (!k.transaction) return;
				const row = link(uid("tx"));
				await expect(
					k.transaction(async (tx) => {
						await tx.insert("magicLinks", row);
						throw new Error("abort");
					}),
				).rejects.toThrow("abort");
				expect(await k.count("magicLinks", [{ field: "id", op: "eq", value: row.id }])).toBe(0);
				const kept = link(uid("tx"));
				await k.transaction(async (tx) => {
					await tx.insert("magicLinks", kept);
				});
				expect(await k.count("magicLinks", [{ field: "id", op: "eq", value: kept.id }])).toBe(1);
			} finally {
				await close();
			}
		});
	});
}
