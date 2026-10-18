import { describe, expect, it } from "vitest";
import { StoreConflictError, toStoreConflict } from "../src/db/store-conflict.js";

function withFields(message: string, fields: Record<string, unknown>): Error {
	return Object.assign(new Error(message), fields);
}

describe("toStoreConflict", () => {
	it("maps structured driver codes without relying on the message", () => {
		const cases: Array<[string, Error]> = [
			["postgres", withFields("x", { code: "23505" })],
			["mysql code", withFields("x", { code: "ER_DUP_ENTRY" })],
			["mysql errno", withFields("x", { errno: 1062 })],
			["sqlite unique", withFields("x", { code: "SQLITE_CONSTRAINT_UNIQUE" })],
			["sqlite pk", withFields("x", { code: "SQLITE_CONSTRAINT_PRIMARYKEY" })],
			["mssql 2627", withFields("x", { number: 2627 })],
			["mssql 2601", withFields("x", { number: 2601 })],
			["prisma", withFields("x", { code: "P2002" })],
			["mongo", withFields("x", { code: 11000 })],
		];
		for (const [name, err] of cases) {
			const conflict = toStoreConflict(err, "users");
			expect(conflict, name).toBeInstanceOf(StoreConflictError);
			expect(conflict?.model).toBe("users");
			expect(conflict?.cause).toBe(err);
		}
	});

	it("finds the code on a wrapped cause", () => {
		const inner = withFields("boom", { code: "23505" });
		const outer = new Error("Failed query", { cause: inner });
		expect(toStoreConflict(outer, "agents")).toBeInstanceOf(StoreConflictError);
	});

	it("keeps the regex as a fallback for drivers that only give text", () => {
		for (const text of [
			"UNIQUE constraint failed: theauth_users.email",
			"duplicate key value violates unique constraint",
			"Violation of UNIQUE KEY constraint",
			"E11000 duplicate key error",
		]) {
			expect(toStoreConflict(new Error(text), "users"), text).toBeInstanceOf(StoreConflictError);
		}
	});

	it("returns null for other failures", () => {
		expect(toStoreConflict(new Error("FOREIGN KEY constraint failed"), "users")).toBeNull();
		expect(
			toStoreConflict(withFields("x", { code: "SQLITE_CONSTRAINT_FOREIGNKEY" }), "u"),
		).toBeNull();
		expect(toStoreConflict(withFields("x", { code: "40001" }), "users")).toBeNull();
		expect(toStoreConflict("unique", "users")).toBeNull();
		expect(toStoreConflict(null, "users")).toBeNull();
	});

	it("passes a StoreConflictError through unchanged", () => {
		const own = new StoreConflictError("users", new Error("x"));
		expect(toStoreConflict(own, "agents")).toBe(own);
		expect(own.code).toBe("STORE_CONFLICT");
		expect(own.name).toBe("StoreConflictError");
	});
});
